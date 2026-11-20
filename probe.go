package gosdf

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ProbeStatus 单项检查的结论。
type ProbeStatus uint8

const (
	// ProbePass 检查通过。
	ProbePass ProbeStatus = iota
	// ProbeFail 检查失败。
	ProbeFail
	// ProbeSkip 检查被跳过(缺符号/缺 PIN/密钥索引不存在等)。
	ProbeSkip
)

// String 返回报告列使用的状态文本。
func (s ProbeStatus) String() string {
	switch s {
	case ProbePass:
		return "PASS"
	case ProbeFail:
		return "FAIL"
	case ProbeSkip:
		return "SKIP"
	}
	return "UNKNOWN"
}

// ProbeSymbol 符号矩阵中的一行:设备是否导出该 SDF 符号。
type ProbeSymbol struct {
	Name      string // SDF_* 全名,如 SDF_HMACInit
	Group     string // 分组(设备管理/杂凑/HMAC/密钥管理/…)
	Supported bool   // dev.Supports(Name) 的结果
}

// ProbeCheck 检查表中一项的结论。
type ProbeCheck struct {
	Name   string      // 检查名,如 sm3-kat
	Group  string      // 分组
	Status ProbeStatus // PASS/FAIL/SKIP
	Detail string      // 判定依据或错误文本
}

// ProbeResult TestDevice 的探测结果:设备信息、63 符号矩阵与全部检查结论。
type ProbeResult struct {
	Info    *DeviceInfo   // SDF_GetDeviceInfo 成功时非 nil,否则为 nil
	Symbols []ProbeSymbol // 按 sdf_shim.c gs_func_name_arr 原序
	Checks  []ProbeCheck
}

// Summary 返回形如 "28 pass, 0 fail, 0 skip" 的统计行。
func (r *ProbeResult) Summary() string {
	var pass, fail, skip int
	for _, c := range r.Checks {
		switch c.Status {
		case ProbePass:
			pass++
		case ProbeFail:
			fail++
		case ProbeSkip:
			skip++
		}
	}
	return fmt.Sprintf("%d pass, %d fail, %d skip", pass, fail, skip)
}

// ProbeConfig TestDevice 的运行参数,零值经 With* 选项或默认值填充。
type ProbeConfig struct {
	KeyIndex uint32    // 内部密钥索引,默认 1
	KEKIndex uint32    // KEK 索引,默认 1
	PIN      []byte    // 空 = 不取私钥权限,needsRight 检查全部 SKIP
	Output   io.Writer // 报告输出,默认 os.Stdout;io.Discard 静默
}

// ProbeOption 修改 ProbeConfig 的选项。
type ProbeOption func(*ProbeConfig)

// WithKeyIndex 指定内部密钥索引(签名/加密密钥),默认 1。
func WithKeyIndex(idx uint32) ProbeOption {
	return func(c *ProbeConfig) { c.KeyIndex = idx }
}

// WithKEKIndex 指定 KEK 索引,默认 1。
func WithKEKIndex(idx uint32) ProbeOption {
	return func(c *ProbeConfig) { c.KEKIndex = idx }
}

// WithPIN 提供私钥访问权限 PIN;为空则所有需要私钥的检查 SKIP。
func WithPIN(pin []byte) ProbeOption {
	return func(c *ProbeConfig) { c.PIN = pin }
}

// WithOutput 重定向报告输出;传 io.Discard 即静默(只取返回值)。
func WithOutput(w io.Writer) ProbeOption {
	return func(c *ProbeConfig) { c.Output = w }
}

// probeSkip 检查内部主动请求跳过(probe_checks.go 的 skipf)。
type probeSkip struct{ msg string }

func (e *probeSkip) Error() string { return e.msg }

// skipf 构造检查级跳过错误,runner 解包为 ProbeSkip 并取 msg 作 Detail。
func skipf(format string, args ...interface{}) error {
	return &probeSkip{msg: fmt.Sprintf(format, args...)}
}

// probeCtx 单次探测的共享上下文(设备/会话/参数/惰性资源)。
type probeCtx struct {
	dev      *Device
	sess     *Session
	keyIndex uint32
	kekIndex uint32
	pin      []byte
	rights   bool  // AcquireKeyRight 是否已成功
	rightErr error // 取权限失败原因(needsRight SKIP 文案)
	info     *DeviceInfo

	keyDone bool   // sessionKey 是否已尝试
	key     *Key   // 惰性会话密钥(共享,探测结束销毁)
	keyRaw  []byte // 密钥字节;nil 表示密钥未知(KEK 回退)
	keyErr  error  // ImportKey 与 GenerateKeyWithKEK 均失败
}

// sessionKey 惰性获取会话密钥:优先 ImportKey(随机 16 字节,密钥已知 → KAT 可用),
// 失败回退 GenerateKeyWithKEK(密钥未知 → 仅往返类判定);两者皆败返回错误,
// 调用方按 "no session key" SKIP。
func (c *probeCtx) sessionKey() (*Key, []byte, error) {
	if c.keyDone {
		return c.key, c.keyRaw, c.keyErr
	}
	c.keyDone = true
	var importErr error
	raw, err := probeRand(16)
	if err == nil {
		if k, err2 := c.sess.ImportKey(raw); err2 == nil {
			c.key, c.keyRaw = k, raw
		} else {
			importErr = err2
		}
	} else {
		importErr = err
	}
	if c.key == nil {
		_, k, err3 := c.sess.GenerateKeyWithKEK(c.kekIndex, 128, SM4_ECB)
		if err3 != nil {
			c.keyErr = fmt.Errorf("ImportKey: %v; GenerateKeyWithKEK: %v", importErr, err3)
			return nil, nil, c.keyErr
		}
		c.key = k
	}
	return c.key, c.keyRaw, nil
}

// cleanup 探测结束的非破坏性收尾:销毁共享会话密钥、释放私钥权限。
func (c *probeCtx) cleanup() {
	if c.key != nil {
		c.key.Destroy()
		c.key = nil
	}
	if c.rights {
		c.sess.ReleaseKeyRight(c.keyIndex)
		c.rights = false
	}
}

// probeCheck 检查表条目:requires 任一符号未绑定即 SKIP;needsRight 需已取到权限。
type probeCheck struct {
	name       string
	group      string
	requires   []string
	needsRight bool
	run        func(c *probeCtx) (string, error)
}

// runChecks 顺序执行检查表,统一实施跳过/恢复策略:
//   - requires 缺符号 → SKIP "missing <symbol>"
//   - needsRight 未取到权限 → SKIP(PIN 空: "needs PIN (WithPIN)")
//   - run 主动 skipf → SKIP(附原因)
//   - run 返回 SDR_KEYNOTEXIST → SKIP(密钥索引设备相关,不算失败)
//   - run 返回 SDR_PARDENY → SKIP "needs PIN (WithPIN)"
//   - run panic → FAIL "panic: …"
//   - 其余错误 → FAIL(附错误文本);nil → PASS(附 run 返回的判定文本)
func runChecks(c *probeCtx, table []probeCheck) []ProbeCheck {
	out := make([]ProbeCheck, 0, len(table))
	for _, ck := range table {
		out = append(out, evalCheck(c, ck))
	}
	return out
}

// evalCheck 执行单个检查并给出状态与 Detail(命名结果:recover 时保留已赋状态)。
func evalCheck(c *probeCtx, ck probeCheck) (p ProbeCheck) {
	p = ProbeCheck{Name: ck.name, Group: ck.group}
	defer func() {
		if r := recover(); r != nil {
			p.Status, p.Detail = ProbeFail, fmt.Sprintf("panic: %v", r)
		}
	}()
	for _, sym := range ck.requires {
		if !c.dev.Supports(sym) {
			p.Status, p.Detail = ProbeSkip, "missing "+sym
			return p
		}
	}
	if ck.needsRight && !c.rights {
		if len(c.pin) == 0 {
			p.Status, p.Detail = ProbeSkip, "needs PIN (WithPIN)"
		} else if c.rightErr != nil {
			p.Status, p.Detail = ProbeSkip, "key right unavailable: "+c.rightErr.Error()
		} else {
			p.Status, p.Detail = ProbeSkip, "key right unavailable: key-right check did not run"
		}
		return p
	}

	detail, err := ck.run(c)
	if err == nil {
		p.Status, p.Detail = ProbePass, detail
		return p
	}
	var sk *probeSkip
	if errors.As(err, &sk) {
		p.Status, p.Detail = ProbeSkip, sk.msg
		return p
	}
	if errors.Is(err, SDR_KEYNOTEXIST) {
		p.Status, p.Detail = ProbeSkip, err.Error()
		return p
	}
	if errors.Is(err, SDR_PARDENY) {
		p.Status, p.Detail = ProbeSkip, "needs PIN (WithPIN): "+err.Error()
		return p
	}
	p.Status, p.Detail = ProbeFail, err.Error()
	return p
}

// TestDevice 加载 libPath 并运行能力探测,报告写入 cfg.Output。
// 有任一 FAIL 时返回非 nil error(文本含 Summary),*ProbeResult 始终返回
// (Open 失败除外)。空 libPath 由 Open 返回 SDR_INARGERR;Open/NewSession
// 失败时关闭已开资源并向上返回错误,不打印报告。
// 探测非破坏:会话密钥用完销毁、探测文件用完删除、权限用完释放;
// 按进程 CWD 相对路径读密钥文件的设备(SoftSDF)要求调用方在正确目录运行,
// TestDevice 不改变 CWD。
func TestDevice(libPath string, opts ...ProbeOption) (*ProbeResult, error) {
	cfg := &ProbeConfig{KeyIndex: 1, KEKIndex: 1, Output: os.Stdout}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.Output == nil {
		cfg.Output = io.Discard
	}

	dev, err := Open(libPath)
	if err != nil {
		return nil, err
	}
	defer dev.Close()
	sess, err := dev.NewSession()
	if err != nil {
		return &ProbeResult{}, err
	}
	defer sess.Close()

	c := &probeCtx{
		dev: dev, sess: sess, keyIndex: cfg.KeyIndex,
		kekIndex: cfg.KEKIndex, pin: cfg.PIN,
	}
	defer c.cleanup()

	res := &ProbeResult{Symbols: probeSymbols(dev)}
	res.Checks = runChecks(c, probeCheckTable)
	res.Info = c.info
	writeReport(cfg.Output, libPath, res)

	for _, ck := range res.Checks {
		if ck.Status == ProbeFail {
			return res, fmt.Errorf("gosdf: TestDevice: %s", res.Summary())
		}
	}
	return res, nil
}

// writeReport 输出探测报告(格式见 README「设备能力探测」)。
func writeReport(w io.Writer, libPath string, res *ProbeResult) {
	fmt.Fprintf(w, "gosdf TestDevice: %s\n", libPath)
	if res.Info != nil {
		fmt.Fprintf(w, "device: issuer=%s name=%s serial=%s stdver=0x%08x buffer=%d\n",
			res.Info.IssuerName, res.Info.DeviceName, res.Info.DeviceSerial,
			res.Info.StandardVersion, res.Info.BufferSize)
		fmt.Fprintf(w, "ability: sym=0x%08x hash=0x%08x\n",
			res.Info.SymAlgAbility, res.Info.HashAlgAbility)
	}
	fmt.Fprint(w, "symbols:\n")
	for _, s := range res.Symbols {
		state := "miss"
		if s.Supported {
			state = "ok"
		}
		fmt.Fprintf(w, "  %-4s %-24s %s\n", state, s.Name, s.Group)
	}
	fmt.Fprint(w, "checks:\n")
	for _, ck := range res.Checks {
		fmt.Fprintf(w, "  %-5s %-20s%s\n", ck.Status, ck.Name, ck.Detail)
	}
	fmt.Fprintf(w, "summary: %s\n", res.Summary())
}
