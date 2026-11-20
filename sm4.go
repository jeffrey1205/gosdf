package gosdf

/*
#include "sdf.h"
*/
import "C"

import (
	"crypto/cipher"
	"fmt"
	"unsafe"

	"github.com/emmansun/gmsm/padding"
)

// Key 会话密钥句柄。Destroy 后继续使用返回 SDR_KEYNOTEXIST;
// 会话/设备关闭后密钥随之失效。
type Key struct {
	s *Session
	h HANDLE
}

// handles 返回 C 上下文、会话句柄与密钥句柄;密钥已销毁报 SDR_KEYNOTEXIST。
func (k *Key) handles(op string) (*C.sdf_ctx, *C.long, *C.long, error) {
	if k == nil || k.h == nil {
		return nil, nil, nil, rvErr(op, SDR_KEYNOTEXIST)
	}
	ctx, h, err := k.s.handles(op)
	if err != nil {
		return nil, nil, nil, err
	}
	return ctx, h, (*C.long)(unsafe.Pointer(k.h)), nil
}

// Destroy 销毁会话密钥,幂等。会话或设备已关闭时视为密钥已销毁(返回 nil);
// 设备报错时保留句柄,可重试。
func (k *Key) Destroy() error {
	const op = "SDF_DestroyKey"
	if k == nil || k.h == nil {
		return nil
	}
	ctx, sh, kh, err := k.handles(op)
	if err != nil { // 会话/设备已关闭,密钥随之失效
		k.h = nil
		return nil
	}
	rv := C.destroy_key(ctx, sh, kh)
	if rv != 0 {
		return rvErr(op, RV(rv))
	}
	k.h = nil
	return nil
}

// GenerateKeyWithKEK 用 keyIndex 对应的 KEK 加密生成会话密钥,
// 返回导出的包装密钥与可用会话密钥(密钥长度 keyBits,算法 alg)。
func (s *Session) GenerateKeyWithKEK(kekIndex, keyBits uint32, alg ALGID) ([]byte, *Key, error) {
	const op = "SDF_GenerateKeyWithKEK"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 256)
	keyLen := C.UINT32(len(buf)) // 入参为缓冲容量,出参为实际长度
	var kh HANDLE
	rv := C.gen_key_with_kek(ctx, h, C.UINT32(keyBits), C.UINT32(alg), C.UINT32(kekIndex),
		bytePtr(buf), (*C.UINT32)(unsafe.Pointer(&keyLen)),
		(**C.long)(unsafe.Pointer(&kh)))
	if rv != 0 {
		return nil, nil, rvErr(op, RV(rv))
	}
	if keyLen > C.UINT32(len(buf)) { // 防御设备返回越界长度
		keyLen = C.UINT32(len(buf))
	}
	return append([]byte(nil), buf[:keyLen]...), &Key{s: s, h: kh}, nil
}

// ImportKeyWithKEK 导入被 keyIndex 对应 KEK 加密的会话密钥。
func (s *Session) ImportKeyWithKEK(kekIndex uint32, alg ALGID, wrapped []byte) (*Key, error) {
	const op = "SDF_ImportKeyWithKEK"
	if len(wrapped) == 0 {
		return nil, argErr(op)
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var kh HANDLE
	if rv := C.import_key_with_kek(ctx, h, C.UINT32(alg), C.UINT32(kekIndex),
		bytePtr(wrapped), C.UINT32(len(wrapped)),
		(**C.long)(unsafe.Pointer(&kh))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Key{s: s, h: kh}, nil
}

// ImportKey 导入明文会话密钥(SDF_ImportKey,GM/T 0018-2012 6.3.20 密钥管理类;
// 2023 版已删除该函数,依赖可选符号,缺失时返回 SDR_NOTSUPPORT)。
// key 为空报 SDR_INARGERR。
func (s *Session) ImportKey(key []byte) (*Key, error) {
	const op = "SDF_ImportKey"
	if len(key) == 0 {
		return nil, argErr(op)
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var kh HANDLE
	if rv := C.import_key(ctx, h, bytePtr(key), C.UINT32(len(key)),
		(**C.long)(unsafe.Pointer(&kh))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Key{s: s, h: kh}, nil
}

// ivBytes 校验 IV:alg 无分组返回 SDR_ALGNOTSUPPORT;iv==nil 返回全零块;
// 长度必须等于分组长度,否则 SDR_INARGERR。
func ivBytes(alg ALGID, iv []byte, op string) ([]byte, error) {
	bs := alg.BlockSize()
	if bs == 0 {
		return nil, rvErr(op, SDR_ALGNOTSUPPORT)
	}
	if iv == nil {
		return make([]byte, bs), nil
	}
	if len(iv) != bs {
		return nil, argErr(op)
	}
	return iv, nil
}

// alignCheck 单包 ECB/CBC 运算要求数据为分组整数倍(其余模式任意长度)。
func alignCheck(alg ALGID, n int, op string) error {
	if mode := alg & 0xFF; mode != 0x01 && mode != 0x02 { // 非 ECB/CBC
		return nil
	}
	if n%alg.BlockSize() != 0 {
		return argErr(op)
	}
	return nil
}

// callCrypt 执行单包 SDF_Encrypt/SDF_Decrypt。单包语义不填充,
// 设备返回长度必须等于输入长度,否则报 SDR_OUTARGERR。
func callCrypt(encrypt bool, op string, ctx *C.sdf_ctx, sh, kh *C.long,
	alg ALGID, iv, data []byte,
) ([]byte, error) {
	out := make([]byte, len(data))
	outLen := C.UINT32(len(out))
	var rv C.RV
	if encrypt {
		rv = C.encrypt(ctx, sh, kh, C.UINT32(alg), bytePtr(iv), bytePtr(data),
			C.UINT32(len(data)), bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	} else {
		rv = C.decrypt(ctx, sh, kh, C.UINT32(alg), bytePtr(iv), bytePtr(data),
			C.UINT32(len(data)), bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	}
	if rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	if outLen != C.UINT32(len(out)) {
		return nil, rvErr(op, SDR_OUTARGERR)
	}
	return out[:outLen], nil
}

// Encrypt 单包加密,标准语义:不填充。
// alg 无分组返回 SDR_ALGNOTSUPPORT;iv==nil 视为全零块,非 nil 时长度必须等于分组长度;
// ECB/CBC 要求数据为分组整数倍;空输入返回空切片。
func (k *Key) Encrypt(alg ALGID, iv, plaintext []byte) ([]byte, error) {
	const op = "SDF_Encrypt"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	if err := alignCheck(alg, len(plaintext), op); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return []byte{}, nil
	}
	return callCrypt(true, op, ctx, sh, kh, alg, ivb, plaintext)
}

// Decrypt 单包解密,标准语义:不填充。校验规则同 Encrypt,空输入返回空切片。
func (k *Key) Decrypt(alg ALGID, iv, ciphertext []byte) ([]byte, error) {
	const op = "SDF_Decrypt"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	if err := alignCheck(alg, len(ciphertext), op); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return []byte{}, nil
	}
	return callCrypt(false, op, ctx, sh, kh, alg, ivb, ciphertext)
}

// EncryptPKCS7 单包加密,总是先做 PKCS7 填充(整分组也填充一个完整填充块),
// 保证解密端可无歧义去填充。IV/分组校验同 Encrypt。
func (k *Key) EncryptPKCS7(alg ALGID, iv, plaintext []byte) ([]byte, error) {
	const op = "SDF_Encrypt"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	padded := padding.NewPKCS7Padding(uint(alg.BlockSize())).Pad(plaintext)
	return callCrypt(true, op, ctx, sh, kh, alg, ivb, padded)
}

// DecryptPKCS7 单包解密并做 PKCS7 去填充;填充非法返回错误(不返回垃圾明文)。
func (k *Key) DecryptPKCS7(alg ALGID, iv, ciphertext []byte) ([]byte, error) {
	const op = "SDF_Decrypt"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	if err := alignCheck(alg, len(ciphertext), op); err != nil {
		return nil, err
	}
	plain, err := callCrypt(false, op, ctx, sh, kh, alg, ivb, ciphertext)
	if err != nil {
		return nil, err
	}
	unpadded, err := padding.NewPKCS7Padding(uint(alg.BlockSize())).Unpad(plain)
	if err != nil {
		return nil, fmt.Errorf("gosdf: DecryptPKCS7: invalid PKCS7 padding: %w", err)
	}
	return unpadded, nil
}

// MAC 单包 CBC-MAC,输出按设备返回长度截取。
func (k *Key) MAC(alg ALGID, iv, data []byte) ([]byte, error) {
	const op = "SDF_CalculateMAC"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	out := make([]byte, alg.BlockSize())
	outLen := C.UINT32(len(out))
	if rv := C.cbc_mac(ctx, sh, kh, C.UINT32(alg), bytePtr(ivb), bytePtr(data),
		C.UINT32(len(data)), bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	if outLen > C.UINT32(len(out)) {
		outLen = C.UINT32(len(out))
	}
	return out[:outLen], nil
}

// MACM3 先做 ISO9797-1 方法3填充再计算 MAC(抵御变长消息的长度扩展攻击)。
func (k *Key) MACM3(alg ALGID, iv, data []byte) ([]byte, error) {
	const op = "SDF_CalculateMAC"
	if alg.BlockSize() == 0 {
		return nil, rvErr(op, SDR_ALGNOTSUPPORT)
	}
	// 全切片表达式钉 cap==len:gmsm padding 对 cap 超出 len 的输入走别名快路径,
	// 会静默清零 data[0:BlockSize()],破坏调方缓冲且 MAC 计算错误。
	padded := padding.NewISO9797M3Padding(uint(alg.BlockSize())).Pad(data[:len(data):len(data)])
	return k.MAC(alg, iv, padded)
}

// 多步运算角色
const (
	cryptEnc = iota
	cryptDec
	cryptMAC
)

// finalBufSize 多步 Final 的最小输出缓冲(分组尾块与 MAC 输出 ≤16);
// finalBufMax 为按已投递数据量分配时的上限(兼容在 Final 输出全部数据的厂商)。
const (
	finalBufSize = 16
	finalBufMax  = 1 << 20
)

// Crypter 多步运算句柄(SDF_EncryptInit/DecryptInit/CalculateMACInit 系列)。
// 厂商 .so 缺少对应符号时构造返回 SDR_NOTSUPPORT;Final 之后再调用返回 SDR_STEPERR。
type Crypter struct {
	k       *Key // 对称加解密、MAC 使用
	role    int
	total   int // Update 已成功投递的数据量(用于 Final 输出缓冲)
	started bool
	done    bool
}

// prefix 返回当前角色的操作名前缀;nil 接收者返回 "SDF"。
func (c *Crypter) prefix() string {
	if c == nil {
		return "SDF"
	}
	switch c.role {
	case cryptEnc:
		return "SDF_Encrypt"
	case cryptDec:
		return "SDF_Decrypt"
	case cryptMAC:
		return "SDF_CalculateMAC"
	}
	return "SDF"
}

// handles 返回运算所需句柄。
func (c *Crypter) handles(op string) (*C.sdf_ctx, *C.long, *C.long, error) {
	return c.k.handles(op)
}

// NewEncrypter 初始化多步加密(SDF_EncryptInit)。
func (k *Key) NewEncrypter(alg ALGID, iv []byte) (*Crypter, error) {
	const op = "SDF_EncryptInit"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	if rv := C.enc_init(ctx, sh, kh, C.UINT32(alg), bytePtr(ivb), C.UINT32(len(ivb))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Crypter{k: k, role: cryptEnc, started: true}, nil
}

// NewDecrypter 初始化多步解密(SDF_DecryptInit)。
func (k *Key) NewDecrypter(alg ALGID, iv []byte) (*Crypter, error) {
	const op = "SDF_DecryptInit"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	if rv := C.dec_init(ctx, sh, kh, C.UINT32(alg), bytePtr(ivb), C.UINT32(len(ivb))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Crypter{k: k, role: cryptDec, started: true}, nil
}

// NewMAC 初始化多步 MAC(SDF_CalculateMACInit)。
func (k *Key) NewMAC(alg ALGID, iv []byte) (*Crypter, error) {
	const op = "SDF_CalculateMACInit"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	ivb, err := ivBytes(alg, iv, op)
	if err != nil {
		return nil, err
	}
	if rv := C.mac_init(ctx, sh, kh, C.UINT32(alg), bytePtr(ivb), C.UINT32(len(ivb))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Crypter{k: k, role: cryptMAC, started: true}, nil
}

// Update 追加数据。对称加解密返回本段输出;MAC 无输出参数,返回 (nil, nil)。
// Final 之后调用返回 SDR_STEPERR。
func (c *Crypter) Update(p []byte) ([]byte, error) {
	op := c.prefix() + "Update"
	if c == nil || !c.started || c.done {
		return nil, rvErr(op, SDR_STEPERR)
	}
	ctx, sh, _, err := c.handles(op) // 密钥句柄已在 Init 绑定
	if err != nil {
		return nil, err
	}
	switch c.role {
	case cryptEnc:
		out := make([]byte, len(p))
		outLen := C.UINT32(len(p))
		if rv := C.enc_update(ctx, sh, bytePtr(p), C.UINT32(len(p)),
			bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen))); rv != 0 {
			return nil, rvErr(op, RV(rv))
		}
		if outLen > C.UINT32(len(out)) {
			return nil, rvErr(op, SDR_OUTARGERR)
		}
		c.total += len(p)
		return out[:outLen], nil
	case cryptDec:
		out := make([]byte, len(p))
		outLen := C.UINT32(len(p))
		if rv := C.dec_update(ctx, sh, bytePtr(p), C.UINT32(len(p)),
			bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen))); rv != 0 {
			return nil, rvErr(op, RV(rv))
		}
		if outLen > C.UINT32(len(out)) {
			return nil, rvErr(op, SDR_OUTARGERR)
		}
		c.total += len(p)
		return out[:outLen], nil
	case cryptMAC:
		if rv := C.mac_update(ctx, sh, bytePtr(p), C.UINT32(len(p))); rv != 0 {
			return nil, rvErr(op, RV(rv))
		}
		return nil, nil
	}
	return nil, rvErr(op, SDR_NOTSUPPORT)
}

// Final 结束运算并返回尾部输出;加密/解密按已投递总量分配输出缓冲
// (上限 finalBufMax),兼容在 Final 输出全部数据的厂商;MAC 固定 16 字节。
// 之后再调用返回 SDR_STEPERR。
func (c *Crypter) Final() ([]byte, error) {
	op := c.prefix() + "Final"
	if c == nil || !c.started || c.done {
		return nil, rvErr(op, SDR_STEPERR)
	}
	ctx, sh, _, err := c.handles(op) // 密钥句柄已在 Init 绑定
	if err != nil {
		return nil, err
	}
	bufLen := finalBufSize
	if c.role != cryptMAC {
		bufLen = c.total
		if bufLen < finalBufSize {
			bufLen = finalBufSize
		}
		if bufLen > finalBufMax {
			bufLen = finalBufMax
		}
	}
	out := make([]byte, bufLen)
	outLen := C.UINT32(bufLen)
	var rv C.RV
	switch c.role {
	case cryptEnc:
		rv = C.enc_final(ctx, sh, bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	case cryptDec:
		rv = C.dec_final(ctx, sh, bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	case cryptMAC:
		rv = C.mac_final(ctx, sh, bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	default:
		return nil, rvErr(op, SDR_NOTSUPPORT)
	}
	if rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	c.done = true
	if outLen > C.UINT32(len(out)) {
		return nil, rvErr(op, SDR_OUTARGERR)
	}
	return out[:outLen], nil
}

// Block 返回 ECB 单分组 cipher.Block(可接入 stdlib cipher 模式)。
// 仅接受 SM1_ECB/SM4_ECB/SM7_ECB/AES_ECB;设备错误时 panic(接口无 error 路径)。
func (k *Key) Block(alg ALGID) (cipher.Block, error) {
	switch alg {
	case SM1_ECB, SM4_ECB, SM7_ECB, AES_ECB:
	default:
		return nil, rvErr("SDF_Encrypt", SDR_ALGMODNOTSUPPORT)
	}
	return &ecbBlock{k: k, alg: alg}, nil
}

type ecbBlock struct {
	k   *Key
	alg ALGID
}

func (b *ecbBlock) BlockSize() int { return b.alg.BlockSize() }

// Encrypt 单分组加密(一次 SDF 调用处理整段,ECB 等价)。
// dst/src 重叠时先拷贝 src;设备错误或输出长度异常时 panic。
func (b *ecbBlock) Encrypt(dst, src []byte) {
	const op = "SDF_Encrypt"
	bs := b.BlockSize()
	if len(src) != bs || len(dst) < bs {
		panic(argErr(op))
	}
	out, err := b.k.Encrypt(b.alg, nil, overlapCopy(dst, src))
	if err != nil {
		panic(err)
	}
	if len(out) != bs {
		panic(rvErr(op, SDR_OUTARGERR))
	}
	copy(dst, out)
}

// Decrypt 单分组解密,规则同 Encrypt。
func (b *ecbBlock) Decrypt(dst, src []byte) {
	const op = "SDF_Decrypt"
	bs := b.BlockSize()
	if len(src) != bs || len(dst) < bs {
		panic(argErr(op))
	}
	out, err := b.k.Decrypt(b.alg, nil, overlapCopy(dst, src))
	if err != nil {
		panic(err)
	}
	if len(out) != bs {
		panic(rvErr(op, SDR_OUTARGERR))
	}
	copy(dst, out)
}

// overlapCopy 在 src 与 dst[:len(src)] 重叠时返回拷贝,否则原样返回。
func overlapCopy(dst, src []byte) []byte {
	if len(src) == 0 || !overlaps(dst[:len(src)], src) {
		return src
	}
	return append([]byte(nil), src...)
}

func overlaps(a, b []byte) bool {
	return uintptr(unsafe.Pointer(&a[0])) < uintptr(unsafe.Pointer(&b[0]))+uintptr(len(b)) &&
		uintptr(unsafe.Pointer(&b[0])) < uintptr(unsafe.Pointer(&a[0]))+uintptr(len(a))
}
