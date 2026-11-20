package gosdf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/emmansun/gmsm/sm2"
)

var (
	stubSO         string // 桩动态库路径,空表示 cc 不可用或编译失败
	stubNoHMACSO   string // 缺 HMAC 符号的桩变体路径,空表示编译失败
	stubAEADSO     string // 流式 AEAD 桩变体路径,空表示编译失败
	stubBufSymSO   string // Final 才输出全部密文的对称桩变体路径,空表示编译失败
	stubRec        string // 桩参数记录文件
	stubSkipReason string // 桩不可用时的 skip 文案(记录真实原因,非笼统的 cc not available)
)

func TestMain(m *testing.M) {
	var stubDir string
	if cc, err := exec.LookPath("cc"); err == nil {
		if dir, err := os.MkdirTemp("", "gosdf-stub"); err == nil {
			so := filepath.Join(dir, "libsdf_stub.so")
			out, err := exec.Command(cc, "-shared", "-fPIC", "-I.", "-o", so,
				filepath.Join("testdata", "sdf_stub.c")).CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, "sdf_stub build failed: %v\n%s", err, out)
				stubSkipReason = fmt.Sprintf("sdf_stub build failed: %v", err)
				os.RemoveAll(dir)
			} else {
				stubDir, stubSO, stubRec = dir, so, filepath.Join(dir, "record.txt")

				// 缺符号变体(无 SDF_HMAC*):模拟 2012 时代 .so
				soNH := filepath.Join(dir, "libsdf_stub_nohmac.so")
				out, err := exec.Command(cc, "-shared", "-fPIC", "-I.",
					"-DGOSDF_STUB_OMIT_HMAC", "-o", soNH,
					filepath.Join("testdata", "sdf_stub.c")).CombinedOutput()
				if err != nil {
					fmt.Fprintf(os.Stderr, "sdf_stub(nohmac) build failed: %v\n%s", err, out)
					stubSkipReason = fmt.Sprintf("sdf_stub(nohmac) build failed: %v", err)
				} else {
					stubNoHMACSO = soNH
				}

				// 流式 AEAD 变体:Update 直接输出本段密文/明文,用于验证
				// AuthCrypter.Update 不会丢弃设备输出。
				soAEAD := filepath.Join(dir, "libsdf_stub_aead.so")
				out, err = exec.Command(cc, "-shared", "-fPIC", "-I.",
					"-DGOSDF_STUB_STREAM_AEAD", "-o", soAEAD,
					filepath.Join("testdata", "sdf_stub.c")).CombinedOutput()
				if err != nil {
					fmt.Fprintf(os.Stderr, "sdf_stub(aead) build failed: %v\n%s", err, out)
					stubSkipReason = fmt.Sprintf("sdf_stub(aead) build failed: %v", err)
				} else {
					stubAEADSO = soAEAD
				}

				// 缓冲对称变体:Update 只累计,Final 才输出全部密文,
				// 用于验证 Crypter.Final 按已投递数据量分配缓冲。
				soBufSym := filepath.Join(dir, "libsdf_stub_bufsym.so")
				out, err = exec.Command(cc, "-shared", "-fPIC", "-I.",
					"-DGOSDF_STUB_BUFFERED_SYM", "-o", soBufSym,
					filepath.Join("testdata", "sdf_stub.c")).CombinedOutput()
				if err != nil {
					fmt.Fprintf(os.Stderr, "sdf_stub(bufsym) build failed: %v\n%s", err, out)
					stubSkipReason = fmt.Sprintf("sdf_stub(bufsym) build failed: %v", err)
				} else {
					stubBufSymSO = soBufSym
				}
			}
		} else {
			stubSkipReason = fmt.Sprintf("stub MkdirTemp: %v", err)
		}
	} else {
		stubSkipReason = "cc not available, stub device tests skipped"
	}
	code := m.Run()
	if stubDir != "" {
		os.RemoveAll(stubDir)
	}
	os.Exit(code)
}

// openStub 打开桩设备并返回会话;cc 不可用时 Skip。
func openStub(t *testing.T) (*Device, *Session) {
	return openStubSO(t, stubSO)
}

// openStubSO 打开指定桩动态库并返回会话;so 为空时按 stubSkipReason 跳过。
func openStubSO(t *testing.T, so string) (*Device, *Session) {
	t.Helper()
	if so == "" {
		t.Skip(stubSkipReason)
	}
	t.Setenv("SDF_STUB_RECORD", stubRec)
	if err := os.Remove(stubRec); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clear stub record: %v", err)
	}
	dev, err := Open(so)
	if err != nil {
		t.Fatalf("Open(stub): %v", err)
	}
	t.Cleanup(func() { dev.Close() })
	sess, err := dev.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return dev, sess
}

// readRecord 读取桩参数记录文件全部内容。
func readRecord(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(stubRec)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read stub record: %v", err)
	}
	return string(b)
}

// recordLine 返回以 prefix 开头的记录行。
func recordLine(t *testing.T, prefix string) string {
	t.Helper()
	all := readRecord(t)
	for _, line := range strings.Split(all, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("record %q not found in stub log:\n%s", prefix, all)
	return ""
}

// validSM2Pub 返回一个 SM2 有效公钥(供 ZA 杂凑等入参校验路径使用)。
func validSM2Pub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	x, y := sm2.P256().ScalarBaseMult(bytes.Repeat([]byte{1}, 32))
	return &ecdsa.PublicKey{Curve: sm2.P256(), X: x, Y: y}
}

// ---- 纯 Go 单测(无设备) ----

// TestSignatureRoundTripLeadingZero 回归:R/S 含前导零时必须左补零到 64 字节定长。
func TestSignatureRoundTripLeadingZero(t *testing.T) {
	sBytes := make([]byte, 32)
	sBytes[0] = 0x00 // 32 字节窗口首字节为 0(前导零)
	sBytes[1] = 0x80
	sBytes[31] = 0x7F
	der, err := asn1.Marshal(sm2SignatureASN1{R: big.NewInt(1), S: new(big.Int).SetBytes(sBytes)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	sig, err := sigDERtoECC(der)
	if err != nil {
		t.Fatalf("sigDERtoECC: %v", err)
	}
	var wantR eccSignature
	wantR.R[63] = 0x01 // R = 1,右对齐
	if !bytes.Equal(sig.R[:], wantR.R[:]) {
		t.Fatalf("R = %x, want right-aligned 01", sig.R)
	}
	wantS := eccSignature{}
	copy(wantS.S[32:], sBytes) // 32 字节窗口右对齐到 64 字节数组
	if !bytes.Equal(sig.S[:], wantS.S[:]) {
		t.Fatalf("S = %x, want %x", sig.S, wantS.S)
	}

	der2, err := sigECCtoDER(sig)
	if err != nil {
		t.Fatalf("sigECCtoDER: %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Fatalf("DER round trip mismatch:\n%x\n%x", der, der2)
	}
}

// TestCipherRoundTripLeadingZero 回归:X/Y 含前导零时必须左补零到 64 字节定长。
func TestCipherRoundTripLeadingZero(t *testing.T) {
	xBytes := make([]byte, 32)
	xBytes[0] = 0x00
	xBytes[1] = 0x01
	xBytes[31] = 0x02
	hash := bytes.Repeat([]byte{0xAB}, Sm3HashSize)
	text := []byte("hello sm2 cipher")

	der, err := asn1.Marshal(sm2CipherASN1{
		X:          new(big.Int).SetBytes(xBytes),
		Y:          big.NewInt(0x0304),
		HASH:       hash,
		CipherText: text,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	buf, err := cipherDERtoECC(der)
	if err != nil {
		t.Fatalf("cipherDERtoECC: %v", err)
	}
	if !bytes.Equal(buf[eccCipherYOff-32:eccCipherYOff], xBytes) {
		t.Fatalf("X = %x, want right-aligned %x", buf[eccCipherXOff:eccCipherYOff], xBytes)
	}
	if buf[eccCipherYOff+62] != 0x03 || buf[eccCipherYOff+63] != 0x04 {
		t.Fatalf("Y = %x, want right-aligned 0304", buf[eccCipherYOff:eccCipherMOff])
	}
	if l := eccCipherContentLen(buf); l != len(text) {
		t.Fatalf("L = %d, want %d", l, len(text))
	}
	if !bytes.Equal(buf[eccCipherMOff:eccCipherLOff], hash) {
		t.Fatal("HASH mismatch")
	}

	der2, err := cipherECCtoDER(buf)
	if err != nil {
		t.Fatalf("cipherECCtoDER: %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Fatalf("DER round trip mismatch:\n%x\n%x", der, der2)
	}
}

// TestBlockSize 校验 ALGID.BlockSize 映射。
func TestBlockSize(t *testing.T) {
	cases := map[ALGID]int{
		SM1_ECB: 16, SM1_MAC: 16,
		SM4_ECB: 16, SM4_CBC: 16, SM4_MAC: 16, SM4_CTR: 16,
		SM7_ECB: 16,
		AES_ECB: 16, AES_CTR: 16,
		SGD_SM3: 0, SGD_SHA256: 0, SGD_SM3_HMAC: 0,
		SGD_SM2_1: 0, SGD_SM2_3: 0,
	}
	for alg, want := range cases {
		if got := alg.BlockSize(); got != want {
			t.Errorf("ALGID(%#x).BlockSize() = %d, want %d", uint32(alg), got, want)
		}
	}
}

// TestSigCipherDERRejects 回归:DER→ABI 转换的全部拒绝路径(sm2.go)。
func TestSigCipherDERRejects(t *testing.T) {
	// 签名:非 DER 乱字节。
	if _, err := sigDERtoECC([]byte{0x30, 0x03, 0x02, 0x01}); err == nil ||
		!strings.Contains(err.Error(), "SM2 signature decode") {
		t.Errorf("sigDERtoECC(garbage) error = %v, want SM2 signature decode", err)
	}

	// R≤0 / S≤0。
	for _, tc := range []struct {
		name string
		r, s *big.Int
	}{
		{"R=0", big.NewInt(0), big.NewInt(1)},
		{"S=0", big.NewInt(1), big.NewInt(0)},
	} {
		der, err := asn1.Marshal(sm2SignatureASN1{R: tc.r, S: tc.s})
		if err != nil {
			t.Fatalf("marshal %s: %v", tc.name, err)
		}
		if _, err := sigDERtoECC(der); err == nil || !strings.Contains(err.Error(), "invalid R/S") {
			t.Errorf("sigDERtoECC(%s) error = %v, want invalid R/S", tc.name, err)
		}
	}

	// R ≥ 2^512(65 字节)超出 64 字节定长窗口 → padLeft 溢出 SDR_INARGERR。
	// 注意溢出阈值是定长 64 字节而非 SM2 的 256 位:33 字节的超宽 R 照单全收。
	over := new(big.Int).Lsh(big.NewInt(1), 512)
	der, err := asn1.Marshal(sm2SignatureASN1{R: over, S: big.NewInt(1)})
	if err != nil {
		t.Fatalf("marshal over-wide R: %v", err)
	}
	if _, err := sigDERtoECC(der); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("sigDERtoECC(over-wide R) error = %v, want SDR_INARGERR", err)
	}

	// 尾随垃圾字节(外层 TLV 后有 rest)。
	good, err := asn1.Marshal(sm2SignatureASN1{R: big.NewInt(1), S: big.NewInt(1)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := sigDERtoECC(append(good, 0x00)); err == nil ||
		!strings.Contains(err.Error(), "invalid R/S") {
		t.Errorf("sigDERtoECC(trailing garbage) error = %v, want invalid R/S", err)
	}

	// 密文:非 DER 乱字节。
	if _, err := cipherDERtoECC([]byte{0x01, 0x02, 0x03}); err == nil ||
		!strings.Contains(err.Error(), "SM2 cipher decode") {
		t.Errorf("cipherDERtoECC(garbage) error = %v, want SM2 cipher decode", err)
	}

	// HASH 非 32 字节。
	badHash, err := asn1.Marshal(sm2CipherASN1{
		X: big.NewInt(1), Y: big.NewInt(2),
		HASH: make([]byte, Sm3HashSize-1), CipherText: []byte{1},
	})
	if err != nil {
		t.Fatalf("marshal bad-hash: %v", err)
	}
	if _, err := cipherDERtoECC(badHash); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("cipherDERtoECC(short HASH) error = %v, want SDR_INARGERR", err)
	}

	// CipherText 超 ECCref_MAX_CIPHER_LEN(136)字节。
	bigCT, err := asn1.Marshal(sm2CipherASN1{
		X: big.NewInt(1), Y: big.NewInt(2),
		HASH: make([]byte, Sm3HashSize), CipherText: make([]byte, int(ECCref_MAX_CIPHER_LEN)+1),
	})
	if err != nil {
		t.Fatalf("marshal big-ct: %v", err)
	}
	if _, err := cipherDERtoECC(bigCT); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("cipherDERtoECC(137-byte CT) error = %v, want SDR_INARGERR", err)
	}

	// 结构缺失分支(len(rest)!=0 || X/Y==nil → invalid structure):
	// 尾随垃圾使 len(rest)!=0 走该分支;序列缺字段会在 asn1.Unmarshal 阶段
	// 就报 "sequence truncated",走不到 X/Y==nil。
	fullCipher, err := asn1.Marshal(sm2CipherASN1{
		X: big.NewInt(1), Y: big.NewInt(2),
		HASH: make([]byte, Sm3HashSize), CipherText: []byte{1},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := cipherDERtoECC(append(fullCipher, 0x00)); err == nil ||
		!strings.Contains(err.Error(), "invalid structure") {
		t.Errorf("cipherDERtoECC(trailing garbage) error = %v, want invalid structure", err)
	}
}

// TestPubToECCRejectsInvalid 回归:SM2 公钥入参必须是 sm2.P256() 曲线上的点。
func TestPubToECCRejectsInvalid(t *testing.T) {
	if _, err := pubToECC(nil); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToECC(nil) error = %v, want SDR_INARGERR", err)
	}
	if _, err := pubToECC(&ecdsa.PublicKey{Curve: sm2.P256()}); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToECC(X/Y nil) error = %v, want SDR_INARGERR", err)
	}
	zero := &ecdsa.PublicKey{Curve: sm2.P256(), X: big.NewInt(0), Y: big.NewInt(0)}
	if _, err := pubToECC(zero); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToECC(0,0) error = %v, want SDR_INARGERR", err)
	}
	off := &ecdsa.PublicKey{Curve: sm2.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	if _, err := pubToECC(off); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToECC(off-curve) error = %v, want SDR_INARGERR", err)
	}
	// 非 SM2 曲线:即便点在 P384 自己的曲线上也拒绝。
	x, y := elliptic.P384().ScalarBaseMult(bytes.Repeat([]byte{3}, 48))
	p384 := &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}
	if _, err := pubToECC(p384); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("pubToECC(P384) error = %v, want SDR_INARGERR", err)
	}
}

// TestOpenErrors 钉住 Open 的失败契约:空路径 SDR_INARGERR;dlopen 失败
// (不存在 / 存在但非 ELF)返回错误文本含 SDF_OpenDevice 的 rvErr。
func TestOpenErrors(t *testing.T) {
	if _, err := Open(""); !errors.Is(err, SDR_INARGERR) {
		t.Errorf(`Open("") error = %v, want SDR_INARGERR`, err)
	}
	for _, p := range []string{"/no/such/lib.so", filepath.Join("testdata", "sdf_stub.c")} {
		_, err := Open(p)
		if err == nil {
			t.Errorf("Open(%q) = nil error, want failure", p)
			continue
		}
		if !strings.Contains(err.Error(), "SDF_OpenDevice") {
			t.Errorf("Open(%q) error = %v, want SDF_OpenDevice in message", p, err)
		}
	}
}

// ---- 桩设备集成测试 ----

// TestDestroyKeyReceivesSessionAndKey 回归:DestroyKey 必须分别传 session 与 key
// (旧实现两个参数都传了 key)。
func TestDestroyKeyReceivesSessionAndKey(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	sessH := uintptr(unsafe.Pointer(sess.h))
	keyH := uintptr(unsafe.Pointer(key.h))
	if sessH == keyH {
		t.Fatal("test setup: session and key handles must differ")
	}
	if err := key.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	line := recordLine(t, "destroy:")
	parts := strings.Split(line, ":")
	if len(parts) != 3 {
		t.Fatalf("malformed destroy record %q", line)
	}
	gotSess, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}
	gotKey, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if uintptr(gotSess) != sessH {
		t.Errorf("DestroyKey session = %#x, want %#x", uintptr(gotSess), sessH)
	}
	if uintptr(gotKey) != keyH {
		t.Errorf("DestroyKey key = %#x, want %#x", uintptr(gotKey), keyH)
	}
	if err := key.Destroy(); err != nil {
		t.Errorf("Destroy not idempotent: %v", err)
	}
}

// TestFileOpsPassFileName 回归:文件名必须真实传给设备
// (旧实现传的是全零缓冲,"foo.txt" 变成 7 个 0x00)。
func TestFileOpsPassFileName(t *testing.T) {
	_, sess := openStub(t)
	const name = "foo.txt"

	if err := sess.CreateFile(name, 64); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if line := recordLine(t, "file:create:"); line != "file:create:"+name {
		t.Errorf("CreateFile recorded %q, want %q", line, name)
	}

	if err := sess.WriteFile(name, 0, []byte("hi")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if line := recordLine(t, "file:write:"); line != "file:write:"+name {
		t.Errorf("WriteFile recorded %q, want %q", line, name)
	}

	data, err := sess.ReadFile(name, 0, 16)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hi" {
		t.Errorf("ReadFile = %q, want %q", data, "hi")
	}
	if line := recordLine(t, "file:read:"); line != "file:read:"+name {
		t.Errorf("ReadFile recorded %q, want %q", line, name)
	}

	if err := sess.DeleteFile(name); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if line := recordLine(t, "file:delete:"); line != "file:delete:"+name {
		t.Errorf("DeleteFile recorded %q, want %q", line, name)
	}
}

// TestEmptyInputsNoPanic 回归:空明文/空 Update/零长度随机数/空 uid 均不得 panic。
func TestEmptyInputsNoPanic(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}

	out, err := key.Encrypt(SM4_ECB, nil, nil)
	if err != nil {
		t.Fatalf("empty Encrypt: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("empty Encrypt returned %d bytes", len(out))
	}

	c, err := key.NewEncrypter(SM4_ECB, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	part, err := c.Update(nil)
	if err != nil {
		t.Fatalf("empty Update: %v", err)
	}
	if len(part) != 0 {
		t.Errorf("empty Update returned %d bytes", len(part))
	}

	n, err := sess.GenerateRandom(0)
	if err != nil {
		t.Fatalf("GenerateRandom(0): %v", err)
	}
	if len(n) != 0 {
		t.Errorf("GenerateRandom(0) returned %d bytes", len(n))
	}

	h, err := sess.NewSM2ZAHash(validSM2Pub(t), nil)
	if err != nil {
		t.Fatalf("NewSM2ZAHash with empty uid: %v", err)
	}
	if err := h.Update(nil); err != nil {
		t.Fatalf("ZA Update: %v", err)
	}
	digest, err := h.Final()
	if err != nil {
		t.Fatalf("ZA Final: %v", err)
	}
	if len(digest) != Sm3HashSize {
		t.Errorf("ZA digest length = %d, want %d", len(digest), Sm3HashSize)
	}
}

// TestSymmetricRoundTrip 回归:EncryptPKCS7 总是填充,往返一致
// (旧实现整分组不填充,解密端无法无歧义去填充)。
func TestSymmetricRoundTrip(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	iv := bytes.Repeat([]byte{0x01}, Sm4BlockSize)
	plain := []byte("round trip, non-block-aligned!")

	ct, err := key.EncryptPKCS7(SM4_CBC, iv, plain)
	if err != nil {
		t.Fatalf("EncryptPKCS7: %v", err)
	}
	back, err := key.DecryptPKCS7(SM4_CBC, iv, ct)
	if err != nil {
		t.Fatalf("DecryptPKCS7: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", back, plain)
	}
}

// TestPKCS7AlwaysPads 回归:整分组输入也必须填充(16 → 32 字节)。
func TestPKCS7AlwaysPads(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	ct, err := key.EncryptPKCS7(SM4_ECB, nil, make([]byte, Sm4BlockSize))
	if err != nil {
		t.Fatalf("EncryptPKCS7: %v", err)
	}
	if len(ct) != 2*Sm4BlockSize {
		t.Fatalf("EncryptPKCS7(16 zero bytes) = %d bytes, want %d (full padding block)",
			len(ct), 2*Sm4BlockSize)
	}
}

// TestDecryptPKCS7BadPadding 填充非法必须返回错误,不得吞掉返回垃圾明文。
func TestDecryptPKCS7BadPadding(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	iv := bytes.Repeat([]byte{0x01}, Sm4BlockSize)
	// 16 字节明文经 XOR 桩后解密得 16 字节,末字节 0x00 不是合法 PKCS7 填充
	_, err = key.DecryptPKCS7(SM4_CBC, iv, bytes.Repeat([]byte{0x5A}, Sm4BlockSize))
	if err == nil {
		t.Fatal("DecryptPKCS7 with invalid padding returned nil error")
	}
}

// TestMultiPartEqualsOneShot 多包 Update 分 3 块 + Final 必须等于单包输出。
func TestMultiPartEqualsOneShot(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	data := bytes.Repeat([]byte("0123456789abcdef"), 3) // 48 字节,3 个分组

	one, err := key.Encrypt(SM4_ECB, nil, data)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	c, err := key.NewEncrypter(SM4_ECB, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	var got []byte
	for i := 0; i < len(data); i += Sm4BlockSize {
		part, err := c.Update(data[i : i+Sm4BlockSize])
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		got = append(got, part...)
	}
	tail, err := c.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	got = append(got, tail...)

	if !bytes.Equal(got, one) {
		t.Fatalf("multi-part != one-shot:\n got %x\nwant %x", got, one)
	}
	if _, err := c.Final(); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("second Final error = %v, want SDR_STEPERR", err)
	}
	if _, err := c.Update(data); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("Update after Final error = %v, want SDR_STEPERR", err)
	}
}

// TestHMACFlow 回归:NewHMAC 分块累加 == HMAC 一步式(2023 SDF_HMACInit/Update/Final),
// 并钉住设备边界:传给 SDF_HMACInit 的必须是密钥句柄(非会话句柄),
// uiAlgID 为杂凑标识 SGD_SM3(调用方传 SGD_SM3_HMAC,内部映射)。
func TestHMACFlow(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}

	want, err := key.HMAC(SGD_SM3_HMAC, []byte("hello hmac"))
	if err != nil {
		t.Fatalf("HMAC: %v", err)
	}
	if len(want) != 32 {
		t.Fatalf("HMAC length = %d, want 32", len(want))
	}

	line := recordLine(t, "hmacinit:")
	parts := strings.Split(line, ":")
	if len(parts) != 3 {
		t.Fatalf("malformed hmacinit record %q", line)
	}
	gotKey, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	gotAlg, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		t.Fatalf("parse alg: %v", err)
	}
	if uintptr(gotKey) != uintptr(unsafe.Pointer(key.h)) {
		t.Errorf("SDF_HMACInit key handle = %#x, want %#x",
			uintptr(gotKey), uintptr(unsafe.Pointer(key.h)))
	}
	if ALGID(gotAlg) != SGD_SM3 {
		t.Errorf("SDF_HMACInit uiAlgID = %#x, want SGD_SM3(%#x)", gotAlg, uint32(SGD_SM3))
	}

	h, err := key.NewHMAC(SGD_SM3_HMAC)
	if err != nil {
		t.Fatalf("NewHMAC: %v", err)
	}
	if err := h.Update([]byte("hello ")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := h.Update([]byte("hmac")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := h.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("multi-part HMAC = %x, want %x", got, want)
	}
}

// TestSupports 覆盖 Device.Supports:绑定符号 true、未绑定符号 false、关闭后 false。
func TestSupports(t *testing.T) {
	dev, _ := openStub(t)
	if !dev.Supports("SDF_HMACInit") {
		t.Error(`Supports("SDF_HMACInit") = false, want true`)
	}
	if !dev.Supports("SDF_Encrypt") {
		t.Error(`Supports("SDF_Encrypt") = false, want true`)
	}
	if dev.Supports("SDF_Nosuch") {
		t.Error(`Supports("SDF_Nosuch") = true, want false`)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if dev.Supports("SDF_Encrypt") {
		t.Error("Supports after Close = true, want false")
	}
}

// TestMissingHMACSymbols 缺符号端到端:2012 时代 .so(无 SDF_HMAC*)上
// sdf_open 不失败,HMAC 按符号降级返回 SDR_NOTSUPPORT,其余功能不受影响。
func TestMissingHMACSymbols(t *testing.T) {
	// openStubSO 内 Open 失败即 Fatalf:sdf_open 不因缺符号失败在此钉住
	_, sess := openStubSO(t, stubNoHMACSO)
	dev := sess.d

	if dev.Supports("SDF_HMACInit") {
		t.Fatal(`Supports("SDF_HMACInit") = true, want false on no-HMAC stub`)
	}
	if !dev.Supports("SDF_Encrypt") {
		t.Fatal(`Supports("SDF_Encrypt") = false, want true on no-HMAC stub`)
	}

	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	if _, err := key.HMAC(SGD_SM3_HMAC, []byte("hello")); !errors.Is(err, SDR_NOTSUPPORT) {
		t.Errorf("HMAC error = %v, want SDR_NOTSUPPORT", err)
	}
	if _, err := key.NewHMAC(SGD_SM3_HMAC); !errors.Is(err, SDR_NOTSUPPORT) {
		t.Errorf("NewHMAC error = %v, want SDR_NOTSUPPORT", err)
	}

	plain := []byte("0123456789abcdef") // 16 字节单分组(Encrypt 不填充)
	ct, err := key.Encrypt(SM4_ECB, nil, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	back, err := key.Decrypt(SM4_ECB, nil, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", back, plain)
	}
}

// TestErrorsIs 设备错误经 errors.Is 可判定,且错误串包含 SDF 函数名。
func TestErrorsIs(t *testing.T) {
	_, sess := openStub(t)
	err := sess.AcquireKeyRight(7, []byte("123456"))
	if !errors.Is(err, SDR_KEYNOTEXIST) {
		t.Fatalf("AcquireKeyRight(7) error = %v, want SDR_KEYNOTEXIST", err)
	}
	if !strings.Contains(err.Error(), "SDF_GetPrivateKeyAccessRight") {
		t.Errorf("error %q does not contain function name", err)
	}
}

// TestGetDeviceInfo 覆盖 C DEVICEINFO → Go 字符串的转换(尾部 NUL 截断)。
func TestGetDeviceInfo(t *testing.T) {
	_, sess := openStub(t)
	info, err := sess.GetDeviceInfo()
	if err != nil {
		t.Fatalf("GetDeviceInfo: %v", err)
	}
	if info.IssuerName != "stub-issuer" {
		t.Errorf("IssuerName = %q, want %q", info.IssuerName, "stub-issuer")
	}
	if info.DeviceName != "stub-dev" {
		t.Errorf("DeviceName = %q, want %q", info.DeviceName, "stub-dev")
	}
	if info.DeviceSerial != "0001" {
		t.Errorf("DeviceSerial = %q, want %q", info.DeviceSerial, "0001")
	}
	if info.BufferSize != 65536 {
		t.Errorf("BufferSize = %d, want 65536", info.BufferSize)
	}
}

// TestECCCipherOutputPaths 覆盖设备写入 ECCCipher 柔性数组缓冲的路径
// (原缺陷:Go 结构定长 128 < 厂商 136,密文越界写 Go 堆)。
func TestECCCipherOutputPaths(t *testing.T) {
	_, sess := openStub(t)
	pub := validSM2Pub(t)

	// 外部加密 → DER 解析设备输出(SM2 私钥解密不在标准中,经 DER↔ECCCipher 往返校验布局)
	msg := []byte("digital envelope round trip")
	ct, err := sess.SM2Encrypt(pub, msg)
	if err != nil {
		t.Fatalf("SM2Encrypt: %v", err)
	}
	cbuf, err := cipherDERtoECC(ct)
	if err != nil {
		t.Fatalf("cipherDERtoECC: %v", err)
	}
	if got := eccCipherContentLen(cbuf); got != len(msg) {
		t.Fatalf("cipher content len = %d, want %d", got, len(msg))
	}
	back, err := cipherECCtoDER(cbuf)
	if err != nil {
		t.Fatalf("cipherECCtoDER: %v", err)
	}
	if !bytes.Equal(back, ct) {
		t.Fatal("DER ↔ ECCCipher round trip mismatch")
	}

	// 密钥包装:GenerateKeyWithEPK → DER → ImportKeyWithISK
	wrapped, key, err := sess.GenerateKeyWithEPK(128, pub)
	if err != nil {
		t.Fatalf("GenerateKeyWithEPK: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("GenerateKeyWithEPK returned empty wrapped key")
	}
	key2, err := sess.ImportKeyWithISK(1, wrapped)
	if err != nil {
		t.Fatalf("ImportKeyWithISK: %v", err)
	}
	if err := key.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}
	if err := key2.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}

	wrappedIPK, keyIPK, err := sess.GenerateKeyWithIPK(1, 128)
	if err != nil {
		t.Fatalf("GenerateKeyWithIPK: %v", err)
	}
	if len(wrappedIPK) == 0 {
		t.Fatal("GenerateKeyWithIPK returned empty wrapped key")
	}
	if err := keyIPK.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}
}

// TestGenerateKeyPairECC 覆盖 SDF_GenerateKeyPair_ECC 绑定(2023 表16 验证调试类,
// 2012 6.3.10 密钥管理类):ECCrefPublicKey/PrivateKey → crypto/ecdsa 转换校验。
func TestGenerateKeyPairECC(t *testing.T) {
	_, sess := openStub(t)
	priv, err := sess.GenerateKeyPairECC(SGD_SM2_1, 256)
	if err != nil {
		t.Fatalf("GenerateKeyPairECC: %v", err)
	}
	if priv.D == nil || priv.D.Sign() <= 0 {
		t.Fatal("private key D not positive")
	}
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
		t.Fatal("public key not on curve")
	}
}

// TestExchangeEnvelopeECC 覆盖 SDF_ExchangeDigitEnvelopeBaseOnECC 绑定
// (2012 6.3.17 密钥管理类,2023 已删除,可选符号):DER 密文进、DER 密文出,L 保留。
// §6.3.17 要求输入为内部加密公钥(GM/T 0018 IPK)信封,EPK 信封输入真机必 SDR_SKOPERR。
func TestExchangeEnvelopeECC(t *testing.T) {
	_, sess := openStub(t)
	pub := validSM2Pub(t)
	wrapped, key, err := sess.GenerateKeyWithIPK(1, 128)
	if err != nil {
		t.Fatalf("GenerateKeyWithIPK: %v", err)
	}
	defer key.Destroy()

	out, err := sess.ExchangeEnvelopeECC(1, SGD_SM2_3, pub, wrapped)
	if err != nil {
		t.Fatalf("ExchangeEnvelopeECC: %v", err)
	}
	inBuf, err := cipherDERtoECC(wrapped)
	if err != nil {
		t.Fatalf("cipherDERtoECC(in): %v", err)
	}
	outBuf, err := cipherDERtoECC(out)
	if err != nil {
		t.Fatalf("cipherDERtoECC(out): %v", err)
	}
	if eccCipherContentLen(outBuf) != eccCipherContentLen(inBuf) {
		t.Fatalf("envelope L changed: in %d, out %d",
			eccCipherContentLen(inBuf), eccCipherContentLen(outBuf))
	}
}

// TestRsaKeyMgmt 覆盖 RSA 密钥管理类绑定:导出公钥、密钥对生成(验证调试类)、
// IPK/EPK/ISK 会话密钥封装、明文会话密钥导入(2012 6.3.20)、数字信封转换(2012 6.3.7)。
func TestRsaKeyMgmt(t *testing.T) {
	_, sess := openStub(t)

	pub, err := sess.ExportSignPublicKeyRSA(2)
	if err != nil {
		t.Fatalf("ExportSignPublicKeyRSA: %v", err)
	}
	if pub.N == nil || pub.N.Sign() <= 0 {
		t.Fatal("exported sign public key has no modulus")
	}
	encPub, err := sess.ExportEncPublicKeyRSA(2)
	if err != nil {
		t.Fatalf("ExportEncPublicKeyRSA: %v", err)
	}
	if encPub.N == nil || encPub.N.Sign() <= 0 {
		t.Fatal("exported enc public key has no modulus")
	}

	priv, err := sess.GenerateKeyPairRSA(1024)
	if err != nil {
		t.Fatalf("GenerateKeyPairRSA: %v", err)
	}
	if priv.D == nil || priv.D.Sign() <= 0 {
		t.Fatal("generated private key D not positive")
	}
	if priv.N.Cmp(priv.PublicKey.N) != 0 {
		t.Fatal("key pair modulus mismatch")
	}

	wrappedIPK, keyIPK, err := sess.GenerateKeyWithIPKRSA(1, 128)
	if err != nil {
		t.Fatalf("GenerateKeyWithIPKRSA: %v", err)
	}
	if len(wrappedIPK) == 0 {
		t.Fatal("GenerateKeyWithIPKRSA returned empty wrapped key")
	}
	if err := keyIPK.Destroy(); err != nil {
		t.Errorf("Destroy keyIPK: %v", err)
	}

	wrappedEPK, keyEPK, err := sess.GenerateKeyWithEPKRSA(128, pub)
	if err != nil {
		t.Fatalf("GenerateKeyWithEPKRSA: %v", err)
	}
	keyISK, err := sess.ImportKeyWithISKRSA(1, wrappedEPK)
	if err != nil {
		t.Fatalf("ImportKeyWithISKRSA: %v", err)
	}
	if err := keyEPK.Destroy(); err != nil {
		t.Errorf("Destroy keyEPK: %v", err)
	}
	if err := keyISK.Destroy(); err != nil {
		t.Errorf("Destroy keyISK: %v", err)
	}

	keyPlain, err := sess.ImportKey(bytes.Repeat([]byte{0x5A}, 16))
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if err := keyPlain.Destroy(); err != nil {
		t.Errorf("Destroy keyPlain: %v", err)
	}

	// §6.3.17:输入须为内部公钥(IPK)信封,裸字节/EPK 信封真机不可解。
	out, err := sess.ExchangeEnvelopeRSA(2, pub, wrappedIPK)
	if err != nil {
		t.Fatalf("ExchangeEnvelopeRSA: %v", err)
	}
	if len(out) != len(wrappedIPK) {
		t.Fatalf("envelope conversion length = %d, want %d", len(out), len(wrappedIPK))
	}
}

// TestSM2SignVerifyStub 覆盖 crypto.Signer 各分支与验签路径。
func TestSM2SignVerifyStub(t *testing.T) {
	_, sess := openStub(t)
	signer, err := sess.NewSignerKey(1)
	if err != nil {
		t.Fatalf("NewSignerKey: %v", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != sm2.P256() {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey on sm2.P256()", signer.Public())
	}

	// 消息路径(*SM2SignerOptions,digest 参数为原始消息)
	msg := []byte("sign me")
	sig, err := signer.Sign(nil, msg, &SM2SignerOptions{})
	if err != nil {
		t.Fatalf("Sign with SM2SignerOptions: %v", err)
	}
	if err := sess.VerifySM2(pub, nil, msg, sig); err != nil {
		t.Fatalf("VerifySM2: %v", err)
	}

	// 预摘要路径(opts 缺省,digest 必须 32 字节)
	digest := bytes.Repeat([]byte{7}, Sm3HashSize)
	sig2, err := signer.Sign(nil, digest, nil)
	if err != nil {
		t.Fatalf("Sign pre-digested: %v", err)
	}
	if err := sess.VerifySM2Digest(pub, digest, sig2); err != nil {
		t.Fatalf("VerifySM2Digest: %v", err)
	}
	if _, err := signer.Sign(nil, []byte("short"), nil); !errors.Is(err, SDR_INARGERR) {
		t.Errorf("Sign with short digest error = %v, want SDR_INARGERR", err)
	}

	// gmsm 的 SM2SignerOption(uid 不可导出)不被猜测支持
	if _, err := signer.Sign(nil, msg, sm2.DefaultSM2SignerOpts); err == nil {
		t.Fatal("Sign with gmsm SM2SignerOption: want unsupported-opts error, got nil")
	}
}

// TestStubExternalVerifyDeterministic 回归:桩验签与 InternalSign 同一确定性
// 派生规则(修复前恒 SDR_OK,验签接线回归检测不到):正确签名 SDR_OK,
// 签名末字节翻转/错摘要一律 SDR_VERIFYERR。
func TestStubExternalVerifyDeterministic(t *testing.T) {
	_, sess := openStub(t)
	signer, err := sess.NewSignerKey(1)
	if err != nil {
		t.Fatalf("NewSignerKey: %v", err)
	}
	pub := signer.Public().(*ecdsa.PublicKey)
	digest := bytes.Repeat([]byte{7}, Sm3HashSize)
	sig, err := signer.Sign(nil, digest, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := sess.VerifySM2Digest(pub, digest, sig); err != nil {
		t.Fatalf("VerifySM2Digest(correct) = %v, want nil", err)
	}

	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01 // 末字节恒为 S 的 DER 内容字节
	if err := sess.VerifySM2Digest(pub, digest, bad); !errors.Is(err, SDR_VERIFYERR) {
		t.Errorf("VerifySM2Digest(flipped sig) = %v, want SDR_VERIFYERR", err)
	}

	other := bytes.Repeat([]byte{8}, Sm3HashSize)
	if err := sess.VerifySM2Digest(pub, other, sig); !errors.Is(err, SDR_VERIFYERR) {
		t.Errorf("VerifySM2Digest(wrong digest) = %v, want SDR_VERIFYERR", err)
	}
}

// TestArgValidation 钉住参数校验/错误契约(aead/sm4/session 三组),
// 断言值来源 aead.go 的 aeadAlgCheck/aeadStartVarCheck/aeadInit 与
// sm4.go 的 ivBytes/alignCheck。全部在校验层返回,不触达设备 C 调用。
func TestArgValidation(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}

	t.Run("aead", func(t *testing.T) {
		gcmIV := bytes.Repeat([]byte{1}, 12)

		// 算法:仅 GCM/CCM,其余 SDR_ALGMODNOTSUPPORT。
		if _, _, err := key.AuthEncrypt(SM4_ECB, gcmIV, nil, []byte("x")); !errors.Is(err, SDR_ALGMODNOTSUPPORT) {
			t.Errorf("AuthEncrypt(SM4_ECB) error = %v, want SDR_ALGMODNOTSUPPORT", err)
		}
		// startVar:GCM 1..64,CCM 7..13,越界 SDR_INARGERR。
		if _, _, err := key.AuthEncrypt(SM4_GCM, nil, nil, []byte("x")); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("AuthEncrypt(GCM iv len 0) error = %v, want SDR_INARGERR", err)
		}
		if _, _, err := key.AuthEncrypt(SM4_GCM, make([]byte, 65), nil, []byte("x")); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("AuthEncrypt(GCM iv len 65) error = %v, want SDR_INARGERR", err)
		}
		if _, _, err := key.AuthEncrypt(SM4_CCM, make([]byte, 6), nil, []byte("x")); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("AuthEncrypt(CCM iv len 6) error = %v, want SDR_INARGERR", err)
		}
		if _, _, err := key.AuthEncrypt(SM4_CCM, make([]byte, 14), nil, []byte("x")); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("AuthEncrypt(CCM iv len 14) error = %v, want SDR_INARGERR", err)
		}
		// 解密标签必须 16 字节。
		if _, err := key.AuthDecrypt(SM4_GCM, gcmIV, nil, []byte("ct"), make([]byte, 15)); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("AuthDecrypt(tag len 15) error = %v, want SDR_INARGERR", err)
		}
		// 多步 Init:总量/AAF/标签阈值。
		if _, err := key.NewAuthEncer(SM4_GCM, []byte{1}, nil, -1); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("NewAuthEncer(totalLen=-1) error = %v, want SDR_INARGERR", err)
		}
		if _, err := key.NewAuthEncer(SM4_GCM, gcmIV, nil, 1<<20+1); !errors.Is(err, SDR_NOBUFFER) {
			t.Errorf("NewAuthEncer(totalLen>1MiB) error = %v, want SDR_NOBUFFER", err)
		}
		if _, err := key.NewAuthEncer(SM4_GCM, gcmIV, make([]byte, 257), 16); !errors.Is(err, SDR_NOBUFFER) {
			t.Errorf("NewAuthEncer(aad 257) error = %v, want SDR_NOBUFFER", err)
		}
		if _, err := key.NewAuthDecrypter(SM4_GCM, gcmIV, nil, make([]byte, 15), 16); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("NewAuthDecrypter(tag len 15) error = %v, want SDR_INARGERR", err)
		}
	})

	t.Run("sm4", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x5A}, Sm4BlockSize)

		// IV 非 nil 时长度必须等于分组长度。
		if _, err := key.Encrypt(SM4_CBC, make([]byte, Sm4BlockSize-1), data); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("Encrypt(CBC iv 15) error = %v, want SDR_INARGERR", err)
		}
		// iv==nil 视为全零块(ivBytes 契约),16 字节 CBC 合法 → 成功。
		if _, err := key.Encrypt(SM4_CBC, nil, data); err != nil {
			t.Errorf("Encrypt(CBC nil iv) error = %v, want nil", err)
		}
		// ECB/CBC 单包要求分组整数倍(alignCheck)。
		if _, err := key.Encrypt(SM4_ECB, nil, make([]byte, Sm4BlockSize-1)); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("Encrypt(ECB 15 bytes) error = %v, want SDR_INARGERR", err)
		}
		// 流模式(CTR)任意长度,不要求对齐。
		if _, err := key.Encrypt(SM4_CTR, make([]byte, Sm4BlockSize), make([]byte, 15)); err != nil {
			t.Errorf("Encrypt(CTR 15 bytes) error = %v, want nil", err)
		}
		// MACM3 只接受分组类算法,杂凑标识 SDR_ALGNOTSUPPORT。
		if _, err := key.MACM3(SGD_SM3, nil, data); !errors.Is(err, SDR_ALGNOTSUPPORT) {
			t.Errorf("MACM3(SGD_SM3) error = %v, want SDR_ALGNOTSUPPORT", err)
		}
		// KEK 导入空密文在调用设备前拒绝。
		if _, err := sess.ImportKeyWithKEK(1, SM4_ECB, nil); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("ImportKeyWithKEK(nil) error = %v, want SDR_INARGERR", err)
		}
	})

	t.Run("session", func(t *testing.T) {
		if _, err := sess.GenerateRandom(-1); !errors.Is(err, SDR_INARGERR) {
			t.Errorf("GenerateRandom(-1) error = %v, want SDR_INARGERR", err)
		}
	})
}

// TestMACM3BufferAlias 回归:MACM3 不得改写调用方缓冲(gmsm ISO9797M3 padding
// 对 cap>len 的输入走别名快路径,曾静默清零 data[0:BlockSize()]),
// 且输出必须与对独立拷贝计算的结果一致。
func TestMACM3BufferAlias(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}

	buf := make([]byte, 48)
	for i := range buf {
		buf[i] = byte(i + 1)
	}
	data := buf[:32] // cap 48 > len 32:触发别名快路径的形态
	want := append([]byte(nil), data...)

	mac1, err := key.MACM3(SM4_MAC, nil, data)
	if err != nil {
		t.Fatalf("MACM3: %v", err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("MACM3 mutated caller buffer:\n got %x\nwant %x", data, want)
	}
	mac2, err := key.MACM3(SM4_MAC, nil, append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("MACM3(copy): %v", err)
	}
	if !bytes.Equal(mac1, mac2) {
		t.Fatalf("MACM3 aliased input = %x, want %x", mac1, mac2)
	}
}

// TestStubAgreementOneShot 回归:一步式协商桩按 GM/T 0018 §6.3.16 填充响应方
// 输出槽(sponsor 侧为 [in] 不写),Go 包装必须拿到非零 Bits 的响应方公钥
// (修复前桩写错槽,响应方公钥全零 → pubFromECC 拒绝)。
func TestStubAgreementOneShot(t *testing.T) {
	_, sess := openStub(t)
	sponsorID := []byte("sponsor-id-00001")
	responseID := []byte("response-id-0001")

	_, sponsorPub, sponsorTmp, err := sess.GenerateAgreementDataWithECC(1, 128, sponsorID)
	if err != nil {
		t.Fatalf("GenerateAgreementDataWithECC: %v", err)
	}
	respPub, respTmp, key, err := sess.GenerateAgreementDataAndKeyWithECC(1, 128,
		sponsorID, responseID, sponsorPub, sponsorTmp)
	if err != nil {
		t.Fatalf("GenerateAgreementDataAndKeyWithECC: %v", err)
	}
	defer key.Destroy()
	if respPub == nil || respPub.X == nil || respPub.Y == nil {
		t.Errorf("response long-term pub = %v, want non-nil with coordinates", respPub)
	}
	if respTmp == nil || respTmp.X == nil || respTmp.Y == nil {
		t.Errorf("response tmp pub = %v, want non-nil with coordinates", respTmp)
	}
}

// TestAuthCrypterTotalLen 回归:Update 必须在投递设备前校验累计量,
// 超出 Init 声明的 totalLen 返回 SDR_NOBUFFER 且不改动累计计数。
// 桩缺 AEAD 符号(P3 维持不补),故直接构造已 Init 的句柄钉住投递前检查;
// NewAuthEncer 端到端成功路径见 integration.TestAuthCrypterTotalLen。
func TestAuthCrypterTotalLen(t *testing.T) {
	_, sess := openStub(t)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}

	// 分支 1:累计超量(16 + 1 > 16)。
	enc := &AuthCrypter{k: key, role: cryptEnc, total: 16, acc: 16, started: true}
	if _, err := enc.Update(make([]byte, 1)); !errors.Is(err, SDR_NOBUFFER) {
		t.Errorf("Update(1B after 16/16) error = %v, want SDR_NOBUFFER", err)
	}
	if enc.acc != 16 {
		t.Errorf("acc after rejected Update = %d, want 16", enc.acc)
	}

	// 分支 2:单次超量(0 + 32 > 16)。
	enc2 := &AuthCrypter{k: key, role: cryptEnc, total: 16, started: true}
	if _, err := enc2.Update(make([]byte, 32)); !errors.Is(err, SDR_NOBUFFER) {
		t.Errorf("Update(32B of 16) error = %v, want SDR_NOBUFFER", err)
	}
	if enc2.acc != 0 {
		t.Errorf("acc after rejected Update = %d, want 0", enc2.acc)
	}

	// 构造失败返回的 nil crypter:Update/Final 返回 SDR_STEPERR,不 panic。
	nilEnc, err := key.NewAuthEncer(SM4_ECB, nil, nil, 16) // SM4_ECB 非 AEAD 模式
	if err == nil || nilEnc != nil {
		t.Fatalf("NewAuthEncer(SM4_ECB) = (%v, %v), want (nil, error)", nilEnc, err)
	}
	if _, err := nilEnc.Update(make([]byte, 1)); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("nil crypter Update error = %v, want SDR_STEPERR", err)
	}
	if _, _, err := nilEnc.Final(); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("nil crypter Final error = %v, want SDR_STEPERR", err)
	}
}

// TestGenerateKeyWithKEKRejectsKeyBits 钉住 KEK 生成与 IPK/EPK 相同的
// 64..256 位会话密钥长度契约:越界在调用设备前返回 SDR_INARGERR。
func TestGenerateKeyWithKEKRejectsKeyBits(t *testing.T) {
	_, sess := openStub(t)
	for _, bits := range []uint32{0, 32, 512, 4096} {
		_, key, err := sess.GenerateKeyWithKEK(1, bits, SM4_ECB)
		key.Destroy() // nil 接收者安全
		if !errors.Is(err, SDR_INARGERR) {
			t.Errorf("GenerateKeyWithKEK(keyBits=%d) error = %v, want SDR_INARGERR", bits, err)
		}
	}
	_, key, err := sess.GenerateKeyWithKEK(1, 256, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK(keyBits=256): %v", err)
	}
	if err := key.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}
}

// TestCrypterNilReceiver nil 接收者与 AuthCrypter 保持一致:返回 SDR_STEPERR,
// 不 panic(错误路径可能把 nil crypter 交给调用方)。
func TestCrypterNilReceiver(t *testing.T) {
	var c *Crypter
	if _, err := c.Update(nil); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("nil Crypter Update error = %v, want SDR_STEPERR", err)
	}
	if _, err := c.Final(); !errors.Is(err, SDR_STEPERR) {
		t.Errorf("nil Crypter Final error = %v, want SDR_STEPERR", err)
	}
}

// TestCrypterBufferedFinal 缓冲型设备在 Final 才输出全部密文:Final 必须按
// 已投递总量分配缓冲,48 字节输入不能被 16 字节尾块缓冲截断。
func TestCrypterBufferedFinal(t *testing.T) {
	_, sess := openStubSO(t, stubBufSymSO)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	defer key.Destroy()

	data := make([]byte, 48)
	for i := range data {
		data[i] = byte(i + 1)
	}
	enc, err := key.NewEncrypter(SM4_ECB, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	for _, sp := range [][2]int{{0, 7}, {7, 24}, {24, 48}} {
		part, err := enc.Update(data[sp[0]:sp[1]])
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if len(part) != 0 {
			t.Fatalf("buffered Update returned %d bytes, want 0", len(part))
		}
	}
	ct, err := enc.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	want := make([]byte, len(data))
	for i := range data {
		want[i] = data[i] ^ 0x5A
	}
	if !bytes.Equal(ct, want) {
		t.Fatalf("Final output = %x, want %x", ct, want)
	}
}

// TestAuthCrypterStreamingUpdate 流式设备(Update 直接输出本段密文/明文)上,
// Update 输出必须原样返回,与 Final 尾部拼接后还原输入;不得丢段或越界。
func TestAuthCrypterStreamingUpdate(t *testing.T) {
	_, sess := openStubSO(t, stubAEADSO)
	_, key, err := sess.GenerateKeyWithKEK(1, 128, SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	defer key.Destroy()

	iv := bytes.Repeat([]byte{0x11}, 12)
	pt := []byte("streaming aead payload")
	splits := [][2]int{{0, 4}, {4, 11}, {11, len(pt)}}

	enc, err := key.NewAuthEncer(SM4_GCM, iv, nil, len(pt))
	if err != nil {
		t.Fatalf("NewAuthEncer: %v", err)
	}
	var ct []byte
	for _, sp := range splits {
		part, err := enc.Update(pt[sp[0]:sp[1]])
		if err != nil {
			t.Fatalf("AuthEnc Update: %v", err)
		}
		if len(part) != sp[1]-sp[0] {
			t.Fatalf("AuthEnc Update returned %d bytes, want %d (streaming output dropped)",
				len(part), sp[1]-sp[0])
		}
		ct = append(ct, part...)
	}
	last, tag, err := enc.Final()
	if err != nil {
		t.Fatalf("AuthEnc Final: %v", err)
	}
	ct = append(ct, last...)
	want := make([]byte, len(pt))
	for i := range pt {
		want[i] = pt[i] ^ 0x5A
	}
	if !bytes.Equal(ct, want) {
		t.Fatalf("streaming ciphertext = %x, want %x", ct, want)
	}
	if len(tag) != aeadTagLen {
		t.Fatalf("tag len = %d, want %d", len(tag), aeadTagLen)
	}

	dec, err := key.NewAuthDecrypter(SM4_GCM, iv, nil, tag, len(ct))
	if err != nil {
		t.Fatalf("NewAuthDecrypter: %v", err)
	}
	var back []byte
	for _, sp := range splits {
		part, err := dec.Update(ct[sp[0]:sp[1]])
		if err != nil {
			t.Fatalf("AuthDec Update: %v", err)
		}
		if len(part) != sp[1]-sp[0] {
			t.Fatalf("AuthDec Update returned %d bytes, want %d (streaming output dropped)",
				len(part), sp[1]-sp[0])
		}
		back = append(back, part...)
	}
	tail, authOut, err := dec.Final()
	if err != nil {
		t.Fatalf("AuthDec Final: %v", err)
	}
	back = append(back, tail...)
	if authOut != nil {
		t.Errorf("AuthDec Final auth = %x, want nil", authOut)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("streaming decrypt = %x, want %x", back, pt)
	}
}

// TestProbeSkipMissingSymbols 探测 requires 的 AND 语义:缺 SDF_HMACUpdate/Final
// 的桩变体上 hmac-kat 必须 SKIP(missing symbol),而非 FAIL(SDR_NOTSUPPORT)。
func TestProbeSkipMissingSymbols(t *testing.T) {
	if stubNoHMACSO == "" {
		t.Skip(stubSkipReason)
	}
	// 桩非真设备,KAT 类检查天然 FAIL:忽略整体 error,只看 hmac-kat 单项。
	res, _ := TestDevice(stubNoHMACSO, WithOutput(io.Discard))
	if res == nil {
		t.Fatal("TestDevice returned nil result")
	}
	for _, ck := range res.Checks {
		if ck.Name != "hmac-kat" {
			continue
		}
		if ck.Status != ProbeSkip {
			t.Fatalf("hmac-kat status = %s (%s), want SKIP", ck.Status, ck.Detail)
		}
		return
	}
	t.Fatal("hmac-kat check not found in probe report")
}
