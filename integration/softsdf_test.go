package integration

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"

	"gitee.com/zhujingfeng/gosdf"
)

const (
	testPIN         = "P@ssw0rd"
	keyIndex        = 1
	kekIndex        = 1
	missingKeyIndex = 3
	missingKEKIndex = 99
	defaultSM2UID   = "1234567812345678"
)

var (
	dev     *gosdf.Device
	libPath string
)

// TestMain 引导:定位 testdata 产物、生成密钥文件到临时目录并 chdir
// (SoftSDF 按进程 CWD 相对路径读密钥)、打开全包唯一设备。
func TestMain(m *testing.M) {
	base, err := filepath.Abs("..")
	if err != nil {
		log.Fatalf("abs cwd: %v", err)
	}
	libPath = filepath.Join(base, "testdata", "softsdf", "libsoftsdf.so")
	initPath := filepath.Join(base, "testdata", "softsdf", "softsdfinit")
	for _, p := range []string{libPath, initPath} {
		if _, err := os.Stat(p); err != nil {
			log.Fatalf("missing SoftSDF artifact %s: %v", p, err)
		}
	}
	workDir, err := os.MkdirTemp("", "gosdf-softsdf")
	if err != nil {
		log.Fatalf("MkdirTemp: %v", err)
	}
	for _, idx := range []int{1, 2} {
		cmd := exec.Command(initPath, "-kek", strconv.Itoa(idx),
			"-key", strconv.Itoa(idx), "-pass", testPIN)
		cmd.Dir = workDir
		if out, err := cmd.CombinedOutput(); err != nil {
			os.RemoveAll(workDir)
			log.Fatalf("softsdfinit -key %d: %v\n%s", idx, err, out)
		}
	}
	if err := os.Chdir(workDir); err != nil {
		os.RemoveAll(workDir)
		log.Fatalf("chdir %s: %v", workDir, err)
	}
	dev, err = gosdf.Open(libPath)
	if err != nil {
		os.RemoveAll(workDir)
		log.Fatalf("Open(softsdf): %v", err)
	}
	code := m.Run()
	dev.Close()
	os.RemoveAll(workDir)
	os.Exit(code)
}

// newSession 从当前包级设备开一个会话,测试结束自动关闭。
func newSession(t *testing.T) *gosdf.Session {
	t.Helper()
	s, err := dev.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func acquireRight(t *testing.T, s *gosdf.Session) {
	t.Helper()
	if err := s.AcquireKeyRight(keyIndex, []byte(testPIN)); err != nil {
		t.Fatalf("AcquireKeyRight(%d): %v", keyIndex, err)
	}
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// importKey 导入 n 字节明文会话密钥,测试结束自动销毁。
func importKey(t *testing.T, s *gosdf.Session, n int) (*gosdf.Key, []byte) {
	t.Helper()
	raw := randBytes(t, n)
	key, err := s.ImportKey(raw)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	t.Cleanup(func() { key.Destroy() })
	return key, raw
}

// signPub 导出设备内部签名公钥。
func signPub(t *testing.T, s *gosdf.Session) *ecdsa.PublicKey {
	t.Helper()
	pub, err := s.ExportSignPublicKey(keyIndex)
	if err != nil {
		t.Fatalf("ExportSignPublicKey: %v", err)
	}
	return pub
}

func sm4ECBRef(t *testing.T, key, block []byte) []byte {
	t.Helper()
	blk, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	out := make([]byte, len(block))
	blk.Encrypt(out, block)
	return out
}

func cbcMacRef(t *testing.T, key, iv, data []byte) []byte {
	t.Helper()
	if len(data)%16 != 0 {
		t.Fatalf("test bug: CBC-MAC reference needs aligned data, got %d", len(data))
	}
	blk, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, data)
	return out[len(out)-16:]
}

// ---- A: 设备管理 ----

func TestDeviceInfo(t *testing.T) {
	s := newSession(t)
	info, err := s.GetDeviceInfo()
	if err != nil {
		t.Fatalf("GetDeviceInfo: %v", err)
	}
	if info.IssuerName == "" {
		t.Error("empty IssuerName")
	}
	if info.DeviceName == "" {
		t.Error("empty DeviceName")
	}
	if info.DeviceSerial == "" {
		t.Error("empty DeviceSerial")
	}
	if info.StandardVersion == 0 {
		t.Error("StandardVersion == 0")
	}
	if info.SymAlgAbility&uint32(gosdf.SM4_CBC) != uint32(gosdf.SM4_CBC) {
		t.Errorf("SymAlgAbility %#x lacks SM4", uint32(info.SymAlgAbility))
	}
	if info.HashAlgAbility&uint32(gosdf.SGD_SM3) != uint32(gosdf.SGD_SM3) {
		t.Errorf("HashAlgAbility %#x lacks SM3", uint32(info.HashAlgAbility))
	}
	if info.BufferSize == 0 {
		t.Error("BufferSize == 0")
	}
}

func TestGenerateRandom(t *testing.T) {
	s := newSession(t)
	r1, err := s.GenerateRandom(32)
	if err != nil {
		t.Fatalf("GenerateRandom(32): %v", err)
	}
	if len(r1) != 32 {
		t.Fatalf("len = %d, want 32", len(r1))
	}
	r2, err := s.GenerateRandom(32)
	if err != nil {
		t.Fatalf("GenerateRandom(32) 2nd: %v", err)
	}
	if bytes.Equal(r1, r2) {
		t.Error("two random blocks are equal")
	}
	n0, err := s.GenerateRandom(0)
	if err != nil {
		t.Fatalf("GenerateRandom(0): %v", err)
	}
	if len(n0) != 0 {
		t.Errorf("GenerateRandom(0) = %d bytes, want 0", len(n0))
	}
	buf := make([]byte, 32)
	if n, err := io.ReadFull(s.Random(), buf); err != nil || n != 32 {
		t.Fatalf("Random().Read = (%d, %v), want (32, nil)", n, err)
	}
}

func TestDeviceCloseIdempotent(t *testing.T) {
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	nd, err := gosdf.Open(libPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	dev = nd
	s := newSession(t)
	if _, err := s.GetDeviceInfo(); err != nil {
		t.Fatalf("GetDeviceInfo after reopen: %v", err)
	}
}

func TestSupports(t *testing.T) {
	if !dev.Supports("SDF_HMACInit") {
		t.Error(`Supports("SDF_HMACInit") = false, want true`)
	}
	if dev.Supports("SDF_Nosuch") {
		t.Error(`Supports("SDF_Nosuch") = true, want false`)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if dev.Supports("SDF_HMACInit") {
		t.Error("Supports after Close = true, want false")
	}
	nd, err := gosdf.Open(libPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	dev = nd
}

// ---- B: 杂凑与 HMAC ----

func TestSM3HashKAT(t *testing.T) {
	s := newSession(t)
	h := s.NewHash(gosdf.SGD_SM3)
	if err := h.Update([]byte("abc")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := h.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	want := sm3.Sum([]byte("abc"))
	if !bytes.Equal(got, want[:]) {
		t.Errorf("SM3(abc) = %x, want %x", got, want)
	}
}

func TestHashMultiUpdate(t *testing.T) {
	s := newSession(t)
	parts := []string{"a", "b", "c"}
	h := s.NewHash(gosdf.SGD_SM3)
	for _, p := range parts {
		if err := h.Update([]byte(p)); err != nil {
			t.Fatalf("Update(%q): %v", p, err)
		}
	}
	got, err := h.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	one := s.NewHash(gosdf.SGD_SM3)
	if err := one.Update([]byte("abc")); err != nil {
		t.Fatalf("one-shot Update: %v", err)
	}
	want, err := one.Final()
	if err != nil {
		t.Fatalf("one-shot Final: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("chunked = %x, want %x", got, want)
	}
}

func TestSM2DigestZA(t *testing.T) {
	s := newSession(t)
	pub := signPub(t, s)
	msg := []byte("za digest message")

	// uid 为空按默认 ID
	got, err := s.SM2Digest(pub, nil, msg)
	if err != nil {
		t.Fatalf("SM2Digest(default uid): %v", err)
	}
	za, err := sm2.CalculateZA(pub, []byte(defaultSM2UID))
	if err != nil {
		t.Fatalf("CalculateZA: %v", err)
	}
	want := sm3.Sum(append(append([]byte{}, za...), msg...))
	if !bytes.Equal(got, want[:]) {
		t.Errorf("SM2Digest(default) = %x, want %x", got, want)
	}

	// NewSM2ZAHash 分步路径
	uid := []byte("uid-0123456789")
	h, err := s.NewSM2ZAHash(pub, uid)
	if err != nil {
		t.Fatalf("NewSM2ZAHash: %v", err)
	}
	if err := h.Update(msg); err != nil {
		t.Fatalf("ZA Update: %v", err)
	}
	got2, err := h.Final()
	if err != nil {
		t.Fatalf("ZA Final: %v", err)
	}
	za2, err := sm2.CalculateZA(pub, uid)
	if err != nil {
		t.Fatalf("CalculateZA(uid): %v", err)
	}
	want2 := sm3.Sum(append(append([]byte{}, za2...), msg...))
	if !bytes.Equal(got2, want2[:]) {
		t.Errorf("NewSM2ZAHash = %x, want %x", got2, want2)
	}
}

func TestHashStepErrors(t *testing.T) {
	s := newSession(t)
	h := s.NewHash(gosdf.SGD_SM3)
	if err := h.Update([]byte("x")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := h.Final(); err != nil {
		t.Fatalf("Final: %v", err)
	}
	if err := h.Update([]byte("y")); !errors.Is(err, gosdf.SDR_STEPERR) {
		t.Errorf("Update after Final = %v, want SDR_STEPERR", err)
	}

	// HMAC 类标识不被 NewHash 接受,错误在 Update/Final 浮出
	bad := s.NewHash(gosdf.SGD_SM3_HMAC)
	if err := bad.Update([]byte("x")); !errors.Is(err, gosdf.SDR_ALGNOTSUPPORT) {
		t.Errorf("bad Update = %v, want SDR_ALGNOTSUPPORT", err)
	}
	bad2 := s.NewHash(gosdf.SGD_SM3_HMAC)
	if _, err := bad2.Final(); !errors.Is(err, gosdf.SDR_ALGNOTSUPPORT) {
		t.Errorf("bad Final = %v, want SDR_ALGNOTSUPPORT", err)
	}
}

func TestHMACKAT(t *testing.T) {
	s := newSession(t)
	key, raw := importKey(t, s, 32)
	msg := []byte("abc")

	got, err := key.HMAC(gosdf.SGD_SM3_HMAC, msg)
	if err != nil {
		t.Fatalf("HMAC: %v", err)
	}
	m := hmac.New(sm3.New, raw)
	m.Write(msg)
	want := m.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Errorf("HMAC-SM3 = %x, want %x", got, want)
	}

	// NewHMAC 分块 == 一步式
	h, err := key.NewHMAC(gosdf.SGD_SM3_HMAC)
	if err != nil {
		t.Fatalf("NewHMAC: %v", err)
	}
	if err := h.Update([]byte("a")); err != nil {
		t.Fatalf("HMAC Update: %v", err)
	}
	if err := h.Update([]byte("bc")); err != nil {
		t.Fatalf("HMAC Update: %v", err)
	}
	got2, err := h.Final()
	if err != nil {
		t.Fatalf("HMAC Final: %v", err)
	}
	if !bytes.Equal(got2, want) {
		t.Errorf("chunked HMAC = %x, want %x", got2, want)
	}
}

func TestHMACSHA256(t *testing.T) {
	s := newSession(t)
	key, raw := importKey(t, s, 32)
	msg := []byte("sha256 hmac")

	got, err := key.HMAC(gosdf.SGD_SHA256_HMAC, msg)
	if err != nil {
		t.Fatalf("HMAC(SHA256): %v", err)
	}
	m := hmac.New(sha256.New, raw)
	m.Write(msg)
	want := m.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Errorf("HMAC-SHA256 = %x, want %x", got, want)
	}
}

func TestHMACAlgidRejection(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	if _, err := key.HMAC(gosdf.SGD_SM3, []byte("x")); !errors.Is(err, gosdf.SDR_ALGNOTSUPPORT) {
		t.Errorf("HMAC(SGD_SM3) = %v, want SDR_ALGNOTSUPPORT", err)
	}
	if _, err := key.NewHMAC(gosdf.SGD_SM3); !errors.Is(err, gosdf.SDR_ALGNOTSUPPORT) {
		t.Errorf("NewHMAC(SGD_SM3) = %v, want SDR_ALGNOTSUPPORT", err)
	}
}

func TestSM3HashContract(t *testing.T) {
	h := dev.NewSM3Hash()
	if h.Size() != 32 {
		t.Errorf("Size = %d, want 32", h.Size())
	}
	if h.BlockSize() != 64 {
		t.Errorf("BlockSize = %d, want 64", h.BlockSize())
	}
	if n, err := h.Write([]byte("a")); err != nil || n != 1 {
		t.Fatalf("Write = (%d, %v), want (1, nil)", n, err)
	}
	sum1 := h.Sum(nil)
	sum2 := h.Sum(nil) // Sum 不改状态
	if !bytes.Equal(sum1, sum2) {
		t.Error("Sum is not state-preserving")
	}
	h.Reset()
	if _, err := h.Write([]byte("a")); err != nil {
		t.Fatalf("Write after Reset: %v", err)
	}
	if !bytes.Equal(h.Sum(nil), sum1) {
		t.Error("Reset did not restore state")
	}

	got, err := dev.SM3Sum([]byte("abc"))
	if err != nil {
		t.Fatalf("SM3Sum: %v", err)
	}
	want := sm3.Sum([]byte("abc"))
	if !bytes.Equal(got, want[:]) {
		t.Errorf("SM3Sum(abc) = %x, want %x", got, want)
	}
	// GB/T 32905 示例向量前缀
	if !strings.HasPrefix(hex.EncodeToString(got), "66c7f0f4") {
		t.Errorf("SM3Sum(abc) = %s, want prefix 66c7f0f4", hex.EncodeToString(got))
	}
}

// ---- C: SM2 签名与验签 ----

func TestSignVerifyDigestCross(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	signer, err := s.NewSignerKey(keyIndex)
	if err != nil {
		t.Fatalf("NewSignerKey: %v", err)
	}
	pub := signer.Public().(*ecdsa.PublicKey)

	msg := []byte("digest cross check")
	e := sm3.Sum(msg)
	sig, err := signer.Sign(nil, e[:], nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !sm2.VerifyASN1(pub, e[:], sig) {
		t.Fatal("gmsm VerifyASN1 rejected device signature")
	}

	// gmsm 签名 → 设备验签
	gmsmPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gmsm GenerateKey: %v", err)
	}
	e2 := sm3.Sum([]byte("gmsm signed digest"))
	gsig, err := sm2.SignASN1(rand.Reader, gmsmPriv, e2[:], nil)
	if err != nil {
		t.Fatalf("gmsm SignASN1: %v", err)
	}
	if err := s.VerifySM2Digest(&gmsmPriv.PublicKey, e2[:], gsig); err != nil {
		t.Fatalf("VerifySM2Digest(gmsm sig): %v", err)
	}

	// 设备签名 → 设备内部验签
	if err := s.VerifySM2Internal(keyIndex, e[:], sig); err != nil {
		t.Fatalf("VerifySM2Internal: %v", err)
	}
}

func TestSignerKeyMessage(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	signer, err := s.NewSignerKey(keyIndex)
	if err != nil {
		t.Fatalf("NewSignerKey: %v", err)
	}
	pub := signer.Public().(*ecdsa.PublicKey)
	msg := []byte("signer key message path")
	uid := []byte("uid-0123456789")

	sig, err := signer.Sign(nil, msg, &gosdf.SM2SignerOptions{UID: uid})
	if err != nil {
		t.Fatalf("Sign with SM2SignerOptions: %v", err)
	}
	if !sm2.VerifyASN1WithSM2(pub, uid, msg, sig) {
		t.Fatal("gmsm VerifyASN1WithSM2 rejected device signature")
	}
}

func TestSignerKeyPublic(t *testing.T) {
	s := newSession(t)
	signer, err := s.NewSignerKey(keyIndex)
	if err != nil {
		t.Fatalf("NewSignerKey: %v", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}
	exported := signPub(t, s)
	if pub.X.Cmp(exported.X) != 0 || pub.Y.Cmp(exported.Y) != 0 {
		t.Fatal("SignerKey.Public != ExportSignPublicKey")
	}
	if pub.Curve != exported.Curve {
		t.Fatal("public key curves differ")
	}
}

func TestVerifySM2Message(t *testing.T) {
	s := newSession(t)
	gmsmPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gmsm GenerateKey: %v", err)
	}
	pub := &gmsmPriv.PublicKey
	uid := []byte("uid-0123456789")
	msg := []byte("verified message")

	za, err := sm2.CalculateZA(pub, uid)
	if err != nil {
		t.Fatalf("CalculateZA: %v", err)
	}
	e := sm3.Sum(append(append([]byte{}, za...), msg...))
	sig, err := sm2.SignASN1(rand.Reader, gmsmPriv, e[:], nil)
	if err != nil {
		t.Fatalf("gmsm SignASN1: %v", err)
	}
	if err := s.VerifySM2(pub, uid, msg, sig); err != nil {
		t.Fatalf("VerifySM2: %v", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	signer, err := s.NewSignerKey(keyIndex)
	if err != nil {
		t.Fatalf("NewSignerKey: %v", err)
	}
	pub := signer.Public().(*ecdsa.PublicKey)
	msg := []byte("tamper target")
	e := sm3.Sum(msg)
	sig, err := signer.Sign(nil, e[:], nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	badSig := append([]byte(nil), sig...)
	badSig[len(badSig)-1] ^= 0x01 // 末字节恒为 S 的内容字节(中间字节偶发命中 DER 标签)
	if err := s.VerifySM2Digest(pub, e[:], badSig); !errors.Is(err, gosdf.SDR_VERIFYERR) {
		t.Errorf("tampered sig = %v, want SDR_VERIFYERR", err)
	}

	badDigest := e[:]
	badDigest[0] ^= 0x01
	if err := s.VerifySM2Digest(pub, badDigest, sig); !errors.Is(err, gosdf.SDR_VERIFYERR) {
		t.Errorf("tampered digest = %v, want SDR_VERIFYERR", err)
	}
}

func TestKeyRightErrors(t *testing.T) {
	s := newSession(t)
	err := s.AcquireKeyRight(keyIndex, []byte("wrong-pin"))
	if !errors.Is(err, gosdf.SDR_PRKRERR) {
		t.Errorf("wrong PIN = %v, want SDR_PRKRERR", err)
	}
	err = s.AcquireKeyRight(missingKeyIndex, []byte(testPIN))
	if !errors.Is(err, gosdf.SDR_KEYNOTEXIST) {
		t.Errorf("missing index = %v, want SDR_KEYNOTEXIST", err)
	}

	acquireRight(t, s)
	signer, err := s.NewSignerKey(keyIndex)
	if err != nil {
		t.Fatalf("NewSignerKey: %v", err)
	}
	if err := s.ReleaseKeyRight(keyIndex); err != nil {
		t.Fatalf("ReleaseKeyRight: %v", err)
	}
	e := sm3.Sum([]byte("after release"))
	if _, err := signer.Sign(nil, e[:], nil); !errors.Is(err, gosdf.SDR_PARDENY) {
		t.Errorf("Sign after release = %v, want SDR_PARDENY", err)
	}
}

// ---- D: SM2 加解密、封装与协商 ----

func TestSM2EncryptInterop(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	extPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gmsm GenerateKey: %v", err)
	}
	extPub := &extPriv.PublicKey
	k := randBytes(t, 16)

	// 设备加密 → gmsm 解密
	ct, err := s.SM2Encrypt(extPub, k)
	if err != nil {
		t.Fatalf("SM2Encrypt: %v", err)
	}
	back, err := sm2.Decrypt(extPriv, ct)
	if err != nil {
		t.Fatalf("gmsm Decrypt: %v", err)
	}
	if !bytes.Equal(back, k) {
		t.Errorf("gmsm Decrypt = %x, want %x", back, k)
	}

	// gmsm 加密给设备 enc 公钥 → ImportKeyWithISK
	devEncPub, err := s.ExportEncPublicKey(keyIndex)
	if err != nil {
		t.Fatalf("ExportEncPublicKey: %v", err)
	}
	der, err := sm2.EncryptASN1(rand.Reader, devEncPub, k)
	if err != nil {
		t.Fatalf("gmsm EncryptASN1: %v", err)
	}
	key, err := s.ImportKeyWithISK(keyIndex, der)
	if err != nil {
		t.Fatalf("ImportKeyWithISK: %v", err)
	}
	defer key.Destroy()

	block := randBytes(t, 16)
	got, err := key.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key.Encrypt: %v", err)
	}
	if want := sm4ECBRef(t, k, block); !bytes.Equal(got, want) {
		t.Errorf("SM4(imported K) = %x, want %x", got, want)
	}
}

func TestIPKISKRoundTrip(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	wrapped, key1, err := s.GenerateKeyWithIPK(keyIndex, 128)
	if err != nil {
		t.Fatalf("GenerateKeyWithIPK: %v", err)
	}
	defer key1.Destroy()
	key2, err := s.ImportKeyWithISK(keyIndex, wrapped)
	if err != nil {
		t.Fatalf("ImportKeyWithISK: %v", err)
	}
	defer key2.Destroy()

	block := randBytes(t, 16)
	ct1, err := key1.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key1.Encrypt: %v", err)
	}
	ct2, err := key2.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key2.Encrypt: %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("IPK-wrapped and ISK-imported keys differ")
	}
}

func TestGenerateKeyPairECC(t *testing.T) {
	s := newSession(t)
	priv, err := s.GenerateKeyPairECC(gosdf.SGD_SM2_1, 256)
	if err != nil {
		t.Fatalf("GenerateKeyPairECC: %v", err)
	}
	if priv.D == nil || priv.D.Sign() <= 0 {
		t.Fatal("private D not positive")
	}
	if priv.D.Cmp(priv.Params().N) >= 0 {
		t.Fatal("private D not in [1, n-1]")
	}
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
		t.Fatal("public key not on curve")
	}
	// D↔公钥绑定:公钥必须等于 D·G(设备返回互不匹配的 D 与公钥则私钥不可用)
	x, y := priv.Params().ScalarBaseMult(priv.D.Bytes())
	if x.Cmp(priv.X) != 0 || y.Cmp(priv.Y) != 0 {
		t.Fatal("public key != D·G: key pair components do not match")
	}
}

func TestExchangeEnvelopeECC(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	extPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gmsm GenerateKey: %v", err)
	}
	extPub := &extPriv.PublicKey
	block := randBytes(t, 16)

	// GenerateKeyWithEPK:外部公钥封装 → gmsm 解封 → 句柄输出 == SM4(K)
	wrapped, key1, err := s.GenerateKeyWithEPK(128, extPub)
	if err != nil {
		t.Fatalf("GenerateKeyWithEPK: %v", err)
	}
	defer key1.Destroy()
	k1, err := sm2.Decrypt(extPriv, wrapped)
	if err != nil {
		t.Fatalf("gmsm Decrypt(wrapped): %v", err)
	}
	ct1, err := key1.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key1.Encrypt: %v", err)
	}
	if want := sm4ECBRef(t, k1, block); !bytes.Equal(ct1, want) {
		t.Errorf("SM4(K) = %x, want %x", ct1, want)
	}

	// GM/T 0018-2012 6.3.17:输入信封须为内部公钥加密,输出为外部公钥加密
	wrappedIPK, keyIPK, err := s.GenerateKeyWithIPK(keyIndex, 128)
	if err != nil {
		t.Fatalf("GenerateKeyWithIPK: %v", err)
	}
	defer keyIPK.Destroy()
	converted, err := s.ExchangeEnvelopeECC(keyIndex, gosdf.SGD_SM2_3, extPub, wrappedIPK)
	if err != nil {
		t.Fatalf("ExchangeEnvelopeECC: %v", err)
	}
	k2, err := sm2.Decrypt(extPriv, converted)
	if err != nil {
		t.Fatalf("gmsm Decrypt(converted): %v", err)
	}
	ctIPK, err := keyIPK.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("keyIPK.Encrypt: %v", err)
	}
	if want := sm4ECBRef(t, k2, block); !bytes.Equal(ctIPK, want) {
		t.Errorf("converted SM4(K) = %x, want %x", ctIPK, want)
	}

	// ImportKeyWithISK 导入内部封装:与 IPK 句柄同密钥
	key2, err := s.ImportKeyWithISK(keyIndex, wrappedIPK)
	if err != nil {
		t.Fatalf("ImportKeyWithISK: %v", err)
	}
	defer key2.Destroy()
	ct2, err := key2.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key2.Encrypt: %v", err)
	}
	if !bytes.Equal(ct2, ctIPK) {
		t.Fatal("IPK-wrapped and ISK-imported keys differ")
	}
}

func TestKeyAgreement(t *testing.T) {
	sA := newSession(t)
	sB := newSession(t)
	acquireRight(t, sA)
	acquireRight(t, sB)

	sponsorID := []byte("sponsor-id-00001")
	responseID := []byte("response-id-0001")

	ah, sponsorPub, sponsorTmp, err := sA.GenerateAgreementDataWithECC(keyIndex, 128, sponsorID)
	if err != nil {
		t.Fatalf("GenerateAgreementDataWithECC: %v", err)
	}
	respPub, respTmp, keyB, err := sB.GenerateAgreementDataAndKeyWithECC(keyIndex, 128,
		sponsorID, responseID, sponsorPub, sponsorTmp)
	if err != nil {
		t.Fatalf("GenerateAgreementDataAndKeyWithECC: %v", err)
	}
	defer keyB.Destroy()
	keyA, err := sA.GenerateKeyWithECC(ah, responseID, respPub, respTmp)
	if err != nil {
		t.Fatalf("GenerateKeyWithECC: %v", err)
	}
	defer keyA.Destroy()

	block := randBytes(t, 16)
	ctA, err := keyA.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("keyA.Encrypt: %v", err)
	}
	ctB, err := keyB.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("keyB.Encrypt: %v", err)
	}
	if !bytes.Equal(ctA, ctB) {
		t.Errorf("agreed keys differ: A=%x B=%x", ctA, ctB)
	}
}

// ---- E: RSA ----

func TestExportPublicKeyRSA(t *testing.T) {
	s := newSession(t)
	pub, err := s.ExportSignPublicKeyRSA(keyIndex)
	if err != nil {
		t.Fatalf("ExportSignPublicKeyRSA: %v", err)
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("sign N bits = %d, want 2048", pub.N.BitLen())
	}
	if pub.E != 65537 {
		t.Errorf("sign E = %d, want 65537", pub.E)
	}
	if pub.N.Bit(0) != 1 {
		t.Error("sign N is even")
	}

	encPub, err := s.ExportEncPublicKeyRSA(keyIndex)
	if err != nil {
		t.Fatalf("ExportEncPublicKeyRSA: %v", err)
	}
	if encPub.N.BitLen() != 2048 {
		t.Errorf("enc N bits = %d, want 2048", encPub.N.BitLen())
	}
	if encPub.E != 65537 {
		t.Errorf("enc E = %d, want 65537", encPub.E)
	}

	if _, err := s.ExportSignPublicKeyRSA(missingKeyIndex); !errors.Is(err, gosdf.SDR_KEYNOTEXIST) {
		t.Errorf("export missing = %v, want SDR_KEYNOTEXIST", err)
	}
}

func TestGenerateKeyPairRSA(t *testing.T) {
	s := newSession(t)
	priv, err := s.GenerateKeyPairRSA(1024)
	if err != nil {
		t.Fatalf("GenerateKeyPairRSA(1024): %v", err)
	}
	if err := priv.Validate(); err != nil {
		t.Fatalf("priv.Validate: %v", err)
	}
	if priv.E != 65537 {
		t.Errorf("E = %d, want 65537", priv.E)
	}
	if priv.N.BitLen() != 1024 {
		t.Errorf("N bits = %d, want 1024", priv.N.BitLen())
	}
}

func TestRSAWrapInterop(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	block := randBytes(t, 16)

	// EPK → stdlib PKCS1 解封 → SM4(K) 与句柄输出一致
	extPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	wrapped, key1, err := s.GenerateKeyWithEPKRSA(128, &extPriv.PublicKey)
	if err != nil {
		t.Fatalf("GenerateKeyWithEPKRSA: %v", err)
	}
	defer key1.Destroy()
	k, err := rsa.DecryptPKCS1v15(rand.Reader, extPriv, wrapped)
	if err != nil {
		t.Fatalf("rsa.DecryptPKCS1v15: %v", err)
	}
	if len(k) != 16 {
		t.Fatalf("unwrapped K = %d bytes, want 16", len(k))
	}
	got, err := key1.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key1.Encrypt: %v", err)
	}
	if want := sm4ECBRef(t, k, block); !bytes.Equal(got, want) {
		t.Errorf("SM4(K) = %x, want %x", got, want)
	}

	// IPK → ISK 往返
	wrapped1, key2, err := s.GenerateKeyWithIPKRSA(keyIndex, 128)
	if err != nil {
		t.Fatalf("GenerateKeyWithIPKRSA: %v", err)
	}
	defer key2.Destroy()
	key3, err := s.ImportKeyWithISKRSA(keyIndex, wrapped1)
	if err != nil {
		t.Fatalf("ImportKeyWithISKRSA: %v", err)
	}
	defer key3.Destroy()
	ct2, err := key2.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key2.Encrypt: %v", err)
	}
	ct3, err := key3.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key3.Encrypt: %v", err)
	}
	if !bytes.Equal(ct2, ct3) {
		t.Fatal("IPK/ISK RSA round trip keys differ")
	}
}

func TestExchangeEnvelopeRSA(t *testing.T) {
	s := newSession(t)
	acquireRight(t, s)
	block := randBytes(t, 16)

	extPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	wrapped1, key1, err := s.GenerateKeyWithIPKRSA(keyIndex, 128)
	if err != nil {
		t.Fatalf("GenerateKeyWithIPKRSA: %v", err)
	}
	defer key1.Destroy()

	converted, err := s.ExchangeEnvelopeRSA(keyIndex, &extPriv.PublicKey, wrapped1)
	if err != nil {
		t.Fatalf("ExchangeEnvelopeRSA: %v", err)
	}
	extK, err := rsa.DecryptPKCS1v15(rand.Reader, extPriv, converted)
	if err != nil {
		t.Fatalf("rsa.DecryptPKCS1v15(converted): %v", err)
	}
	if len(extK) != 16 {
		t.Fatalf("converted K = %d bytes, want 16", len(extK))
	}
	got, err := key1.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key1.Encrypt: %v", err)
	}
	if want := sm4ECBRef(t, extK, block); !bytes.Equal(got, want) {
		t.Errorf("SM4(exchanged K) = %x, want %x", got, want)
	}
}

// ---- F: 对称与 AEAD ----

func TestSM4KAT(t *testing.T) {
	s := newSession(t)
	// ALGID.BlockSize 契约:分组算法 16,流式 AEAD/杂凑 0
	if gosdf.SM4_CBC.BlockSize() != 16 || gosdf.SM4_MAC.BlockSize() != 16 {
		t.Errorf("BlockSize(SM4) = %d/%d, want 16/16",
			gosdf.SM4_CBC.BlockSize(), gosdf.SM4_MAC.BlockSize())
	}
	if gosdf.SM4_GCM.BlockSize() != 0 || gosdf.SGD_SM3.BlockSize() != 0 {
		t.Errorf("BlockSize(GCM/SM3) = %d/%d, want 0/0",
			gosdf.SM4_GCM.BlockSize(), gosdf.SGD_SM3.BlockSize())
	}
	keyBytes, err := hex.DecodeString("0123456789abcdeffedcba9876543210")
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	plain, err := hex.DecodeString("0123456789abcdeffedcba9876543210")
	if err != nil {
		t.Fatalf("decode plain: %v", err)
	}
	want, err := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	key, err := s.ImportKey(keyBytes)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	defer key.Destroy()

	ct, err := key.Encrypt(gosdf.SM4_ECB, nil, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(ct, want) {
		t.Errorf("SM4 ECB KAT cipher = %x, want %x", ct, want)
	}
	back, err := key.Decrypt(gosdf.SM4_ECB, nil, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Errorf("SM4 ECB KAT round trip = %x, want %x", back, plain)
	}
}

func TestSM4CBCCross(t *testing.T) {
	s := newSession(t)
	key, raw := importKey(t, s, 16)
	iv := randBytes(t, 16)
	data := randBytes(t, 48)

	ct, err := key.Encrypt(gosdf.SM4_CBC, iv, data)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blk, err := sm4.NewCipher(raw)
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	ref := make([]byte, len(data))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ref, data)
	if !bytes.Equal(ct, ref) {
		t.Fatalf("device CBC != stdlib cipher:\n got %x\nwant %x", ct, ref)
	}
	back, err := key.Decrypt(gosdf.SM4_CBC, iv, ref)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(back, data) {
		t.Fatalf("CBC decrypt mismatch:\n got %x\nwant %x", back, data)
	}
}

func TestSM4StreamModes(t *testing.T) {
	s := newSession(t)
	key, raw := importKey(t, s, 16)
	iv := randBytes(t, 16)
	data := randBytes(t, 30)

	blk, err := sm4.NewCipher(raw)
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	// 与 stdlib 流模式逐字节对比:仅往返无法区分"错误但可逆"的模式实现
	for _, tc := range []struct {
		alg gosdf.ALGID
		ref func(dst, src []byte)
	}{
		{gosdf.SM4_CFB, func(dst, src []byte) { cipher.NewCFBEncrypter(blk, iv).XORKeyStream(dst, src) }},
		{gosdf.SM4_OFB, func(dst, src []byte) { cipher.NewOFB(blk, iv).XORKeyStream(dst, src) }},
		{gosdf.SM4_CTR, func(dst, src []byte) { cipher.NewCTR(blk, iv).XORKeyStream(dst, src) }},
	} {
		ct, err := key.Encrypt(tc.alg, iv, data)
		if err != nil {
			t.Fatalf("Encrypt(%#x): %v", uint32(tc.alg), err)
		}
		if len(ct) != len(data) {
			t.Fatalf("Encrypt(%#x) len = %d, want %d", uint32(tc.alg), len(ct), len(data))
		}
		want := make([]byte, len(data))
		tc.ref(want, data)
		if !bytes.Equal(ct, want) {
			t.Fatalf("Encrypt(%#x) != stdlib:\n got %x\nwant %x", uint32(tc.alg), ct, want)
		}
		back, err := key.Decrypt(tc.alg, iv, ct)
		if err != nil {
			t.Fatalf("Decrypt(%#x): %v", uint32(tc.alg), err)
		}
		if !bytes.Equal(back, data) {
			t.Fatalf("round trip mismatch for %#x:\n got %x\nwant %x", uint32(tc.alg), back, data)
		}
	}
}

func TestPKCS7(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	iv := randBytes(t, 16)

	for _, plain := range [][]byte{
		[]byte("non-block-aligned plaintext!"),
		bytes.Repeat([]byte{0xAA}, 32), // 整分组也补全块
	} {
		ct, err := key.EncryptPKCS7(gosdf.SM4_CBC, iv, plain)
		if err != nil {
			t.Fatalf("EncryptPKCS7: %v", err)
		}
		if len(ct)%16 != 0 {
			t.Fatalf("ciphertext len %d not aligned", len(ct))
		}
		back, err := key.DecryptPKCS7(gosdf.SM4_CBC, iv, ct)
		if err != nil {
			t.Fatalf("DecryptPKCS7: %v", err)
		}
		if !bytes.Equal(back, plain) {
			t.Errorf("PKCS7 round trip = %x, want %x", back, plain)
		}
	}

	// 坏填充 → error。用固定密钥构造确定性非法填充(末字节 0x00),
	// 避免随机密钥下约 1/255 概率解出合法 PKCS7 填充造成假失败。
	raw := bytes.Repeat([]byte{0x11}, 16)
	fixed, err := s.ImportKey(raw)
	if err != nil {
		t.Fatalf("ImportKey(fixed): %v", err)
	}
	t.Cleanup(func() { fixed.Destroy() })
	badPlain := make([]byte, 16)
	badPlain[15] = 0x00
	blk, err := sm4.NewCipher(raw)
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	badCT := make([]byte, 16)
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(badCT, badPlain)
	if _, err := fixed.DecryptPKCS7(gosdf.SM4_CBC, iv, badCT); err == nil {
		t.Fatal("DecryptPKCS7 with invalid padding returned nil")
	}
}

func TestMAC(t *testing.T) {
	s := newSession(t)
	key, raw := importKey(t, s, 16)
	iv := randBytes(t, 16)
	data := randBytes(t, 32)

	mac, err := key.MAC(gosdf.SM4_MAC, iv, data)
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if want := cbcMacRef(t, raw, iv, data); !bytes.Equal(mac, want) {
		t.Errorf("MAC = %x, want CBC last block %x", mac, want)
	}

	// MACM3 == ISO9797-M3 填充后 CBC-MAC
	mac3, err := key.MACM3(gosdf.SM4_MAC, iv, data)
	if err != nil {
		t.Fatalf("MACM3: %v", err)
	}
	padded := padding.NewISO9797M3Padding(16).Pad(data)
	if want := cbcMacRef(t, raw, iv, padded); !bytes.Equal(mac3, want) {
		t.Errorf("MACM3 = %x, want %x", mac3, want)
	}
}

func TestMultiPart(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	iv := randBytes(t, 16)
	data := randBytes(t, 48)

	// CBC:三块不等长 Update + Final == 一步式
	one, err := key.Encrypt(gosdf.SM4_CBC, iv, data)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	enc, err := key.NewEncrypter(gosdf.SM4_CBC, iv)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	var got []byte
	for _, sp := range [][2]int{{0, 7}, {7, 24}, {24, 48}} {
		part, err := enc.Update(data[sp[0]:sp[1]])
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		got = append(got, part...)
	}
	tail, err := enc.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	got = append(got, tail...)
	if !bytes.Equal(got, one) {
		t.Fatalf("multi-part != one-shot:\n got %x\nwant %x", got, one)
	}

	// 解密侧还原
	dec, err := key.NewDecrypter(gosdf.SM4_CBC, iv)
	if err != nil {
		t.Fatalf("NewDecrypter: %v", err)
	}
	var plain []byte
	for _, sp := range [][2]int{{0, 10}, {10, 16}, {16, 48}} {
		part, err := dec.Update(one[sp[0]:sp[1]])
		if err != nil {
			t.Fatalf("dec Update: %v", err)
		}
		plain = append(plain, part...)
	}
	tail, err = dec.Final()
	if err != nil {
		t.Fatalf("dec Final: %v", err)
	}
	plain = append(plain, tail...)
	if !bytes.Equal(plain, data) {
		t.Fatalf("multi-part decrypt = %x, want %x", plain, data)
	}

	// NewMAC 分块 == 一步式 MAC
	wantMAC, err := key.MAC(gosdf.SM4_MAC, iv, data)
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	mc, err := key.NewMAC(gosdf.SM4_MAC, iv)
	if err != nil {
		t.Fatalf("NewMAC: %v", err)
	}
	for _, sp := range [][2]int{{0, 7}, {7, 24}, {24, 48}} {
		if _, err := mc.Update(data[sp[0]:sp[1]]); err != nil {
			t.Fatalf("MAC Update: %v", err)
		}
	}
	gotMAC, err := mc.Final()
	if err != nil {
		t.Fatalf("MAC Final: %v", err)
	}
	if !bytes.Equal(gotMAC, wantMAC) {
		t.Errorf("multi-part MAC = %x, want %x", gotMAC, wantMAC)
	}
}

func TestCrypterStepErrors(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	iv := randBytes(t, 16)
	data := randBytes(t, 16)

	c, err := key.NewEncrypter(gosdf.SM4_CBC, iv)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	if _, err := c.Update(data); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := c.Final(); err != nil {
		t.Fatalf("Final: %v", err)
	}
	if _, err := c.Final(); !errors.Is(err, gosdf.SDR_STEPERR) {
		t.Errorf("second Final = %v, want SDR_STEPERR", err)
	}
	if _, err := c.Update(data); !errors.Is(err, gosdf.SDR_STEPERR) {
		t.Errorf("Update after Final = %v, want SDR_STEPERR", err)
	}
}

func TestKeyBlock(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	block := randBytes(t, 16)

	blk, err := key.Block(gosdf.SM4_ECB)
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	if blk.BlockSize() != 16 {
		t.Fatalf("Block.BlockSize = %d, want 16", blk.BlockSize())
	}
	out := make([]byte, 16)
	blk.Encrypt(out, block)
	want, err := key.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("Block.Encrypt = %x, want %x", out, want)
	}
	dec := make([]byte, 16)
	blk.Decrypt(dec, out)
	if !bytes.Equal(dec, block) {
		t.Fatalf("Block.Decrypt = %x, want %x", dec, block)
	}

	// 就地重叠(dst == src)安全
	buf := append([]byte(nil), block...)
	blk.Encrypt(buf, buf)
	if !bytes.Equal(buf, want) {
		t.Fatalf("in-place Block.Encrypt = %x, want %x", buf, want)
	}
}

func TestImportKey(t *testing.T) {
	s := newSession(t)
	key, raw := importKey(t, s, 16)
	block := randBytes(t, 16)

	got, err := key.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if want := sm4ECBRef(t, raw, block); !bytes.Equal(got, want) {
		t.Errorf("SM4(imported) = %x, want %x", got, want)
	}

	if _, err := s.ImportKey(nil); !errors.Is(err, gosdf.SDR_INARGERR) {
		t.Errorf("ImportKey(nil) = %v, want SDR_INARGERR", err)
	}
	if _, err := s.ImportKey(make([]byte, 65)); !errors.Is(err, gosdf.SDR_INARGERR) {
		t.Errorf("ImportKey(65) = %v, want SDR_INARGERR", err)
	}
}

func TestKEK(t *testing.T) {
	s := newSession(t)
	wrapped, key1, err := s.GenerateKeyWithKEK(kekIndex, 128, gosdf.SM4_ECB)
	if err != nil {
		t.Fatalf("GenerateKeyWithKEK: %v", err)
	}
	defer key1.Destroy()
	key2, err := s.ImportKeyWithKEK(kekIndex, gosdf.SM4_ECB, wrapped)
	if err != nil {
		t.Fatalf("ImportKeyWithKEK: %v", err)
	}
	defer key2.Destroy()

	block := randBytes(t, 16)
	ct1, err := key1.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key1.Encrypt: %v", err)
	}
	ct2, err := key2.Encrypt(gosdf.SM4_ECB, nil, block)
	if err != nil {
		t.Fatalf("key2.Encrypt: %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("KEK generate/import keys differ")
	}
	if _, _, err := s.GenerateKeyWithKEK(missingKEKIndex, 128, gosdf.SM4_ECB); !errors.Is(err, gosdf.SDR_KEYNOTEXIST) {
		t.Errorf("missing KEK = %v, want SDR_KEYNOTEXIST", err)
	}
}

func TestKeyDestroy(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	if err := key.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := key.Destroy(); err != nil {
		t.Fatalf("second Destroy: %v", err)
	}
	if _, err := key.Encrypt(gosdf.SM4_ECB, nil, make([]byte, 16)); err == nil {
		t.Fatal("Encrypt after Destroy returned nil")
	}
}

func TestIVUnchanged(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	iv := randBytes(t, 16)
	orig := append([]byte(nil), iv...)
	data := randBytes(t, 32)

	if _, err := key.Encrypt(gosdf.SM4_CBC, iv, data); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(iv, orig) {
		t.Fatal("Encrypt mutated IV")
	}
	ct, err := key.Encrypt(gosdf.SM4_CBC, iv, data)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := key.Decrypt(gosdf.SM4_CBC, iv, ct); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(iv, orig) {
		t.Fatal("Decrypt mutated IV")
	}
	if _, err := key.MAC(gosdf.SM4_MAC, iv, data); err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if !bytes.Equal(iv, orig) {
		t.Fatal("MAC mutated IV")
	}
}

func TestAuthEncGCM(t *testing.T) {
	s := newSession(t)
	key, raw := importKey(t, s, 16)
	iv := randBytes(t, 12)
	aad := randBytes(t, 13)
	pt := randBytes(t, 42)

	ct, tag, err := key.AuthEncrypt(gosdf.SM4_GCM, iv, aad, pt)
	if err != nil {
		t.Fatalf("AuthEncrypt: %v", err)
	}
	if len(tag) != 16 {
		t.Fatalf("tag len = %d, want 16", len(tag))
	}
	blk, err := sm4.NewCipher(raw)
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	ref := gcm.Seal(nil, iv, pt, aad)
	refCT, refTag := ref[:len(pt)], ref[len(pt):]
	if !bytes.Equal(ct, refCT) {
		t.Fatalf("GCM ct != stdlib:\n got %x\nwant %x", ct, refCT)
	}
	if !bytes.Equal(tag, refTag) {
		t.Fatalf("GCM tag = %x, want %x", tag, refTag)
	}

	back, err := key.AuthDecrypt(gosdf.SM4_GCM, iv, aad, ct, tag)
	if err != nil {
		t.Fatalf("AuthDecrypt: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("AuthDecrypt = %x, want %x", back, pt)
	}

	badTag := append([]byte(nil), tag...)
	badTag[0] ^= 0x01
	if _, err := key.AuthDecrypt(gosdf.SM4_GCM, iv, aad, ct, badTag); !errors.Is(err, gosdf.SDR_VERIFYERR) {
		t.Errorf("tampered tag = %v, want SDR_VERIFYERR", err)
	}
}

func TestAuthEncCCM(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	iv := randBytes(t, 9)
	aad := randBytes(t, 7)
	pt := randBytes(t, 42)

	ct, tag, err := key.AuthEncrypt(gosdf.SM4_CCM, iv, aad, pt)
	if err != nil {
		t.Fatalf("AuthEncrypt(CCM): %v", err)
	}
	if len(tag) != 16 {
		t.Fatalf("tag len = %d, want 16", len(tag))
	}
	back, err := key.AuthDecrypt(gosdf.SM4_CCM, iv, aad, ct, tag)
	if err != nil {
		t.Fatalf("AuthDecrypt(CCM): %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("CCM round trip = %x, want %x", back, pt)
	}

	badAAD := append([]byte(nil), aad...)
	badAAD[0] ^= 0x01
	if _, err := key.AuthDecrypt(gosdf.SM4_CCM, iv, badAAD, ct, tag); !errors.Is(err, gosdf.SDR_VERIFYERR) {
		t.Errorf("tampered aad = %v, want SDR_VERIFYERR", err)
	}
}

func TestAuthEncMultiPart(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	iv := randBytes(t, 12)
	aad := randBytes(t, 13)
	pt := randBytes(t, 42)
	splits := [][2]int{{0, 7}, {7, 27}, {27, 42}}

	// 多步 GCM == 一步式
	enc, err := key.NewAuthEncer(gosdf.SM4_GCM, iv, aad, len(pt))
	if err != nil {
		t.Fatalf("NewAuthEncer: %v", err)
	}
	for _, sp := range splits {
		part, err := enc.Update(pt[sp[0]:sp[1]])
		if err != nil {
			t.Fatalf("AuthEnc Update: %v", err)
		}
		if len(part) != 0 {
			t.Fatalf("buffered Update returned %d bytes, want 0", len(part))
		}
	}
	last, tag, err := enc.Final()
	if err != nil {
		t.Fatalf("AuthEnc Final: %v", err)
	}
	oneCT, oneTag, err := key.AuthEncrypt(gosdf.SM4_GCM, iv, aad, pt)
	if err != nil {
		t.Fatalf("AuthEncrypt: %v", err)
	}
	if !bytes.Equal(last, oneCT) || !bytes.Equal(tag, oneTag) {
		t.Fatal("multi-part GCM != one-shot")
	}
	if _, _, err := enc.Final(); !errors.Is(err, gosdf.SDR_STEPERR) {
		t.Errorf("double Final = %v, want SDR_STEPERR", err)
	}

	// 多步解密还原
	dec, err := key.NewAuthDecrypter(gosdf.SM4_GCM, iv, aad, tag, len(oneCT))
	if err != nil {
		t.Fatalf("NewAuthDecrypter: %v", err)
	}
	for _, sp := range [][2]int{{0, 7}, {7, 27}, {27, 42}} {
		part, err := dec.Update(oneCT[sp[0]:sp[1]])
		if err != nil {
			t.Fatalf("AuthDec Update: %v", err)
		}
		if len(part) != 0 {
			t.Fatalf("buffered decrypt Update returned %d bytes, want 0", len(part))
		}
	}
	plain, authOut, err := dec.Final()
	if err != nil {
		t.Fatalf("AuthDec Final: %v", err)
	}
	if authOut != nil {
		t.Error("decrypt Final returned auth data, want nil")
	}
	if !bytes.Equal(plain, pt) {
		t.Fatalf("multi-part decrypt = %x, want %x", plain, pt)
	}

	// CCM 多步 == 一步式
	iv9 := randBytes(t, 9)
	ccmCT, ccmTag, err := key.AuthEncrypt(gosdf.SM4_CCM, iv9, aad, pt)
	if err != nil {
		t.Fatalf("AuthEncrypt(CCM): %v", err)
	}
	enc2, err := key.NewAuthEncer(gosdf.SM4_CCM, iv9, aad, len(pt))
	if err != nil {
		t.Fatalf("NewAuthEncer(CCM): %v", err)
	}
	for _, sp := range splits {
		if _, err := enc2.Update(pt[sp[0]:sp[1]]); err != nil {
			t.Fatalf("CCM Update: %v", err)
		}
	}
	last2, tag2, err := enc2.Final()
	if err != nil {
		t.Fatalf("CCM Final: %v", err)
	}
	if !bytes.Equal(last2, ccmCT) || !bytes.Equal(tag2, ccmTag) {
		t.Fatal("multi-part CCM != one-shot")
	}
}

// TestAuthCrypterTotalLen 回归:Update 累计超出 Init 声明的 totalLen 必须返回
// SDR_NOBUFFER(超量字节不投递设备),且拒绝后 Final 仍按已投递量正常收尾。
func TestAuthCrypterTotalLen(t *testing.T) {
	s := newSession(t)
	key, _ := importKey(t, s, 16)
	iv := randBytes(t, 12)

	// 分支 1:累计超量(16 + 1 > 16),已投递的 16 字节仍正常输出。
	enc, err := key.NewAuthEncer(gosdf.SM4_GCM, iv, nil, 16)
	if err != nil {
		t.Fatalf("NewAuthEncer: %v", err)
	}
	if _, err := enc.Update(make([]byte, 16)); err != nil {
		t.Fatalf("Update(16B): %v", err)
	}
	if _, err := enc.Update(make([]byte, 1)); !errors.Is(err, gosdf.SDR_NOBUFFER) {
		t.Errorf("Update(1B after 16/16) = %v, want SDR_NOBUFFER", err)
	}
	ct, tag, err := enc.Final()
	if err != nil {
		t.Fatalf("Final: %v", err)
	}
	if len(ct) != 16 || len(tag) != 16 {
		t.Errorf("Final output = (%d bytes, tag %d), want (16, 16)", len(ct), len(tag))
	}

	// 分支 2:单次超量(0 + 32 > 16),无字节投递 → 密文 0 字节、标签正常。
	enc2, err := key.NewAuthEncer(gosdf.SM4_GCM, iv, nil, 16)
	if err != nil {
		t.Fatalf("NewAuthEncer(2): %v", err)
	}
	if _, err := enc2.Update(make([]byte, 32)); !errors.Is(err, gosdf.SDR_NOBUFFER) {
		t.Errorf("Update(32B of 16) = %v, want SDR_NOBUFFER", err)
	}
	ct2, tag2, err := enc2.Final()
	if err != nil {
		t.Fatalf("Final(2): %v", err)
	}
	if len(ct2) != 0 || len(tag2) != 16 {
		t.Errorf("Final output = (%d bytes, tag %d), want (0, 16)", len(ct2), len(tag2))
	}
}

// TestProbeSoftSDF 覆盖 probe API(TestDevice):软模拟器冒烟必须 0 FAIL。
// SoftSDF 全局单设备(二次 OpenDevice 返回 SDR_OPENDEVICE),先关闭包级设备
// 让 TestDevice 自己打开,结束后重开供后续测试使用。
func TestProbeSoftSDF(t *testing.T) {
	if err := dev.Close(); err != nil {
		t.Fatalf("Close(package dev): %v", err)
	}
	defer func() {
		d, err := gosdf.Open(libPath)
		if err != nil {
			t.Errorf("reopen device after probe: %v", err)
			return
		}
		dev = d
	}()

	res, err := gosdf.TestDevice(libPath, gosdf.WithPIN([]byte(testPIN)),
		gosdf.WithOutput(io.Discard))
	if err != nil {
		t.Fatalf("TestDevice: %v", err)
	}
	var fails []string
	for _, ck := range res.Checks {
		if ck.Status == gosdf.ProbeFail {
			fails = append(fails, ck.Name+": "+ck.Detail)
		}
	}
	if len(fails) != 0 {
		t.Errorf("probe FAIL checks: %s", strings.Join(fails, "; "))
	}
}

// ---- G: 文件操作 ----

func TestFileRoundTrip(t *testing.T) {
	s := newSession(t)
	const name = "foo.dat"
	data := randBytes(t, 32)

	if err := s.CreateFile(name, 64); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := s.WriteFile(name, 0, data); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := s.ReadFile(name, 0, 32)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("ReadFile = %x, want %x", got, data)
	}
	if err := s.DeleteFile(name); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if _, err := s.ReadFile(name, 0, 32); !errors.Is(err, gosdf.SDR_FILENOEXIST) {
		t.Errorf("read after delete = %v, want SDR_FILENOEXIST", err)
	}
}

func TestFileErrors(t *testing.T) {
	s := newSession(t)
	const name = "dup.dat"

	if err := s.CreateFile(name, 32); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if err := s.CreateFile(name, 32); !errors.Is(err, gosdf.SDR_FILEEXISTS) {
		t.Errorf("duplicate Create = %v, want SDR_FILEEXISTS", err)
	}
	// 越界写:offset 32 + 4 > 文件大小
	if err := s.WriteFile(name, 32, []byte("abcd")); !errors.Is(err, gosdf.SDR_FILEOFSERR) {
		t.Errorf("out-of-range Write = %v, want SDR_FILEOFSERR", err)
	}
	// 超读按文件实际大小截断
	got, err := s.ReadFile(name, 0, 100)
	if err != nil {
		t.Fatalf("ReadFile(100): %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("ReadFile(100) len = %d, want 32", len(got))
	}
	// 文件名 >128 字节
	if err := s.CreateFile(strings.Repeat("a", 129), 32); !errors.Is(err, gosdf.SDR_INARGERR) {
		t.Errorf("129-byte name = %v, want SDR_INARGERR", err)
	}
	s.DeleteFile(name)
}

// ---- H: 错误契约 ----

func TestErrorsIs(t *testing.T) {
	s := newSession(t)
	err := s.AcquireKeyRight(missingKeyIndex, []byte(testPIN))
	if !errors.Is(err, gosdf.SDR_KEYNOTEXIST) {
		t.Fatalf("AcquireKeyRight(missing) = %v, want SDR_KEYNOTEXIST", err)
	}
	if !strings.Contains(err.Error(), "SDF_GetPrivateKeyAccessRight") {
		t.Errorf("error %q does not contain function name", err)
	}
}
