package gosdf

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// ---- 符号矩阵(按 sdf_shim.c gs_func_name_arr 原序,分组按 BIND 块与 GM/T 0018 表) ----

// probeSymbolTable 是绑定面的 63 个 SDF_* 符号名,顺序与 sdf_shim.c 的
// gs_func_name_arr 一字不差;分组:设备管理 8、杂凑 3、HMAC 3、密钥管理 21、
// 非对称运算 4、对称运算 12、AEAD 8、文件 4。
var probeSymbolTable = []struct{ name, group string }{
	{"SDF_OpenDevice", "设备管理"},
	{"SDF_CloseDevice", "设备管理"},
	{"SDF_OpenSession", "设备管理"},
	{"SDF_CloseSession", "设备管理"},
	{"SDF_GetDeviceInfo", "设备管理"},
	{"SDF_GenerateRandom", "设备管理"},
	{"SDF_GetPrivateKeyAccessRight", "设备管理"},
	{"SDF_ReleasePrivateKeyAccessRight", "设备管理"},

	{"SDF_HashInit", "杂凑"},
	{"SDF_HashUpdate", "杂凑"},
	{"SDF_HashFinal", "杂凑"},

	{"SDF_HMACInit", "HMAC"},
	{"SDF_HMACUpdate", "HMAC"},
	{"SDF_HMACFinal", "HMAC"},

	{"SDF_ExportSignPublicKey_ECC", "密钥管理"},
	{"SDF_ExportEncPublicKey_ECC", "密钥管理"},
	{"SDF_GenerateKeyWithIPK_ECC", "密钥管理"},
	{"SDF_GenerateKeyWithEPK_ECC", "密钥管理"},
	{"SDF_ImportKeyWithISK_ECC", "密钥管理"},
	{"SDF_GenerateKeyWithKEK", "密钥管理"},
	{"SDF_ImportKeyWithKEK", "密钥管理"},
	{"SDF_DestroyKey", "密钥管理"},
	{"SDF_ExportSignPublicKey_RSA", "密钥管理"},
	{"SDF_ExportEncPublicKey_RSA", "密钥管理"},
	{"SDF_GenerateKeyPair_RSA", "密钥管理"},
	{"SDF_GenerateKeyPair_ECC", "密钥管理"},
	{"SDF_GenerateKeyWithIPK_RSA", "密钥管理"},
	{"SDF_GenerateKeyWithEPK_RSA", "密钥管理"},
	{"SDF_ImportKeyWithISK_RSA", "密钥管理"},
	{"SDF_ExchangeDigitEnvelopeBaseOnRSA", "密钥管理"},
	{"SDF_ExchangeDigitEnvelopeBaseOnECC", "密钥管理"},
	{"SDF_ImportKey", "密钥管理"},
	{"SDF_GenerateAgreementDataWithECC", "密钥管理"},
	{"SDF_GenerateKeyWithECC", "密钥管理"},
	{"SDF_GenerateAgreementDataAndKeyWithECC", "密钥管理"},

	{"SDF_ExternalVerify_ECC", "非对称运算"},
	{"SDF_InternalSign_ECC", "非对称运算"},
	{"SDF_InternalVerify_ECC", "非对称运算"},
	{"SDF_ExternalEncrypt_ECC", "非对称运算"},

	{"SDF_Encrypt", "对称运算"},
	{"SDF_Decrypt", "对称运算"},
	{"SDF_CalculateMAC", "对称运算"},
	{"SDF_EncryptInit", "对称运算"},
	{"SDF_EncryptUpdate", "对称运算"},
	{"SDF_EncryptFinal", "对称运算"},
	{"SDF_DecryptInit", "对称运算"},
	{"SDF_DecryptUpdate", "对称运算"},
	{"SDF_DecryptFinal", "对称运算"},
	{"SDF_CalculateMACInit", "对称运算"},
	{"SDF_CalculateMACUpdate", "对称运算"},
	{"SDF_CalculateMACFinal", "对称运算"},

	{"SDF_AuthEnc", "AEAD"},
	{"SDF_AuthDec", "AEAD"},
	{"SDF_AuthEncInit", "AEAD"},
	{"SDF_AuthEncUpdate", "AEAD"},
	{"SDF_AuthEncFinal", "AEAD"},
	{"SDF_AuthDecInit", "AEAD"},
	{"SDF_AuthDecUpdate", "AEAD"},
	{"SDF_AuthDecFinal", "AEAD"},

	{"SDF_CreateFile", "文件"},
	{"SDF_ReadFile", "文件"},
	{"SDF_WriteFile", "文件"},
	{"SDF_DeleteFile", "文件"},
}

// probeSymbols 按静态表顺序探测 dev 导出的支持情况。
func probeSymbols(dev *Device) []ProbeSymbol {
	out := make([]ProbeSymbol, len(probeSymbolTable))
	for i, s := range probeSymbolTable {
		out[i] = ProbeSymbol{Name: s.name, Group: s.group, Supported: dev.Supports(s.name)}
	}
	return out
}

// ---- 参考实现(移植自 integration/softsdf_test.go:132-155,gmsm + stdlib) ----

// probeRand 返回 n 字节密码学随机数。
func probeRand(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	return b, nil
}

// sm4ECBRef 用 gmsm SM4-ECB 计算参考密文。
func sm4ECBRef(key, block []byte) ([]byte, error) {
	blk, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sm4.NewCipher: %w", err)
	}
	out := make([]byte, len(block))
	blk.Encrypt(out, block)
	return out, nil
}

// cbcMacRef 用 gmsm SM4-CBC 计算参考 CBC-MAC(末块)。
func cbcMacRef(key, iv, data []byte) ([]byte, error) {
	if len(data)%Sm4BlockSize != 0 {
		return nil, fmt.Errorf("probe bug: CBC-MAC reference needs aligned data, got %d", len(data))
	}
	blk, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sm4.NewCipher: %w", err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, data)
	return out[len(out)-Sm4BlockSize:], nil
}

// ---- 检查表(28 项;crib 见 integration/softsdf_test.go 对应测试) ----

// probeCheckTable 按 GM/T 0018 功能分组排列;跳过/恢复策略见 runChecks。
var probeCheckTable = []probeCheck{
	{
		name: "key-right", group: "设备管理",
		requires: []string{"SDF_GetPrivateKeyAccessRight"},
		run:      checkKeyRight,
	},
	{
		name: "device.info", group: "设备管理",
		requires: []string{"SDF_GetDeviceInfo"},
		run:      checkDeviceInfo,
	},
	{
		name: "random", group: "设备管理",
		requires: []string{"SDF_GenerateRandom"},
		run:      checkRandom,
	},

	{
		name: "sm3-kat", group: "杂凑",
		requires: []string{"SDF_HashInit", "SDF_HashUpdate", "SDF_HashFinal"},
		run:      checkSM3KAT,
	},
	{
		name: "sm3-contract", group: "杂凑",
		requires: []string{"SDF_HashInit", "SDF_HashUpdate", "SDF_HashFinal"},
		run:      checkSM3Contract,
	},
	{
		name: "sm2-za", group: "杂凑",
		requires: []string{"SDF_HashInit", "SDF_HashUpdate", "SDF_HashFinal"},
		run:      checkSM2ZA,
	},

	{
		name: "hmac-kat", group: "HMAC",
		requires: []string{"SDF_HMACInit", "SDF_HMACUpdate", "SDF_HMACFinal"},
		run:      checkHMACKAT,
	},

	{
		name: "sm2-export", group: "SM2",
		requires: []string{"SDF_ExportSignPublicKey_ECC"},
		run:      checkSM2Export,
	},
	{
		name: "sm2-verify", group: "SM2",
		requires: []string{
			"SDF_ExternalVerify_ECC",
			"SDF_HashInit", "SDF_HashUpdate", "SDF_HashFinal",
		},
		run: checkSM2Verify,
	},
	{
		name: "sm2-encrypt", group: "SM2",
		requires: []string{"SDF_ExternalEncrypt_ECC"},
		run:      checkSM2Encrypt,
	},
	{
		name: "sm2-sign", group: "SM2",
		requires: []string{
			"SDF_InternalSign_ECC", "SDF_InternalVerify_ECC",
			"SDF_ExportSignPublicKey_ECC",
			"SDF_HashInit", "SDF_HashUpdate", "SDF_HashFinal",
		},
		needsRight: true,
		run:        checkSM2Sign,
	},
	{
		name: "ecc-keypair", group: "SM2",
		requires: []string{"SDF_GenerateKeyPair_ECC"},
		run:      checkECCKeyPair,
	},
	{
		name: "sm2-envelope", group: "SM2",
		requires: []string{"SDF_GenerateKeyWithEPK_ECC", "SDF_Encrypt"},
		run:      checkSM2Envelope,
	},

	{
		name: "ipk-isk", group: "密钥管理",
		requires: []string{
			"SDF_GenerateKeyWithIPK_ECC", "SDF_ImportKeyWithISK_ECC",
			"SDF_Encrypt",
		},
		needsRight: true,
		run:        checkIPKISK,
	},
	{
		name: "key-agreement", group: "密钥管理",
		requires: []string{
			"SDF_GenerateAgreementDataWithECC", "SDF_GenerateKeyWithECC",
			"SDF_GenerateAgreementDataAndKeyWithECC",
			"SDF_Encrypt",
		},
		needsRight: true,
		run:        checkKeyAgreement,
	},
	{
		name: "kek-wrap", group: "密钥管理",
		requires: []string{"SDF_GenerateKeyWithKEK", "SDF_ImportKeyWithKEK", "SDF_Encrypt"},
		run:      checkKEKWrap,
	},
	{
		name: "import-key", group: "密钥管理",
		requires: []string{"SDF_ImportKey", "SDF_Encrypt"},
		run:      checkImportKey,
	},

	{
		name: "rsa-export", group: "RSA",
		requires: []string{"SDF_ExportSignPublicKey_RSA", "SDF_ExportEncPublicKey_RSA"},
		run:      checkRSAExport,
	},
	{
		name: "rsa-envelope", group: "RSA",
		requires: []string{"SDF_GenerateKeyWithEPK_RSA", "SDF_Encrypt"},
		run:      checkRSAEnvelope,
	},
	{
		name: "rsa-ipk-isk", group: "RSA",
		requires: []string{
			"SDF_GenerateKeyWithIPK_RSA", "SDF_ImportKeyWithISK_RSA",
			"SDF_Encrypt",
		},
		needsRight: true,
		run:        checkRSAIPKISK,
	},
	{
		name: "rsa-keypair", group: "RSA",
		requires: []string{"SDF_GenerateKeyPair_RSA"},
		run:      checkRSAKeyPair,
	},

	{
		name: "sym-roundtrip", group: "对称",
		requires: []string{"SDF_Encrypt", "SDF_Decrypt"},
		run:      checkSymRoundtrip,
	},
	{
		name: "sym-stream", group: "对称",
		requires: []string{"SDF_Encrypt", "SDF_Decrypt"},
		run:      checkSymStream,
	},
	{
		name: "sym-multipart", group: "对称",
		requires: []string{
			"SDF_EncryptInit", "SDF_EncryptUpdate", "SDF_EncryptFinal",
			"SDF_Encrypt",
		},
		run: checkSymMultipart,
	},
	{
		name: "mac", group: "对称",
		requires: []string{"SDF_CalculateMAC"},
		run:      checkMAC,
	},

	{
		name: "aead", group: "AEAD",
		requires: []string{"SDF_AuthEnc", "SDF_AuthDec"},
		run:      checkAEAD,
	},
	{
		name: "aead-multipart", group: "AEAD",
		requires: []string{
			"SDF_AuthEncInit", "SDF_AuthEncUpdate", "SDF_AuthEncFinal",
			"SDF_AuthDecInit", "SDF_AuthDecUpdate", "SDF_AuthDecFinal",
			"SDF_AuthEnc",
		},
		run: checkAEADMultipart,
	},

	{
		name: "file-ops", group: "文件",
		requires: []string{"SDF_CreateFile", "SDF_WriteFile", "SDF_ReadFile", "SDF_DeleteFile"},
		run:      checkFileOps,
	},
}

// ---- 各检查实现 ----

// checkKeyRight 仅在提供 PIN 时运行:AcquireKeyRight 成功即取到权限。
func checkKeyRight(c *probeCtx) (string, error) {
	if len(c.pin) == 0 {
		return "", skipf("needs PIN (WithPIN)")
	}
	if err := c.sess.AcquireKeyRight(c.keyIndex, c.pin); err != nil {
		c.rightErr = err
		return "", err
	}
	c.rights = true
	return fmt.Sprintf("key index %d unlocked", c.keyIndex), nil
}

// checkDeviceInfo 设备身份非全空;Detail 打印版本与算法能力位。
func checkDeviceInfo(c *probeCtx) (string, error) {
	info, err := c.sess.GetDeviceInfo()
	if err != nil {
		return "", err
	}
	c.info = info
	if info.IssuerName == "" && info.DeviceName == "" && info.DeviceSerial == "" {
		return "", errors.New("empty IssuerName/DeviceName/DeviceSerial")
	}
	return fmt.Sprintf("stdver=0x%08x sym=0x%08x hash=0x%08x buffer=%d",
		info.StandardVersion, info.SymAlgAbility, info.HashAlgAbility, info.BufferSize), nil
}

// checkRandom 两次 32 字节随机数非零且互异;GenerateRandom(0) 为空;流式读满。
func checkRandom(c *probeCtx) (string, error) {
	r1, err := c.sess.GenerateRandom(32)
	if err != nil {
		return "", fmt.Errorf("GenerateRandom(32): %w", err)
	}
	if len(r1) != 32 {
		return "", fmt.Errorf("GenerateRandom(32) = %d bytes, want 32", len(r1))
	}
	zero := make([]byte, 32)
	if bytes.Equal(r1, zero) {
		return "", errors.New("GenerateRandom(32) returned all-zero bytes")
	}
	r2, err := c.sess.GenerateRandom(32)
	if err != nil {
		return "", fmt.Errorf("GenerateRandom(32) 2nd: %w", err)
	}
	if bytes.Equal(r2, zero) {
		return "", errors.New("GenerateRandom(32) 2nd returned all-zero bytes")
	}
	if bytes.Equal(r1, r2) {
		return "", errors.New("two GenerateRandom(32) blocks are equal")
	}
	n0, err := c.sess.GenerateRandom(0)
	if err != nil {
		return "", fmt.Errorf("GenerateRandom(0): %w", err)
	}
	if len(n0) != 0 {
		return "", fmt.Errorf("GenerateRandom(0) = %d bytes, want 0", len(n0))
	}
	buf := make([]byte, 16)
	if n, err := io.ReadFull(c.sess.Random(), buf); err != nil || n != 16 {
		return "", fmt.Errorf("Random().Read = (%d, %v), want (16, nil)", n, err)
	}
	return "2x32 distinct non-zero; GenerateRandom(0) empty; stream read ok", nil
}

// checkSM3KAT SM3("abc") 与 gmsm 参考值一致。
func checkSM3KAT(c *probeCtx) (string, error) {
	got, err := c.dev.SM3Sum([]byte("abc"))
	if err != nil {
		return "", fmt.Errorf("SM3Sum: %w", err)
	}
	want := sm3.Sum([]byte("abc"))
	if !bytes.Equal(got, want[:]) {
		return "", fmt.Errorf("SM3(abc) = %x, want %x", got, want)
	}
	return "SM3(abc) matches gmsm reference", nil
}

// checkSM3Contract hash.Hash 契约:Size/BlockSize、Sum 可重复、Reset 复原。
func checkSM3Contract(c *probeCtx) (string, error) {
	h := c.dev.NewSM3Hash()
	if h.Size() != 32 {
		return "", fmt.Errorf("Size = %d, want 32", h.Size())
	}
	if h.BlockSize() != 64 {
		return "", fmt.Errorf("BlockSize = %d, want 64", h.BlockSize())
	}
	if n, err := h.Write([]byte("probe")); err != nil || n != 5 {
		return "", fmt.Errorf("Write = (%d, %v), want (5, nil)", n, err)
	}
	sum1 := h.Sum(nil)
	if sum2 := h.Sum(nil); !bytes.Equal(sum1, sum2) {
		return "", errors.New("Sum is not state-preserving")
	}
	h.Reset()
	if _, err := h.Write([]byte("probe")); err != nil {
		return "", fmt.Errorf("Write after Reset: %w", err)
	}
	if !bytes.Equal(h.Sum(nil), sum1) {
		return "", errors.New("Reset did not restore state")
	}
	return "Size=32 BlockSize=64; Sum state-preserving; Reset restores", nil
}

// checkSM2ZA NewSM2ZAHash 分步结果 == sm2.CalculateZA + SM3(GB/T 32918.1)。
func checkSM2ZA(c *probeCtx) (string, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("sm2.GenerateKey: %w", err)
	}
	uid := []byte("gosdf-probe-uid")
	msg := []byte("gosdf probe za message")
	h, err := c.sess.NewSM2ZAHash(&priv.PublicKey, uid)
	if err != nil {
		return "", fmt.Errorf("NewSM2ZAHash: %w", err)
	}
	if err := h.Update(msg); err != nil {
		return "", fmt.Errorf("ZA Update: %w", err)
	}
	got, err := h.Final()
	if err != nil {
		return "", fmt.Errorf("ZA Final: %w", err)
	}
	za, err := sm2.CalculateZA(&priv.PublicKey, uid)
	if err != nil {
		return "", fmt.Errorf("sm2.CalculateZA: %w", err)
	}
	want := sm3.Sum(append(append([]byte{}, za...), msg...))
	if !bytes.Equal(got, want[:]) {
		return "", fmt.Errorf("ZA digest = %x, want %x", got, want)
	}
	return "ZA digest matches sm2.CalculateZA+SM3", nil
}

// checkHMACKAT 一步式 == 分块;密钥已知时另与 crypto/hmac 比对。
func checkHMACKAT(c *probeCtx) (string, error) {
	key, raw, err := c.sessionKey()
	if err != nil {
		return "", skipf("no session key: %v", err)
	}
	msg := []byte("abc")
	got, err := key.HMAC(SGD_SM3_HMAC, msg)
	if err != nil {
		return "", fmt.Errorf("HMAC: %w", err)
	}
	h, err := key.NewHMAC(SGD_SM3_HMAC)
	if err != nil {
		return "", fmt.Errorf("NewHMAC: %w", err)
	}
	if err := h.Update([]byte("a")); err != nil {
		return "", fmt.Errorf("HMAC Update: %w", err)
	}
	if err := h.Update([]byte("bc")); err != nil {
		return "", fmt.Errorf("HMAC Update: %w", err)
	}
	got2, err := h.Final()
	if err != nil {
		return "", fmt.Errorf("HMAC Final: %w", err)
	}
	if !bytes.Equal(got, got2) {
		return "", fmt.Errorf("chunked HMAC = %x, want one-shot %x", got2, got)
	}
	if raw == nil {
		return "chunked == one-shot (session key bytes unknown)", nil
	}
	m := hmac.New(sm3.New, raw)
	m.Write(msg)
	want := m.Sum(nil)
	if !bytes.Equal(got, want) {
		return "", fmt.Errorf("HMAC-SM3 = %x, want %x", got, want)
	}
	return "HMAC-SM3 matches crypto/hmac; chunked == one-shot", nil
}

// checkSM2Export 导出的内部签名公钥必须是 SM2 曲线上的点。
func checkSM2Export(c *probeCtx) (string, error) {
	pub, err := c.sess.ExportSignPublicKey(c.keyIndex)
	if err != nil {
		return "", fmt.Errorf("ExportSignPublicKey: %w", err)
	}
	if pub == nil || pub.Curve == nil || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return "", errors.New("exported sign public key not on curve")
	}
	return "sign public key valid on SM2 curve", nil
}

// checkSM2Verify gmsm 签名 → 设备验签;篡改签名 → SDR_VERIFYERR。
func checkSM2Verify(c *probeCtx) (string, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("sm2.GenerateKey: %w", err)
	}
	pub := &priv.PublicKey
	uid := []byte("gosdf-probe-uid")
	msg := []byte("gosdf probe verify message")
	za, err := sm2.CalculateZA(pub, uid)
	if err != nil {
		return "", fmt.Errorf("sm2.CalculateZA: %w", err)
	}
	e := sm3.Sum(append(append([]byte{}, za...), msg...))
	sig, err := sm2.SignASN1(rand.Reader, priv, e[:], nil)
	if err != nil {
		return "", fmt.Errorf("sm2.SignASN1: %w", err)
	}
	if err := c.sess.VerifySM2(pub, uid, msg, sig); err != nil {
		return "", fmt.Errorf("VerifySM2: %w", err)
	}
	badSig := append([]byte(nil), sig...)
	badSig[len(badSig)-1] ^= 0x01 // 末字节恒为 S 的内容字节,避免命中 DER 标签
	if err := c.sess.VerifySM2(pub, uid, msg, badSig); !errors.Is(err, SDR_VERIFYERR) {
		return "", fmt.Errorf("tampered sig = %v, want SDR_VERIFYERR", err)
	}
	return "gmsm signature verified; tampered signature SDR_VERIFYERR", nil
}

// checkSM2Encrypt 设备 SM2Encrypt 输出可被 gmsm Decrypt 还原。
func checkSM2Encrypt(c *probeCtx) (string, error) {
	extPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("sm2.GenerateKey: %w", err)
	}
	k, err := probeRand(16)
	if err != nil {
		return "", err
	}
	ct, err := c.sess.SM2Encrypt(&extPriv.PublicKey, k)
	if err != nil {
		return "", fmt.Errorf("SM2Encrypt: %w", err)
	}
	back, err := sm2.Decrypt(extPriv, ct)
	if err != nil {
		return "", fmt.Errorf("gmsm Decrypt: %w", err)
	}
	if !bytes.Equal(back, k) {
		return "", fmt.Errorf("gmsm Decrypt = %x, want %x", back, k)
	}
	return "device SM2Encrypt output decrypts with gmsm", nil
}

// checkSM2Sign 内部签名:gmsm 同 UID 验签 + 设备内部验签。
func checkSM2Sign(c *probeCtx) (string, error) {
	signer, err := c.sess.NewSignerKey(c.keyIndex)
	if err != nil {
		return "", fmt.Errorf("NewSignerKey: %w", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}
	uid := []byte("gosdf-probe-uid")
	msg := []byte("gosdf probe sign message")
	sig, err := signer.Sign(nil, msg, &SM2SignerOptions{UID: uid})
	if err != nil {
		return "", fmt.Errorf("Sign: %w", err)
	}
	if !sm2.VerifyASN1WithSM2(pub, uid, msg, sig) {
		return "", errors.New("gmsm VerifyASN1WithSM2 rejected device signature")
	}
	e := sm3.Sum(msg)
	sig2, err := signer.Sign(nil, e[:], nil)
	if err != nil {
		return "", fmt.Errorf("Sign pre-digested: %w", err)
	}
	if err := c.sess.VerifySM2Internal(c.keyIndex, e[:], sig2); err != nil {
		return "", fmt.Errorf("VerifySM2Internal: %w", err)
	}
	return "gmsm VerifyASN1WithSM2 + SDF_InternalVerify_ECC ok", nil
}

// checkECCKeyPair 生成的 SM2 密钥对:D∈[1,n-1]、公钥点在曲线上。
func checkECCKeyPair(c *probeCtx) (string, error) {
	priv, err := c.sess.GenerateKeyPairECC(SGD_SM2_1, 256)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyPairECC: %w", err)
	}
	if priv.D == nil || priv.D.Sign() <= 0 {
		return "", errors.New("private D not positive")
	}
	if priv.D.Cmp(priv.Params().N) >= 0 {
		return "", errors.New("private D not in [1, n-1]")
	}
	if !priv.Curve.IsOnCurve(priv.X, priv.Y) {
		return "", errors.New("public key not on curve")
	}
	return "SM2 keypair: D in [1,n-1], point on curve", nil
}

// checkSM2Envelope EPK 封装信封可被外部私钥解封,句柄密钥 == SM4(K)。
func checkSM2Envelope(c *probeCtx) (string, error) {
	extPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("sm2.GenerateKey: %w", err)
	}
	wrapped, key1, err := c.sess.GenerateKeyWithEPK(128, &extPriv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyWithEPK: %w", err)
	}
	defer key1.Destroy()
	k1, err := sm2.Decrypt(extPriv, wrapped)
	if err != nil {
		return "", fmt.Errorf("gmsm Decrypt(wrapped): %w", err)
	}
	block, err := probeRand(16)
	if err != nil {
		return "", err
	}
	ct, err := key1.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key.Encrypt: %w", err)
	}
	want, err := sm4ECBRef(k1, block)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(ct, want) {
		return "", fmt.Errorf("SM4(K) = %x, want %x", ct, want)
	}
	return "EPK envelope unwraps to handle key (SM4-ECB matches)", nil
}

// checkIPKISK IPK 封装与 ISK 导入同密钥;信封转换已绑定时另验证解封。
func checkIPKISK(c *probeCtx) (string, error) {
	wrappedIPK, key1, err := c.sess.GenerateKeyWithIPK(c.keyIndex, 128)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyWithIPK: %w", err)
	}
	defer key1.Destroy()
	key2, err := c.sess.ImportKeyWithISK(c.keyIndex, wrappedIPK)
	if err != nil {
		return "", fmt.Errorf("ImportKeyWithISK: %w", err)
	}
	defer key2.Destroy()

	block, err := probeRand(16)
	if err != nil {
		return "", err
	}
	ct1, err := key1.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key1.Encrypt: %w", err)
	}
	ct2, err := key2.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key2.Encrypt: %w", err)
	}
	if !bytes.Equal(ct1, ct2) {
		return "", errors.New("IPK-wrapped and ISK-imported keys differ")
	}
	detail := "IPK/ISK wrap round trip equal"

	// GM/T 0018-2012 6.3.17:Exchange 输入须为内部公钥信封,输出为外部公钥信封。
	if c.dev.Supports("SDF_ExchangeDigitEnvelopeBaseOnECC") {
		extPriv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("sm2.GenerateKey: %w", err)
		}
		converted, err := c.sess.ExchangeEnvelopeECC(c.keyIndex, SGD_SM2_3,
			&extPriv.PublicKey, wrappedIPK)
		if err != nil {
			return "", fmt.Errorf("ExchangeEnvelopeECC: %w", err)
		}
		k2, err := sm2.Decrypt(extPriv, converted)
		if err != nil {
			return "", fmt.Errorf("gmsm Decrypt(converted): %w", err)
		}
		want, err := sm4ECBRef(k2, block)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(ct1, want) {
			return "", fmt.Errorf("exchanged envelope SM4(K) = %x, want %x", ct1, want)
		}
		detail += "; ExchangeDigitEnvelopeBaseOnECC unwraps to K"
	}
	return detail, nil
}

// checkKeyAgreement 双会话三函数协商,两侧句柄同块加密相等。
func checkKeyAgreement(c *probeCtx) (string, error) {
	sessB, err := c.dev.NewSession()
	if err != nil {
		return "", fmt.Errorf("NewSession(2): %w", err)
	}
	defer sessB.Close()
	if err := sessB.AcquireKeyRight(c.keyIndex, c.pin); err != nil {
		return "", fmt.Errorf("AcquireKeyRight(2nd session): %w", err)
	}
	defer sessB.ReleaseKeyRight(c.keyIndex)

	sponsorID := []byte("gosdf-probe-sponsor")
	responseID := []byte("gosdf-probe-respons")
	ah, sponsorPub, sponsorTmp, err := c.sess.GenerateAgreementDataWithECC(
		c.keyIndex, 128, sponsorID,
	)
	if err != nil {
		return "", fmt.Errorf("GenerateAgreementDataWithECC: %w", err)
	}
	respPub, respTmp, keyB, err := sessB.GenerateAgreementDataAndKeyWithECC(
		c.keyIndex, 128, sponsorID, responseID, sponsorPub, sponsorTmp,
	)
	if err != nil {
		return "", fmt.Errorf("GenerateAgreementDataAndKeyWithECC: %w", err)
	}
	defer keyB.Destroy()
	keyA, err := c.sess.GenerateKeyWithECC(ah, responseID, respPub, respTmp)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyWithECC: %w", err)
	}
	defer keyA.Destroy()

	block, err := probeRand(16)
	if err != nil {
		return "", err
	}
	ctA, err := keyA.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("keyA.Encrypt: %w", err)
	}
	ctB, err := keyB.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("keyB.Encrypt: %w", err)
	}
	if !bytes.Equal(ctA, ctB) {
		return "", fmt.Errorf("agreed keys differ: A=%x B=%x", ctA, ctB)
	}
	return "two-session agreement produces equal keys", nil
}

// checkKEKWrap GenerateKeyWithKEK 与 ImportKeyWithKEK 结果同密钥。
func checkKEKWrap(c *probeCtx) (string, error) {
	wrapped, key1, err := c.sess.GenerateKeyWithKEK(c.kekIndex, 128, SM4_ECB)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyWithKEK: %w", err)
	}
	defer key1.Destroy()
	key2, err := c.sess.ImportKeyWithKEK(c.kekIndex, SM4_ECB, wrapped)
	if err != nil {
		return "", fmt.Errorf("ImportKeyWithKEK: %w", err)
	}
	defer key2.Destroy()

	block, err := probeRand(16)
	if err != nil {
		return "", err
	}
	ct1, err := key1.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key1.Encrypt: %w", err)
	}
	ct2, err := key2.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key2.Encrypt: %w", err)
	}
	if !bytes.Equal(ct1, ct2) {
		return "", errors.New("KEK generate/import keys differ")
	}
	return "GenerateKeyWithKEK/ImportKeyWithKEK yield same key", nil
}

// checkImportKey 明文导入密钥的 KAT 与入参拒绝(nil/65 字节)。
func checkImportKey(c *probeCtx) (string, error) {
	raw, err := probeRand(16)
	if err != nil {
		return "", err
	}
	key, err := c.sess.ImportKey(raw)
	if err != nil {
		return "", fmt.Errorf("ImportKey: %w", err)
	}
	defer key.Destroy()

	block, err := probeRand(16)
	if err != nil {
		return "", err
	}
	got, err := key.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key.Encrypt: %w", err)
	}
	want, err := sm4ECBRef(raw, block)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(got, want) {
		return "", fmt.Errorf("SM4(imported K) = %x, want %x", got, want)
	}
	if _, err := c.sess.ImportKey(nil); !errors.Is(err, SDR_INARGERR) {
		return "", fmt.Errorf("ImportKey(nil) = %v, want SDR_INARGERR", err)
	}
	if _, err := c.sess.ImportKey(make([]byte, 65)); !errors.Is(err, SDR_INARGERR) {
		return "", fmt.Errorf("ImportKey(65) = %v, want SDR_INARGERR", err)
	}
	return "imported key KAT matches; nil/65-byte input rejected SDR_INARGERR", nil
}

// checkRSAExport 两把 RSA 公钥 N≥1024 位、E≥3。
func checkRSAExport(c *probeCtx) (string, error) {
	signPub, err := c.sess.ExportSignPublicKeyRSA(c.keyIndex)
	if err != nil {
		return "", fmt.Errorf("ExportSignPublicKey_RSA: %w", err)
	}
	encPub, err := c.sess.ExportEncPublicKeyRSA(c.keyIndex)
	if err != nil {
		return "", fmt.Errorf("ExportEncPublicKey_RSA: %w", err)
	}
	for _, tc := range []struct {
		name string
		pub  *rsa.PublicKey
	}{{"sign", signPub}, {"enc", encPub}} {
		if tc.pub.N.BitLen() < 1024 {
			return "", fmt.Errorf("%s N bits = %d, want >= 1024", tc.name, tc.pub.N.BitLen())
		}
		if tc.pub.E < 3 {
			return "", fmt.Errorf("%s E = %d, want >= 3", tc.name, tc.pub.E)
		}
	}
	return fmt.Sprintf("sign/enc N bits = %d/%d, E = %d/%d",
		signPub.N.BitLen(), encPub.N.BitLen(), signPub.E, encPub.E), nil
}

// checkRSAEnvelope RSA EPK 信封可用外部私钥 PKCS#1 v1.5 解封,句柄 == SM4(K)。
func checkRSAEnvelope(c *probeCtx) (string, error) {
	extPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", fmt.Errorf("rsa.GenerateKey: %w", err)
	}
	wrapped, key1, err := c.sess.GenerateKeyWithEPKRSA(128, &extPriv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyWithEPK_RSA: %w", err)
	}
	defer key1.Destroy()
	k, err := rsa.DecryptPKCS1v15(rand.Reader, extPriv, wrapped)
	if err != nil {
		return "", fmt.Errorf("rsa.DecryptPKCS1v15: %w", err)
	}
	if len(k) != 16 {
		return "", fmt.Errorf("unwrapped K = %d bytes, want 16", len(k))
	}
	block, err := probeRand(16)
	if err != nil {
		return "", err
	}
	got, err := key1.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key.Encrypt: %w", err)
	}
	want, err := sm4ECBRef(k, block)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(got, want) {
		return "", fmt.Errorf("SM4(K) = %x, want %x", got, want)
	}
	return "RSA EPK envelope unwraps to handle key", nil
}

// checkRSAIPKISK RSA IPK/ISK 往返;信封转换已绑定时另验证 PKCS#1 解封。
func checkRSAIPKISK(c *probeCtx) (string, error) {
	wrapped1, key2, err := c.sess.GenerateKeyWithIPKRSA(c.keyIndex, 128)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyWithIPK_RSA: %w", err)
	}
	defer key2.Destroy()
	key3, err := c.sess.ImportKeyWithISKRSA(c.keyIndex, wrapped1)
	if err != nil {
		return "", fmt.Errorf("ImportKeyWithISK_RSA: %w", err)
	}
	defer key3.Destroy()

	block, err := probeRand(16)
	if err != nil {
		return "", err
	}
	ct2, err := key2.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key2.Encrypt: %w", err)
	}
	ct3, err := key3.Encrypt(SM4_ECB, nil, block)
	if err != nil {
		return "", fmt.Errorf("key3.Encrypt: %w", err)
	}
	if !bytes.Equal(ct2, ct3) {
		return "", errors.New("IPK/ISK RSA round trip keys differ")
	}
	detail := "RSA IPK/ISK wrap round trip equal"

	if c.dev.Supports("SDF_ExchangeDigitEnvelopeBaseOnRSA") {
		extPriv, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return "", fmt.Errorf("rsa.GenerateKey: %w", err)
		}
		converted, err := c.sess.ExchangeEnvelopeRSA(c.keyIndex, &extPriv.PublicKey, wrapped1)
		if err != nil {
			return "", fmt.Errorf("ExchangeEnvelopeRSA: %w", err)
		}
		extK, err := rsa.DecryptPKCS1v15(rand.Reader, extPriv, converted)
		if err != nil {
			return "", fmt.Errorf("rsa.DecryptPKCS1v15(converted): %w", err)
		}
		if len(extK) != 16 {
			return "", fmt.Errorf("converted K = %d bytes, want 16", len(extK))
		}
		want, err := sm4ECBRef(extK, block)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(ct2, want) {
			return "", fmt.Errorf("exchanged RSA SM4(K) = %x, want %x", ct2, want)
		}
		detail += "; ExchangeDigitEnvelopeBaseOnRSA unwraps to K"
	}
	return detail, nil
}

// checkRSAKeyPair 1024 位 RSA 密钥对通过 Validate。
func checkRSAKeyPair(c *probeCtx) (string, error) {
	priv, err := c.sess.GenerateKeyPairRSA(1024)
	if err != nil {
		return "", fmt.Errorf("GenerateKeyPair_RSA: %w", err)
	}
	if err := priv.Validate(); err != nil {
		return "", fmt.Errorf("priv.Validate: %w", err)
	}
	if priv.N.BitLen() != 1024 {
		return "", fmt.Errorf("N bits = %d, want 1024", priv.N.BitLen())
	}
	return "1024-bit RSA keypair passes Validate", nil
}

// checkSymRoundtrip PKCS7 往返与坏填充拒绝;密钥已知时另做 ECB KAT 与 CBC 对 stdlib。
func checkSymRoundtrip(c *probeCtx) (string, error) {
	key, raw, err := c.sessionKey()
	if err != nil {
		return "", skipf("no session key: %v", err)
	}
	iv, err := probeRand(16)
	if err != nil {
		return "", err
	}
	plain := []byte("non-block-aligned probe data!")
	ct, err := key.EncryptPKCS7(SM4_CBC, iv, plain)
	if err != nil {
		return "", fmt.Errorf("EncryptPKCS7: %w", err)
	}
	back, err := key.DecryptPKCS7(SM4_CBC, iv, ct)
	if err != nil {
		return "", fmt.Errorf("DecryptPKCS7: %w", err)
	}
	if !bytes.Equal(back, plain) {
		return "", fmt.Errorf("PKCS7 round trip = %x, want %x", back, plain)
	}
	if raw == nil {
		return "PKCS7 round trip ok (invalid-padding check needs known key)", nil
	}
	// 用已知密钥构造确定性非法填充(末字节 0x00),避免随机密钥下
	// 约 1/255 概率解出合法 PKCS7 填充造成假失败。
	badBlk, err := sm4.NewCipher(raw)
	if err != nil {
		return "", fmt.Errorf("sm4.NewCipher: %w", err)
	}
	badPlain := make([]byte, Sm4BlockSize)
	badPlain[Sm4BlockSize-1] = 0x00
	badCT := make([]byte, Sm4BlockSize)
	cipher.NewCBCEncrypter(badBlk, iv).CryptBlocks(badCT, badPlain)
	if _, err := key.DecryptPKCS7(SM4_CBC, iv, badCT); err == nil {
		return "", errors.New("DecryptPKCS7 accepted invalid padding")
	}

	// SM4 ECB KAT:独立导入已知 KAT 密钥。
	katKeyBytes, err := hex.DecodeString("0123456789abcdeffedcba9876543210")
	if err != nil {
		return "", err
	}
	katPlain, err := hex.DecodeString("0123456789abcdeffedcba9876543210")
	if err != nil {
		return "", err
	}
	katWant, err := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	if err != nil {
		return "", err
	}
	katKey, err := c.sess.ImportKey(katKeyBytes)
	if err != nil {
		return "", fmt.Errorf("ImportKey(KAT): %w", err)
	}
	defer katKey.Destroy()
	katCT, err := katKey.Encrypt(SM4_ECB, nil, katPlain)
	if err != nil {
		return "", fmt.Errorf("KAT Encrypt: %w", err)
	}
	if !bytes.Equal(katCT, katWant) {
		return "", fmt.Errorf("SM4 ECB KAT = %x, want %x", katCT, katWant)
	}

	// CBC 对 stdlib cipher(已知会话密钥)。
	data, err := probeRand(48)
	if err != nil {
		return "", err
	}
	ct2, err := key.Encrypt(SM4_CBC, iv, data)
	if err != nil {
		return "", fmt.Errorf("Encrypt(CBC): %w", err)
	}
	blk, err := sm4.NewCipher(raw)
	if err != nil {
		return "", fmt.Errorf("sm4.NewCipher: %w", err)
	}
	ref := make([]byte, len(data))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ref, data)
	if !bytes.Equal(ct2, ref) {
		return "", fmt.Errorf("device CBC != stdlib: got %x, want %x", ct2, ref)
	}
	back2, err := key.Decrypt(SM4_CBC, iv, ref)
	if err != nil {
		return "", fmt.Errorf("Decrypt(CBC): %w", err)
	}
	if !bytes.Equal(back2, data) {
		return "", fmt.Errorf("CBC decrypt = %x, want %x", back2, data)
	}
	return "PKCS7 round trip; invalid padding rejected; ECB KAT; CBC vs stdlib", nil
}

// checkSymStream SM4_CFB/OFB/CTR 30 字节往返、长度不变。
func checkSymStream(c *probeCtx) (string, error) {
	key, _, err := c.sessionKey()
	if err != nil {
		return "", skipf("no session key: %v", err)
	}
	iv, err := probeRand(16)
	if err != nil {
		return "", err
	}
	data, err := probeRand(30)
	if err != nil {
		return "", err
	}
	for _, alg := range []ALGID{SM4_CFB, SM4_OFB, SM4_CTR} {
		ct, err := key.Encrypt(alg, iv, data)
		if err != nil {
			return "", fmt.Errorf("Encrypt(%#x): %w", uint32(alg), err)
		}
		if len(ct) != len(data) {
			return "", fmt.Errorf("Encrypt(%#x) len = %d, want %d", uint32(alg), len(ct), len(data))
		}
		back, err := key.Decrypt(alg, iv, ct)
		if err != nil {
			return "", fmt.Errorf("Decrypt(%#x): %w", uint32(alg), err)
		}
		if !bytes.Equal(back, data) {
			return "", fmt.Errorf("round trip mismatch for %#x", uint32(alg))
		}
	}
	return "CFB/OFB/CTR 30-byte round trips preserve length", nil
}

// checkSymMultipart 三块 Update+Final == 一步式;二次 Final/Update → SDR_STEPERR。
func checkSymMultipart(c *probeCtx) (string, error) {
	key, _, err := c.sessionKey()
	if err != nil {
		return "", skipf("no session key: %v", err)
	}
	iv, err := probeRand(16)
	if err != nil {
		return "", err
	}
	data, err := probeRand(48)
	if err != nil {
		return "", err
	}
	one, err := key.Encrypt(SM4_CBC, iv, data)
	if err != nil {
		return "", fmt.Errorf("Encrypt: %w", err)
	}
	enc, err := key.NewEncrypter(SM4_CBC, iv)
	if err != nil {
		return "", fmt.Errorf("NewEncrypter: %w", err)
	}
	var got []byte
	for _, sp := range [][2]int{{0, 7}, {7, 24}, {24, 48}} {
		part, err := enc.Update(data[sp[0]:sp[1]])
		if err != nil {
			return "", fmt.Errorf("Update: %w", err)
		}
		got = append(got, part...)
	}
	tail, err := enc.Final()
	if err != nil {
		return "", fmt.Errorf("Final: %w", err)
	}
	got = append(got, tail...)
	if !bytes.Equal(got, one) {
		return "", fmt.Errorf("multi-part != one-shot: got %x, want %x", got, one)
	}

	enc2, err := key.NewEncrypter(SM4_CBC, iv)
	if err != nil {
		return "", fmt.Errorf("NewEncrypter: %w", err)
	}
	if _, err := enc2.Update(data[:16]); err != nil {
		return "", fmt.Errorf("Update: %w", err)
	}
	if _, err := enc2.Final(); err != nil {
		return "", fmt.Errorf("Final: %w", err)
	}
	if _, err := enc2.Final(); !errors.Is(err, SDR_STEPERR) {
		return "", fmt.Errorf("double Final = %v, want SDR_STEPERR", err)
	}
	if _, err := enc2.Update(data[:16]); !errors.Is(err, SDR_STEPERR) {
		return "", fmt.Errorf("Update after Final = %v, want SDR_STEPERR", err)
	}
	return "multi-part == one-shot; double Final/Update SDR_STEPERR", nil
}

// checkMAC 已知密钥时:MAC == CBC-MAC 末块、MACM3 == ISO9797-M3 填充后 CBC-MAC。
func checkMAC(c *probeCtx) (string, error) {
	key, raw, err := c.sessionKey()
	if err != nil {
		return "", skipf("no session key: %v", err)
	}
	if raw == nil {
		return "", skipf("known session key required for MAC reference")
	}
	iv, err := probeRand(16)
	if err != nil {
		return "", err
	}
	data, err := probeRand(32)
	if err != nil {
		return "", err
	}
	mac, err := key.MAC(SM4_MAC, iv, data)
	if err != nil {
		return "", fmt.Errorf("MAC: %w", err)
	}
	want, err := cbcMacRef(raw, iv, data)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(mac, want) {
		return "", fmt.Errorf("MAC = %x, want CBC last block %x", mac, want)
	}
	padded := padding.NewISO9797M3Padding(uint(Sm4BlockSize)).Pad(data)
	mac3, err := key.MACM3(SM4_MAC, iv, data)
	if err != nil {
		return "", fmt.Errorf("MACM3: %w", err)
	}
	want3, err := cbcMacRef(raw, iv, padded)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(mac3, want3) {
		return "", fmt.Errorf("MACM3 = %x, want %x", mac3, want3)
	}
	return "MAC == CBC-MAC last block; MACM3 == ISO9797-M3 padded CBC-MAC", nil
}

// checkAEAD GCM 往返(密钥已知时对 stdlib GCM 比对 ct+tag)、篡改标签 →
// SDR_VERIFYERR;CCM 往返与篡改 AAD → SDR_VERIFYERR。
func checkAEAD(c *probeCtx) (string, error) {
	key, raw, err := c.sessionKey()
	if err != nil {
		return "", skipf("no session key: %v", err)
	}
	iv, err := probeRand(12)
	if err != nil {
		return "", err
	}
	aad, err := probeRand(13)
	if err != nil {
		return "", err
	}
	pt, err := probeRand(42)
	if err != nil {
		return "", err
	}
	ct, tag, err := key.AuthEncrypt(SM4_GCM, iv, aad, pt)
	if err != nil {
		return "", fmt.Errorf("AuthEncrypt(GCM): %w", err)
	}
	if len(tag) != 16 {
		return "", fmt.Errorf("tag len = %d, want 16", len(tag))
	}
	back, err := key.AuthDecrypt(SM4_GCM, iv, aad, ct, tag)
	if err != nil {
		return "", fmt.Errorf("AuthDecrypt(GCM): %w", err)
	}
	if !bytes.Equal(back, pt) {
		return "", fmt.Errorf("GCM round trip = %x, want %x", back, pt)
	}
	badTag := append([]byte(nil), tag...)
	badTag[0] ^= 0x01
	if _, err := key.AuthDecrypt(SM4_GCM, iv, aad, ct, badTag); !errors.Is(err, SDR_VERIFYERR) {
		return "", fmt.Errorf("tampered tag = %v, want SDR_VERIFYERR", err)
	}

	stdlibOK := false
	if raw != nil {
		blk, err := sm4.NewCipher(raw)
		if err != nil {
			return "", fmt.Errorf("sm4.NewCipher: %w", err)
		}
		gcm, err := cipher.NewGCM(blk)
		if err != nil {
			return "", fmt.Errorf("cipher.NewGCM: %w", err)
		}
		ref := gcm.Seal(nil, iv, pt, aad)
		refCT, refTag := ref[:len(pt)], ref[len(pt):]
		if !bytes.Equal(ct, refCT) {
			return "", fmt.Errorf("GCM ct != stdlib: got %x, want %x", ct, refCT)
		}
		if !bytes.Equal(tag, refTag) {
			return "", fmt.Errorf("GCM tag = %x, want %x", tag, refTag)
		}
		stdlibOK = true
	}

	// CCM 往返 + 篡改 AAD。
	ccmIV, err := probeRand(9)
	if err != nil {
		return "", err
	}
	ccmCT, ccmTag, err := key.AuthEncrypt(SM4_CCM, ccmIV, aad, pt)
	if err != nil {
		return "", fmt.Errorf("AuthEncrypt(CCM): %w", err)
	}
	ccmBack, err := key.AuthDecrypt(SM4_CCM, ccmIV, aad, ccmCT, ccmTag)
	if err != nil {
		return "", fmt.Errorf("AuthDecrypt(CCM): %w", err)
	}
	if !bytes.Equal(ccmBack, pt) {
		return "", fmt.Errorf("CCM round trip = %x, want %x", ccmBack, pt)
	}
	badAAD := append([]byte(nil), aad...)
	badAAD[0] ^= 0x01
	if _, err := key.AuthDecrypt(SM4_CCM, ccmIV, badAAD, ccmCT, ccmTag); !errors.Is(err, SDR_VERIFYERR) {
		return "", fmt.Errorf("tampered aad = %v, want SDR_VERIFYERR", err)
	}

	if stdlibOK {
		return "GCM matches stdlib (ct+tag); tamper rejected; CCM round trip", nil
	}
	return "GCM/CCM round trip; tamper rejected (KAT needs known key)", nil
}

// checkAEADMultipart Update 输出与 Final 拼接后 == 一步式、解密侧还原、
// 二次 Final → SDR_STEPERR。兼容缓冲型(Update 返回空)与流式设备。
func checkAEADMultipart(c *probeCtx) (string, error) {
	key, _, err := c.sessionKey()
	if err != nil {
		return "", skipf("no session key: %v", err)
	}
	iv, err := probeRand(12)
	if err != nil {
		return "", err
	}
	aad, err := probeRand(13)
	if err != nil {
		return "", err
	}
	pt, err := probeRand(42)
	if err != nil {
		return "", err
	}
	splits := [][2]int{{0, 7}, {7, 27}, {27, 42}}

	enc, err := key.NewAuthEncer(SM4_GCM, iv, aad, len(pt))
	if err != nil {
		return "", fmt.Errorf("NewAuthEncer: %w", err)
	}
	var encOut []byte
	for _, sp := range splits {
		part, err := enc.Update(pt[sp[0]:sp[1]])
		if err != nil {
			return "", fmt.Errorf("AuthEnc Update: %w", err)
		}
		encOut = append(encOut, part...)
	}
	last, tag, err := enc.Final()
	if err != nil {
		return "", fmt.Errorf("AuthEnc Final: %w", err)
	}
	encOut = append(encOut, last...)
	oneCT, oneTag, err := key.AuthEncrypt(SM4_GCM, iv, aad, pt)
	if err != nil {
		return "", fmt.Errorf("AuthEncrypt: %w", err)
	}
	if !bytes.Equal(encOut, oneCT) || !bytes.Equal(tag, oneTag) {
		return "", errors.New("multi-part GCM != one-shot")
	}
	if _, _, err := enc.Final(); !errors.Is(err, SDR_STEPERR) {
		return "", fmt.Errorf("double Final = %v, want SDR_STEPERR", err)
	}

	dec, err := key.NewAuthDecrypter(SM4_GCM, iv, aad, tag, len(oneCT))
	if err != nil {
		return "", fmt.Errorf("NewAuthDecrypter: %w", err)
	}
	var decOut []byte
	for _, sp := range splits {
		part, err := dec.Update(oneCT[sp[0]:sp[1]])
		if err != nil {
			return "", fmt.Errorf("AuthDec Update: %w", err)
		}
		decOut = append(decOut, part...)
	}
	plain, authOut, err := dec.Final()
	if err != nil {
		return "", fmt.Errorf("AuthDec Final: %w", err)
	}
	decOut = append(decOut, plain...)
	if authOut != nil {
		return "", errors.New("decrypt Final returned auth data, want nil")
	}
	if !bytes.Equal(decOut, pt) {
		return "", fmt.Errorf("multi-part decrypt = %x, want %x", decOut, pt)
	}
	return "multi-part == one-shot; decrypt restores; double Final SDR_STEPERR", nil
}

// checkFileOps 探测文件(带时间戳)的建/写/读/删往返,删后读 → SDR_FILENOEXIST。
func checkFileOps(c *probeCtx) (string, error) {
	name := fmt.Sprintf("gosdfprobe-%d.tmp", time.Now().UnixNano())
	defer func() { c.sess.DeleteFile(name) }() // 兜底删除

	data, err := probeRand(32)
	if err != nil {
		return "", err
	}
	if err := c.sess.CreateFile(name, 64); err != nil {
		return "", fmt.Errorf("CreateFile: %w", err)
	}
	if err := c.sess.WriteFile(name, 0, data); err != nil {
		return "", fmt.Errorf("WriteFile: %w", err)
	}
	got, err := c.sess.ReadFile(name, 0, 32)
	if err != nil {
		return "", fmt.Errorf("ReadFile: %w", err)
	}
	if !bytes.Equal(got, data) {
		return "", fmt.Errorf("ReadFile = %x, want %x", got, data)
	}
	if err := c.sess.DeleteFile(name); err != nil {
		return "", fmt.Errorf("DeleteFile: %w", err)
	}
	if _, err := c.sess.ReadFile(name, 0, 32); !errors.Is(err, SDR_FILENOEXIST) {
		return "", fmt.Errorf("read after delete = %v, want SDR_FILENOEXIST", err)
	}
	return "create/write/read/delete round trip; post-delete SDR_FILENOEXIST", nil
}
