package gosdf

/*
#include "sdf.h"
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"github.com/emmansun/gmsm/sm2"
)

// 默认用户ID,用于 SM2 ZA 值计算(GB/T 32918.1)
var defaultID = []byte("1234567812345678")

// ECCCipher ABI 布局(本机字节序):X[64] Y[64] M[32] L(u32) C[L]
const (
	eccCipherXOff = 0
	eccCipherYOff = 64
	eccCipherMOff = 128
	eccCipherLOff = 160
	eccCipherCOff = 164
)

// ---- 编解码(ABI 定长数组 ↔ ASN.1 DER,一律左补零到定长) ----

type sm2SignatureASN1 struct {
	R, S *big.Int
}

type sm2CipherASN1 struct {
	X, Y       *big.Int
	HASH       []byte
	CipherText []byte
}

// sigECCtoDER 将 64 字节 R||S 签名转为 ASN.1 DER(SEQUENCE{R,S INTEGER})。
func sigECCtoDER(sig *eccSignature) ([]byte, error) {
	return asn1.Marshal(sm2SignatureASN1{
		R: new(big.Int).SetBytes(sig.R[:]),
		S: new(big.Int).SetBytes(sig.S[:]),
	})
}

// sigDERtoECC 将 ASN.1 DER 签名转为 64 字节 R||S(右对齐、左补零)。
func sigDERtoECC(der []byte) (*eccSignature, error) {
	var v sm2SignatureASN1
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return nil, fmt.Errorf("gosdf: SM2 signature decode: %w", err)
	}
	if len(rest) != 0 || v.R == nil || v.S == nil || v.R.Sign() <= 0 || v.S.Sign() <= 0 {
		return nil, errors.New("gosdf: SM2 signature decode: invalid R/S")
	}
	var sig eccSignature
	if err := padLeft(sig.R[:], v.R.Bytes()); err != nil {
		return nil, err
	}
	if err := padLeft(sig.S[:], v.S.Bytes()); err != nil {
		return nil, err
	}
	return &sig, nil
}

// eccCipherContentLen 读取 ABI 缓冲中 ECCCipher.L(密文内容长度)。
func eccCipherContentLen(buf []byte) int {
	if len(buf) < eccCipherCOff {
		return 0
	}
	return int(binary.NativeEndian.Uint32(buf[eccCipherLOff:eccCipherCOff]))
}

// cipherECCtoDER 将 ECCCipher ABI 缓冲转为 GB/T 35275 ASN.1 DER。
func cipherECCtoDER(buf []byte) ([]byte, error) {
	if len(buf) < eccCipherCOff {
		return nil, argErr("ECCCipher")
	}
	l := eccCipherContentLen(buf)
	if l < 0 || l > len(buf)-eccCipherCOff {
		return nil, argErr("ECCCipher")
	}
	v := sm2CipherASN1{
		X:          new(big.Int).SetBytes(buf[eccCipherXOff:eccCipherYOff]),
		Y:          new(big.Int).SetBytes(buf[eccCipherYOff:eccCipherMOff]),
		HASH:       append([]byte(nil), buf[eccCipherMOff:eccCipherLOff]...),
		CipherText: append([]byte(nil), buf[eccCipherCOff:eccCipherCOff+l]...),
	}
	out, err := asn1.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("gosdf: SM2 cipher encode: %w", err)
	}
	return out, nil
}

// cipherDERtoECC 将 GB/T 35275 DER 转为 ECCCipher ABI 缓冲(含柔性数组,按需读取 L)。
// 校验 HASH 必须 32 字节、密文不超过 ECCCipher.C 容量。
func cipherDERtoECC(der []byte) ([]byte, error) {
	var v sm2CipherASN1
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return nil, fmt.Errorf("gosdf: SM2 cipher decode: %w", err)
	}
	if len(rest) != 0 || v.X == nil || v.Y == nil {
		return nil, errors.New("gosdf: SM2 cipher decode: invalid structure")
	}
	if v.X.Sign() < 0 || v.Y.Sign() < 0 { // 负坐标 Bytes() 取绝对值会静默翻正
		return nil, errors.New("gosdf: SM2 cipher decode: invalid structure")
	}
	if len(v.HASH) != Sm3HashSize || len(v.CipherText) > int(ECCref_MAX_CIPHER_LEN) {
		return nil, argErr("ECCCipher")
	}
	buf := newCipherBuf(len(v.CipherText))
	if err := padLeft(buf[eccCipherXOff:eccCipherYOff], v.X.Bytes()); err != nil {
		return nil, err
	}
	if err := padLeft(buf[eccCipherYOff:eccCipherMOff], v.Y.Bytes()); err != nil {
		return nil, err
	}
	copy(buf[eccCipherMOff:eccCipherLOff], v.HASH)
	binary.NativeEndian.PutUint32(buf[eccCipherLOff:eccCipherCOff], uint32(len(v.CipherText)))
	copy(buf[eccCipherCOff:], v.CipherText)
	return buf, nil
}

// pubToECC 校验并转换 SM2 公钥为 ABI 结构(curve 必须为 sm2.P256() 且点在曲线上)。
func pubToECC(pub *ecdsa.PublicKey) (*eccRefPublicKey, error) {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return nil, argErr("ECCrefPublicKey")
	}
	if pub.Curve != sm2.P256() || pub.Curve.Params().BitSize != 256 || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, argErr("ECCrefPublicKey")
	}
	var out eccRefPublicKey
	out.Bits = 256
	if err := padLeft(out.X[:], pub.X.Bytes()); err != nil {
		return nil, err
	}
	if err := padLeft(out.Y[:], pub.Y.Bytes()); err != nil {
		return nil, err
	}
	return &out, nil
}

// pubFromECC 将 ABI 公钥结构转换为 SM2 *ecdsa.PublicKey。
func pubFromECC(in *eccRefPublicKey) (*ecdsa.PublicKey, error) {
	if in == nil || in.Bits != 256 {
		return nil, argErr("ECCrefPublicKey")
	}
	pub := &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     new(big.Int).SetBytes(in.X[:]),
		Y:     new(big.Int).SetBytes(in.Y[:]),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, argErr("ECCrefPublicKey")
	}
	return pub, nil
}

// privFromECC 将 ABI 公私钥结构转换为 SM2 *ecdsa.PrivateKey(公钥部分经 pubFromECC 校验)。
func privFromECC(pubIn *eccRefPublicKey, privIn *eccRefPrivateKey) (*ecdsa.PrivateKey, error) {
	if privIn == nil || privIn.Bits != 256 {
		return nil, argErr("ECCrefPrivateKey")
	}
	pub, err := pubFromECC(pubIn)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(privIn.K[:])
	if d.Sign() <= 0 || d.Cmp(pub.Curve.Params().N) >= 0 {
		return nil, argErr("ECCrefPrivateKey")
	}
	return &ecdsa.PrivateKey{PublicKey: *pub, D: d}, nil
}

// ---- SM2 签名(crypto.Signer) ----

// SM2SignerOptions 用于 SignerKey.Sign:指定 SM2 用户 ID,
// 此时 digest 参数按原始消息处理(设备端做 ZA+SM3 预处理)。
type SM2SignerOptions struct {
	UID []byte
}

// HashFunc 返回 0:SM2 摘要由设备端 ZA+SM3 计算,不使用 crypto.Hash。
func (o *SM2SignerOptions) HashFunc() crypto.Hash { return 0 }

// SignerKey 设备内部 SM2 签名私钥,实现 crypto.Signer。
// 调用方须先 AcquireKeyRight(keyIndex, pin)、用完 ReleaseKeyRight;
// rand 参数被忽略(签名随机数由设备产生)。
type SignerKey struct {
	s        *Session
	keyIndex uint32
	pub      *ecdsa.PublicKey
}

// NewSignerKey 导出 keyIndex 对应的内部签名公钥并构造签名器。
func (s *Session) NewSignerKey(keyIndex uint32) (*SignerKey, error) {
	pub, err := s.ExportSignPublicKey(keyIndex)
	if err != nil {
		return nil, err
	}
	return &SignerKey{s: s, keyIndex: keyIndex, pub: pub}, nil
}

// Public 返回签名公钥(*ecdsa.PublicKey,Curve = sm2.P256())。
func (k *SignerKey) Public() crypto.PublicKey { return k.pub }

// Sign 实现 crypto.Signer:
//   - opts == nil 或 opts.HashFunc() != 0:digest 为已预处理的 32 字节 e;
//   - opts 为 *SM2SignerOptions:digest 为原始消息,设备端做 ZA+SM3 预处理;
//   - 其它 HashFunc()==0 的 opts(如 gmsm sm2.SM2SignerOption,uid 不可导出)不支持。
//
// 返回 ASN.1 DER 签名;rand 被忽略,随机数由设备产生。
func (k *SignerKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	const op = "SDF_InternalSign_ECC"
	if opts == nil || opts.HashFunc() != 0 {
		if len(digest) != Sm3HashSize {
			return nil, argErr(op)
		}
		return k.signDigest(digest)
	}
	if o, ok := opts.(*SM2SignerOptions); ok {
		var uid []byte
		if o != nil { // typed-nil 视为未带 UID 选项(默认用户 ID),不 panic 不报错
			uid = o.UID
		}
		hash, err := k.s.SM2Digest(k.pub, uid, digest)
		if err != nil {
			return nil, err
		}
		return k.signDigest(hash)
	}
	return nil, errors.New("gosdf: unsupported SignerOpts, use gosdf.SM2SignerOptions")
}

// signDigest 对 32 字节摘要做内部私钥签名,返回 DER。
func (k *SignerKey) signDigest(e []byte) ([]byte, error) {
	const op = "SDF_InternalSign_ECC"
	ctx, h, err := k.s.handles(op)
	if err != nil {
		return nil, err
	}
	var sig eccSignature
	if rv := C.internal_sign_ecc(ctx, h, C.UINT32(k.keyIndex),
		bytePtr(e), C.UINT32(len(e)),
		(*C.ECCSignature)(unsafe.Pointer(&sig))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return sigECCtoDER(&sig)
}

// VerifySM2Digest 验证预处理后摘要上的 SM2 外部签名(输入 DER)。
// 验签失败时设备返回 SDR_VERIFYERR。
func (s *Session) VerifySM2Digest(pub *ecdsa.PublicKey, digest, sig []byte) error {
	const op = "SDF_ExternalVerify_ECC"
	if len(digest) != Sm3HashSize {
		return argErr(op)
	}
	epub, err := pubToECC(pub)
	if err != nil {
		return err
	}
	esig, err := sigDERtoECC(sig)
	if err != nil {
		return err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return err
	}
	if rv := C.external_verify_ecc(ctx, h, C.UINT32(SGD_SM2_1),
		(*C.ECCrefPublicKey)(unsafe.Pointer(epub)),
		bytePtr(digest), C.UINT32(len(digest)),
		(*C.ECCSignature)(unsafe.Pointer(esig))); rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}

// VerifySM2 对原始消息做 ZA+SM3 预处理后验签(uid 为空用默认用户 ID)。
func (s *Session) VerifySM2(pub *ecdsa.PublicKey, uid, message, sig []byte) error {
	digest, err := s.SM2Digest(pub, uid, message)
	if err != nil {
		return err
	}
	return s.VerifySM2Digest(pub, digest, sig)
}

// VerifySM2Internal 用 keyIndex 对应内部公钥验证摘要签名(输入 DER)。
func (s *Session) VerifySM2Internal(keyIndex uint32, digest, sig []byte) error {
	const op = "SDF_InternalVerify_ECC"
	if len(digest) != Sm3HashSize {
		return argErr(op)
	}
	esig, err := sigDERtoECC(sig)
	if err != nil {
		return err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return err
	}
	if rv := C.internal_verify_ecc(ctx, h, C.UINT32(keyIndex),
		bytePtr(digest), C.UINT32(len(digest)),
		(*C.ECCSignature)(unsafe.Pointer(esig))); rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}

// ---- SM2 加解密与密钥包装(密文/包装密钥均为 GB/T 35275 ASN.1 DER) ----

// SM2Encrypt 使用公钥加密,返回 GB/T 35275 ASN.1 DER 密文。
func (s *Session) SM2Encrypt(pub *ecdsa.PublicKey, message []byte) ([]byte, error) {
	const op = "SDF_ExternalEncrypt_ECC"
	epub, err := pubToECC(pub)
	if err != nil {
		return nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	capExtra := len(message)
	if capExtra < int(ECCref_MAX_CIPHER_LEN) {
		// ECCCipher 的 C 容量不由 SDF_ExternalEncrypt_ECC 的原型传入;
		// 按 136 字节下限分配,兼容以固定长度写 C 的设备。
		capExtra = int(ECCref_MAX_CIPHER_LEN)
	}
	buf := newCipherBuf(capExtra)
	if rv := C.external_encrypt_ecc(ctx, h, C.UINT32(SGD_SM2_3),
		(*C.ECCrefPublicKey)(unsafe.Pointer(epub)),
		bytePtr(message), C.UINT32(len(message)),
		unsafe.Pointer(bytePtr(buf)), C.UINT32(len(buf))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return cipherECCtoDER(buf)
}

// validateKeyBits 校验会话密钥长度:64~256 且为 8 的倍数。
func validateKeyBits(keyBits uint32, op string) error {
	if keyBits < 64 || keyBits > 256 || keyBits%8 != 0 {
		return argErr(op)
	}
	return nil
}

// GenerateKeyWithIPK 生成会话密钥并用 keyIndex 内部加密公钥包装,
// 返回 DER 包装密钥与可用会话密钥。
func (s *Session) GenerateKeyWithIPK(keyIndex, keyBits uint32) ([]byte, *Key, error) {
	const op = "SDF_GenerateKeyWithIPK_ECC"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, nil, err
	}
	buf := newCipherBuf(int(ECCref_MAX_CIPHER_LEN))
	var kh HANDLE
	rv := C.gen_key_with_ipk_ecc(ctx, h, C.UINT32(keyIndex), C.UINT32(keyBits),
		unsafe.Pointer(bytePtr(buf)), C.UINT32(len(buf)), (**C.long)(unsafe.Pointer(&kh)))
	if rv != 0 {
		return nil, nil, rvErr(op, RV(rv))
	}
	der, err := cipherECCtoDER(buf)
	if err != nil {
		// 解析失败时销毁设备侧已生成的密钥,避免句柄泄漏
		C.destroy_key(ctx, h, (*C.long)(unsafe.Pointer(kh)))
		return nil, nil, err
	}
	return der, &Key{s: s, h: kh}, nil
}

// GenerateKeyWithEPK 生成会话密钥并用外部公钥(pub)包装,返回 DER 包装密钥与会话密钥。
func (s *Session) GenerateKeyWithEPK(keyBits uint32, pub *ecdsa.PublicKey) ([]byte, *Key, error) {
	const op = "SDF_GenerateKeyWithEPK_ECC"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, nil, err
	}
	epub, err := pubToECC(pub)
	if err != nil {
		return nil, nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, nil, err
	}
	buf := newCipherBuf(int(ECCref_MAX_CIPHER_LEN))
	var kh HANDLE
	rv := C.gen_key_with_epk_ecc(ctx, h, C.UINT32(keyBits), C.UINT32(SGD_SM2_3),
		(*C.ECCrefPublicKey)(unsafe.Pointer(epub)),
		unsafe.Pointer(bytePtr(buf)), C.UINT32(len(buf)), (**C.long)(unsafe.Pointer(&kh)))
	if rv != 0 {
		return nil, nil, rvErr(op, RV(rv))
	}
	der, err := cipherECCtoDER(buf)
	if err != nil {
		C.destroy_key(ctx, h, (*C.long)(unsafe.Pointer(kh)))
		return nil, nil, err
	}
	return der, &Key{s: s, h: kh}, nil
}

// ImportKeyWithISK 导入被 keyIndex 内部加密私钥包装的 DER 密钥。
// SM2 私钥解密不在标准中(GMT 0018 2012/2023 两版均无 InternalDecrypt_ECC):
// 标准模型是会话密钥 + 非对称封装(GenerateKeyWithIPK/GenerateKeyWithEPK →
// ImportKeyWithISK_ECC),不提供内部私钥解密接口。
func (s *Session) ImportKeyWithISK(keyIndex uint32, wrapped []byte) (*Key, error) {
	const op = "SDF_ImportKeyWithISK_ECC"
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	cbuf, err := cipherDERtoECC(wrapped)
	if err != nil {
		return nil, err
	}
	var kh HANDLE
	if rv := C.import_key_with_isk_ecc(ctx, h, C.UINT32(keyIndex),
		unsafe.Pointer(bytePtr(cbuf)), C.UINT32(len(cbuf)),
		(**C.long)(unsafe.Pointer(&kh))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Key{s: s, h: kh}, nil
}

// ---- 密钥对生成与数字信封交换(密钥管理类) ----

// GenerateKeyPairECC 生成 ECC 密钥对,返回 *ecdsa.PrivateKey(Curve = sm2.P256())。
// SDF_GenerateKeyPair_ECC 为 2023 表16 验证调试类函数(2012 版属密钥管理类 6.3.10):
// 私钥会明文导出到调用方,仅适用于调试/测试;生产路径应使用
// GenerateKeyWithIPK/GenerateKeyWithEPK 会话密钥数字信封。
// 依赖可选符号,缺失时返回 SDR_NOTSUPPORT。
func (s *Session) GenerateKeyPairECC(alg ALGID, keyBits uint32) (*ecdsa.PrivateKey, error) {
	const op = "SDF_GenerateKeyPair_ECC"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var pub eccRefPublicKey
	var priv eccRefPrivateKey
	if rv := C.gen_keypair_ecc(ctx, h, C.UINT32(alg), C.UINT32(keyBits),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pub)),
		(*C.ECCrefPrivateKey)(unsafe.Pointer(&priv))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return privFromECC(&pub, &priv)
}

// ExchangeEnvelopeECC 用 keyIndex 对应内部私钥对数字信封重新封装,返回 DER 密文。
// envelope 为 GB/T 35275 ASN.1 DER 编码的 ECCCipher,输出同格式。
// 2012 版密钥管理类 6.3.17 函数,2023 版已删除;依赖可选符号
// SDF_ExchangeDigitEnvelopeBaseOnECC,缺失时返回 SDR_NOTSUPPORT。
// 输入信封必须是内部加密公钥(GenerateKeyWithIPK 产物)加密的信封;外部公钥(EPK)
// 信封输入将返回 SDR_SKOPERR(GM/T 0018 §6.3.17)。设备无法自校验信封来源,
// 调用方须保证输入正确。
func (s *Session) ExchangeEnvelopeECC(keyIndex uint32, alg ALGID, pub *ecdsa.PublicKey, envelope []byte) ([]byte, error) {
	const op = "SDF_ExchangeDigitEnvelopeBaseOnECC"
	epub, err := pubToECC(pub)
	if err != nil {
		return nil, err
	}
	inBuf, err := cipherDERtoECC(envelope)
	if err != nil {
		return nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	outBuf := newCipherBuf(int(ECCref_MAX_CIPHER_LEN))
	if rv := C.exchange_envelope_ecc(ctx, h, C.UINT32(keyIndex), C.UINT32(alg),
		(*C.ECCrefPublicKey)(unsafe.Pointer(epub)),
		unsafe.Pointer(bytePtr(inBuf)), C.UINT32(len(inBuf)),
		unsafe.Pointer(bytePtr(outBuf)), C.UINT32(len(outBuf))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return cipherECCtoDER(outBuf)
}

// ---- SM2 密钥协商(2023 表11 6.3.12~6.3.14) ----

// AgreementHandle SM2 密钥协商中间句柄。标准未提供销毁接口:
// GenerateKeyWithECC 成功后句柄即被设备消费,失败时由设备侧回收,Go 不再持有。
type AgreementHandle struct {
	s *Session
	h HANDLE
}

// GenerateAgreementDataWithECC 协商发起方第一步:生成发起方长期公钥、临时公钥与协商句柄。
func (s *Session) GenerateAgreementDataWithECC(keyIndex, keyBits uint32, sponsorID []byte) (*AgreementHandle, *ecdsa.PublicKey, *ecdsa.PublicKey, error) {
	const op = "SDF_GenerateAgreementDataWithECC"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, nil, nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, nil, nil, err
	}
	var sponsorPub, sponsorTmpPub eccRefPublicKey
	var ah HANDLE
	rv := C.gen_agreement_data_with_ecc(ctx, h, C.UINT32(keyIndex), C.UINT32(keyBits),
		bytePtr(sponsorID), C.UINT32(len(sponsorID)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&sponsorPub)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&sponsorTmpPub)),
		(**C.long)(unsafe.Pointer(&ah)))
	if rv != 0 {
		return nil, nil, nil, rvErr(op, RV(rv))
	}
	pub1, err := pubFromECC(&sponsorPub)
	if err != nil {
		return nil, nil, nil, err
	}
	pub2, err := pubFromECC(&sponsorTmpPub)
	if err != nil {
		return nil, nil, nil, err
	}
	return &AgreementHandle{s: s, h: ah}, pub1, pub2, nil
}

// GenerateKeyWithECC 协商发起方第二步:用响应方公钥计算会话密钥。
// 成功后 ah 即被设备消费;调用前校验失败时句柄仍由 Go 持有,可重试。
func (s *Session) GenerateKeyWithECC(ah *AgreementHandle, responseID []byte, responsePub, responseTmpPub *ecdsa.PublicKey) (*Key, error) {
	const op = "SDF_GenerateKeyWithECC"
	if ah == nil || ah.h == nil {
		return nil, argErr(op)
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	rpub, err := pubToECC(responsePub)
	if err != nil {
		return nil, err
	}
	rtmp, err := pubToECC(responseTmpPub)
	if err != nil {
		return nil, err
	}
	var kh HANDLE
	rv := C.gen_key_with_ecc(ctx, h,
		bytePtr(responseID), C.UINT32(len(responseID)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(rpub)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(rtmp)),
		(*C.long)(unsafe.Pointer(ah.h)), (**C.long)(unsafe.Pointer(&kh)))
	ah.h = nil // 无论成败,句柄不再由 Go 持有
	if rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Key{s: s, h: kh}, nil
}

// GenerateAgreementDataAndKeyWithECC 一步式协商:由响应方调用,以本端 ISK 与
// 发起方传来的协商参数(sponsorID、发起方长期公钥、临时公钥)直接计算会话密钥,
// 返回本端响应方长期公钥、临时公钥(需发送给发起方)与会话密钥句柄。
func (s *Session) GenerateAgreementDataAndKeyWithECC(keyIndex, keyBits uint32, sponsorID, responseID []byte, responsePub, responseTmpPub *ecdsa.PublicKey) (*ecdsa.PublicKey, *ecdsa.PublicKey, *Key, error) {
	const op = "SDF_GenerateAgreementDataAndKeyWithECC"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, nil, nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, nil, nil, err
	}
	rpub, err := pubToECC(responsePub)
	if err != nil {
		return nil, nil, nil, err
	}
	rtmp, err := pubToECC(responseTmpPub)
	if err != nil {
		return nil, nil, nil, err
	}
	var sponsorPub, sponsorTmpPub eccRefPublicKey
	var kh HANDLE
	rv := C.gen_agreement_data_and_key_with_ecc(ctx, h, C.UINT32(keyIndex), C.UINT32(keyBits),
		bytePtr(responseID), C.UINT32(len(responseID)),
		bytePtr(sponsorID), C.UINT32(len(sponsorID)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&sponsorPub)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&sponsorTmpPub)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(rpub)),
		(*C.ECCrefPublicKey)(unsafe.Pointer(rtmp)),
		(**C.long)(unsafe.Pointer(&kh)))
	if rv != 0 {
		return nil, nil, nil, rvErr(op, RV(rv))
	}
	pub1, err := pubFromECC(&sponsorPub)
	if err == nil {
		var pub2 *ecdsa.PublicKey
		if pub2, err = pubFromECC(&sponsorTmpPub); err == nil {
			return pub1, pub2, &Key{s: s, h: kh}, nil
		}
	}
	// 公钥解析失败时销毁已生成的会话密钥,避免句柄泄漏
	C.destroy_key(ctx, h, (*C.long)(unsafe.Pointer(kh)))
	return nil, nil, nil, err
}

// ---- 导出公钥 ----

// ExportSignPublicKey 导出 keyIndex 对应的内部签名公钥。
func (s *Session) ExportSignPublicKey(keyIndex uint32) (*ecdsa.PublicKey, error) {
	const op = "SDF_ExportSignPublicKey_ECC"
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var pub eccRefPublicKey
	if rv := C.export_sign_pubkey_ecc(ctx, h, C.UINT32(keyIndex),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pub))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return pubFromECC(&pub)
}

// ExportEncPublicKey 导出 keyIndex 对应的内部加密公钥。
func (s *Session) ExportEncPublicKey(keyIndex uint32) (*ecdsa.PublicKey, error) {
	const op = "SDF_ExportEncPublicKey_ECC"
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var pub eccRefPublicKey
	if rv := C.export_enc_pubkey_ecc(ctx, h, C.UINT32(keyIndex),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pub))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return pubFromECC(&pub)
}
