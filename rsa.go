package gosdf

/*
#include "sdf.h"
*/
import "C"

import (
	"crypto/rsa"
	"math/big"
	"unsafe"
)

// 编译期断言:Go 镜像与 C 结构体布局逐字节一致(unsafe 转换的前提)。
var (
	_ [unsafe.Sizeof(rsaRefPublicKey{}) - unsafe.Sizeof(C.RSArefPublicKey{})]byte
	_ [unsafe.Sizeof(C.RSArefPublicKey{}) - unsafe.Sizeof(rsaRefPublicKey{})]byte
	_ [unsafe.Sizeof(rsaRefPrivateKey{}) - unsafe.Sizeof(C.RSArefPrivateKey{})]byte
	_ [unsafe.Sizeof(C.RSArefPrivateKey{}) - unsafe.Sizeof(rsaRefPrivateKey{})]byte
)

const (
	// rsaRefMinBits RSA 模数最小位长(标准实现下限 1024)。
	rsaRefMinBits uint32 = 1024
	// rsaMaxExponent 公钥指数上限,与 crypto/rsa 的校验一致(≤ 1<<31-1)。
	rsaMaxExponent = 1<<31 - 1
)

var bigOne = big.NewInt(1)

// checkRSABits 校验 RSA 模数位长:1024..2048(RSAref_MAX_BITS)且为 8 的倍数。
func checkRSABits(keyBits uint32, op string) error {
	if keyBits < rsaRefMinBits || keyBits > uint32(RSAref_MAX_BITS) || keyBits%8 != 0 {
		return argErr(op)
	}
	return nil
}

// rsaField 解码定长大端整数字段:全零或位宽超过 widthBits 报 SDR_INARGERR。
func rsaField(b []byte, widthBits uint32, op string) (*big.Int, error) {
	v := new(big.Int).SetBytes(b)
	if v.Sign() == 0 || uint32(v.BitLen()) > widthBits {
		return nil, argErr(op)
	}
	return v, nil
}

// rsaExponent 校验公钥指数:≥2 且 ≤1<<31-1(与 crypto/rsa checkPub 一致)。
func rsaExponent(v *big.Int, op string) error {
	if v.BitLen() < 2 || v.BitLen() > 31 {
		return argErr(op)
	}
	return nil
}

// ---- ABI 结构 ↔ crypto/rsa 转换 ----

// pubFromRSA 将 ABI 公钥结构转换为 *rsa.PublicKey。
// 校验:bits 为 1024..2048 的 8 的倍数;模数非零且位宽不超过 bits;指数合法。
func pubFromRSA(in *rsaRefPublicKey) (*rsa.PublicKey, error) {
	const op = "RSArefPublicKey"
	if in == nil {
		return nil, argErr(op)
	}
	if err := checkRSABits(in.Bits, op); err != nil {
		return nil, err
	}
	n, err := rsaField(in.M[:], in.Bits, op)
	if err != nil {
		return nil, err
	}
	e, err := rsaField(in.E[:], 31, op)
	if err != nil {
		return nil, err
	}
	if err := rsaExponent(e, op); err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// privFromRSA 将 ABI 私钥结构转换为 *rsa.PrivateKey。
// 字段映射:m=模数、e=公钥指数、d=私钥指数、prime=[P|Q]、pexp=[dP|dQ]、
// coef=[qInv](标准 CRT)。校验:bits 合法,各字段非零且位宽不超过对应上限,
// 否则报 SDR_INARGERR。crypto/rsa 的 CRT 值由 Precompute 从 D/P/Q 派生
// (与设备侧 dP/dQ/qInv 等价),故 pexp/coef 仅参与解码校验,不写入 Go 结构。
func privFromRSA(in *rsaRefPrivateKey) (*rsa.PrivateKey, error) {
	const op = "RSArefPrivateKey"
	if in == nil {
		return nil, argErr(op)
	}
	if err := checkRSABits(in.Bits, op); err != nil {
		return nil, err
	}
	n, err := rsaField(in.M[:], in.Bits, op)
	if err != nil {
		return nil, err
	}
	e, err := rsaField(in.E[:], 31, op)
	if err != nil {
		return nil, err
	}
	if err := rsaExponent(e, op); err != nil {
		return nil, err
	}
	d, err := rsaField(in.D[:], in.Bits, op)
	if err != nil {
		return nil, err
	}
	p, err := rsaField(in.Prime[0][:], uint32(RSAref_MAX_PBITS), op)
	if err != nil {
		return nil, err
	}
	q, err := rsaField(in.Prime[1][:], uint32(RSAref_MAX_PBITS), op)
	if err != nil {
		return nil, err
	}
	// crypto/rsa.Precompute 要求 p、q > 1 且互异:p=1 在旧版实现会触发
	// big.Int.Mod(x, 0) panic,p=q 会得到 nil qInv。这里提前拒绝退化参数。
	if p.Cmp(bigOne) <= 0 || q.Cmp(bigOne) <= 0 || p.Cmp(q) == 0 {
		return nil, argErr(op)
	}
	if _, err := rsaField(in.Pexp[0][:], uint32(RSAref_MAX_PBITS), op); err != nil {
		return nil, err
	}
	if _, err := rsaField(in.Pexp[1][:], uint32(RSAref_MAX_PBITS), op); err != nil {
		return nil, err
	}
	if _, err := rsaField(in.Coef[:], uint32(RSAref_MAX_PBITS), op); err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	priv.Precompute() // 从 D/P/Q 派生 CRT 值
	return priv, nil
}

// pubToRSA 校验并转换 *rsa.PublicKey 为 ABI 结构(模数/指数右对齐、左补零到定长)。
// 拒绝 nil/零模数、位宽超过 2048 或指数不在 2..1<<31-1 的公钥。
func pubToRSA(pub *rsa.PublicKey) (*rsaRefPublicKey, error) {
	const op = "RSArefPublicKey"
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 {
		return nil, argErr(op)
	}
	if pub.N.BitLen() > int(RSAref_MAX_BITS) || pub.E < 2 || pub.E > rsaMaxExponent {
		return nil, argErr(op)
	}
	var out rsaRefPublicKey
	out.Bits = uint32(pub.N.BitLen())
	if err := padLeft(out.M[:], pub.N.Bytes()); err != nil {
		return nil, err
	}
	if err := padLeft(out.E[:], big.NewInt(int64(pub.E)).Bytes()); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- RSA 密钥管理(GM/T 0018-2012 6.3;2023 表11/表16) ----

// ExportSignPublicKeyRSA 导出 keyIndex 对应的内部签名公钥
// (SDF_ExportSignPublicKey_RSA,GM/T 0018-2012 6.3.1~6.3.7 密钥管理类,2023 表11)。
func (s *Session) ExportSignPublicKeyRSA(keyIndex uint32) (*rsa.PublicKey, error) {
	const op = "SDF_ExportSignPublicKey_RSA"
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var pub rsaRefPublicKey
	if rv := C.export_sign_pubkey_rsa(ctx, h, C.UINT32(keyIndex),
		(*C.RSArefPublicKey)(unsafe.Pointer(&pub))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return pubFromRSA(&pub)
}

// ExportEncPublicKeyRSA 导出 keyIndex 对应的内部加密公钥
// (SDF_ExportEncPublicKey_RSA,GM/T 0018-2012 6.3.1~6.3.7 密钥管理类,2023 表11)。
func (s *Session) ExportEncPublicKeyRSA(keyIndex uint32) (*rsa.PublicKey, error) {
	const op = "SDF_ExportEncPublicKey_RSA"
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var pub rsaRefPublicKey
	if rv := C.export_enc_pubkey_rsa(ctx, h, C.UINT32(keyIndex),
		(*C.RSArefPublicKey)(unsafe.Pointer(&pub))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return pubFromRSA(&pub)
}

// GenerateKeyPairRSA 生成 RSA 密钥对,返回私钥(公钥经 priv.Public() 取得)。
// 属 GM/T 0018-2023 表16 验证调试类(2012 版 6.3.3 密钥管理类);
// 私钥以明文返回,仅适用于调试/测试场景。
// keyBits 须为 1024..2048 的 8 的倍数(RSAref_MAX_BITS=2048)。
func (s *Session) GenerateKeyPairRSA(keyBits uint32) (*rsa.PrivateKey, error) {
	const op = "SDF_GenerateKeyPair_RSA"
	if err := checkRSABits(keyBits, op); err != nil {
		return nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var pub rsaRefPublicKey
	var priv rsaRefPrivateKey
	rv := C.gen_keypair_rsa(ctx, h, C.UINT32(keyBits),
		(*C.RSArefPublicKey)(unsafe.Pointer(&pub)),
		(*C.RSArefPrivateKey)(unsafe.Pointer(&priv)))
	if rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return privFromRSA(&priv)
}

// GenerateKeyWithIPKRSA 生成会话密钥(长度 keyBits,64..256 位)并用 keyIndex
// 对应的内部加密公钥(RSA)包装,返回包装后的密文与可用会话密钥
// (返回形态同 GenerateKeyWithKEK;包装密文为设备定义的 RSA 数字信封格式)。
// SDF_GenerateKeyWithIPK_RSA,GM/T 0018-2012 6.3.1~6.3.7 密钥管理类,2023 表11。
func (s *Session) GenerateKeyWithIPKRSA(keyIndex, keyBits uint32) ([]byte, *Key, error) {
	const op = "SDF_GenerateKeyWithIPK_RSA"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, nil, err
	}
	buf := make([]byte, int(RSAref_MAX_LEN))
	keyLen := C.UINT32(len(buf)) // 入参为缓冲容量,出参为实际长度
	var kh HANDLE
	rv := C.gen_key_with_ipk_rsa(ctx, h, C.UINT32(keyIndex), C.UINT32(keyBits),
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

// GenerateKeyWithEPKRSA 生成会话密钥(长度 keyBits,64..256 位)并用外部公钥
// pub(RSA)包装,返回包装后的密文与可用会话密钥。
// SDF_GenerateKeyWithEPK_RSA,GM/T 0018-2012 6.3.1~6.3.7 密钥管理类,2023 表11。
func (s *Session) GenerateKeyWithEPKRSA(keyBits uint32, pub *rsa.PublicKey) ([]byte, *Key, error) {
	const op = "SDF_GenerateKeyWithEPK_RSA"
	if err := validateKeyBits(keyBits, op); err != nil {
		return nil, nil, err
	}
	rpub, err := pubToRSA(pub)
	if err != nil {
		return nil, nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, nil, err
	}
	buf := make([]byte, int(RSAref_MAX_LEN))
	keyLen := C.UINT32(len(buf)) // 入参为缓冲容量,出参为实际长度
	var kh HANDLE
	rv := C.gen_key_with_epk_rsa(ctx, h, C.UINT32(keyBits),
		(*C.RSArefPublicKey)(unsafe.Pointer(rpub)),
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

// ImportKeyWithISKRSA 导入被 keyIndex 内部加密私钥包装的 RSA 密钥(镜像 ImportKeyWithKEK)。
// wrapped 须为非空且不超过 RSAref_MAX_LEN(256) 字节的包装密文。
// SDF_ImportKeyWithISK_RSA,GM/T 0018-2012 6.3.1~6.3.7 密钥管理类,2023 表11。
func (s *Session) ImportKeyWithISKRSA(keyIndex uint32, wrapped []byte) (*Key, error) {
	const op = "SDF_ImportKeyWithISK_RSA"
	if len(wrapped) == 0 || len(wrapped) > int(RSAref_MAX_LEN) {
		return nil, argErr(op)
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	var kh HANDLE
	if rv := C.import_key_with_isk_rsa(ctx, h, C.UINT32(keyIndex),
		bytePtr(wrapped), C.UINT32(len(wrapped)),
		(**C.long)(unsafe.Pointer(&kh))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Key{s: s, h: kh}, nil
}

// ExchangeEnvelopeRSA 数字信封转换:基于 keyIndex 内部密钥与外部公钥 pub
// 对 envelope 重新包装,返回转换后的数字信封(GM/T 0018-2012 6.3.7;
// 2023 版已删除该函数,依赖可选符号,缺失时返回 SDR_NOTSUPPORT)。
// envelope 须为非空且不超过 RSAref_MAX_LEN(256) 字节。
func (s *Session) ExchangeEnvelopeRSA(keyIndex uint32, pub *rsa.PublicKey, envelope []byte) ([]byte, error) {
	const op = "SDF_ExchangeDigitEnvelopeBaseOnRSA"
	if len(envelope) == 0 || len(envelope) > int(RSAref_MAX_LEN) {
		return nil, argErr(op)
	}
	rpub, err := pubToRSA(pub)
	if err != nil {
		return nil, err
	}
	ctx, h, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	out := make([]byte, int(RSAref_MAX_LEN))
	outLen := C.UINT32(len(out))
	if rv := C.exchange_envelope_rsa(ctx, h, C.UINT32(keyIndex),
		(*C.RSArefPublicKey)(unsafe.Pointer(rpub)),
		bytePtr(envelope), C.UINT32(len(envelope)),
		bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	if outLen > C.UINT32(len(out)) { // 防御设备返回越界长度
		outLen = C.UINT32(len(out))
	}
	return out[:outLen], nil
}
