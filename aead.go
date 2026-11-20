package gosdf

/*
#include "sdf.h"
*/
import "C"

import (
	"unsafe"
)

// AEAD startVar 长度约束(GCM:1..64,CCM:7..13)与缓冲上限(与设备一致)。
const (
	aeadMaxTotal    = 1 << 20 // 多步缓冲模型总量上限 1MiB
	aeadMaxAADMulti = 256     // 多步 AAD 上限(设备侧固定缓冲)
	aeadTagLen      = 16
)

// aeadAlgCheck 仅接受 GCM/CCM,否则 SDR_ALGMODNOTSUPPORT。
func aeadAlgCheck(alg ALGID, op string) error {
	if alg != SM4_GCM && alg != SM4_CCM {
		return rvErr(op, SDR_ALGMODNOTSUPPORT)
	}
	return nil
}

// aeadStartVarCheck 校验 StartVar(IV)长度:GCM 1..64,CCM 7..13。
func aeadStartVarCheck(alg ALGID, startVar []byte, op string) error {
	n := len(startVar)
	if alg == SM4_GCM {
		if n < 1 || n > 64 {
			return argErr(op)
		}
		return nil
	}
	if n < 7 || n > 13 {
		return argErr(op)
	}
	return nil
}

// AuthEncrypt 单步可鉴别加密(SDF_AuthEnc,GM/T 0018-2023 表13)。
// alg 仅接受 SM4_GCM/SM4_CCM(SDR_ALGMODNOTSUPPORT);startVar 长度
// GCM 1..64、CCM 7..13,否则 SDR_INARGERR;tag 固定 16 字节。
func (k *Key) AuthEncrypt(alg ALGID, startVar, aad, plaintext []byte) ([]byte, []byte, error) {
	const op = "SDF_AuthEnc"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, nil, err
	}
	if err := aeadAlgCheck(alg, op); err != nil {
		return nil, nil, err
	}
	if err := aeadStartVarCheck(alg, startVar, op); err != nil {
		return nil, nil, err
	}
	enc := make([]byte, len(plaintext))
	encLen := C.UINT32(len(enc))
	auth := make([]byte, aeadTagLen)
	authLen := C.UINT32(len(auth))
	if rv := C.auth_enc(ctx, sh, kh, C.UINT32(alg),
		bytePtr(startVar), C.UINT32(len(startVar)),
		bytePtr(aad), C.UINT32(len(aad)),
		bytePtr(plaintext), C.UINT32(len(plaintext)),
		bytePtr(enc), (*C.UINT32)(unsafe.Pointer(&encLen)),
		bytePtr(auth), (*C.UINT32)(unsafe.Pointer(&authLen))); rv != 0 {
		return nil, nil, rvErr(op, RV(rv))
	}
	if encLen != C.UINT32(len(enc)) || authLen != C.UINT32(len(auth)) {
		return nil, nil, rvErr(op, SDR_OUTARGERR)
	}
	return enc[:encLen], auth[:authLen], nil
}

// AuthDecrypt 单步可鉴别解密(SDF_AuthDec);标签或密文被篡改返回
// SDR_VERIFYERR。authData 必须为 16 字节,否则 SDR_INARGERR。
func (k *Key) AuthDecrypt(alg ALGID, startVar, aad, ciphertext, authData []byte) ([]byte, error) {
	const op = "SDF_AuthDec"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	if err := aeadAlgCheck(alg, op); err != nil {
		return nil, err
	}
	if err := aeadStartVarCheck(alg, startVar, op); err != nil {
		return nil, err
	}
	if len(authData) != aeadTagLen {
		return nil, argErr(op)
	}
	out := make([]byte, len(ciphertext))
	outLen := C.UINT32(len(out))
	if rv := C.auth_dec(ctx, sh, kh, C.UINT32(alg),
		bytePtr(startVar), C.UINT32(len(startVar)),
		bytePtr(aad), C.UINT32(len(aad)),
		bytePtr(authData), C.UINT32(len(authData)),
		bytePtr(ciphertext), C.UINT32(len(ciphertext)),
		bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	if outLen != C.UINT32(len(out)) {
		return nil, rvErr(op, SDR_OUTARGERR)
	}
	return out[:outLen], nil
}

// AuthCrypter 可鉴别加解密多步句柄(SDF_AuthEncInit/Update/Final 系列)。
// Init 声明 totalLen(上限 1MiB,超出 SDR_NOBUFFER);Update 返回设备本段输出
// (缓冲型设备返回空切片),Final 返回尾部密文/明文与标签;调用方按
// Update 输出 + Final 输出的顺序拼接。厂商 .so 缺少对应符号时构造返回
// SDR_NOTSUPPORT;Final 之后再调用返回 SDR_STEPERR。
type AuthCrypter struct {
	k       *Key
	role    int // cryptEnc / cryptDec
	total   int // Init 声明的总长度(Final 输出缓冲)
	acc     int // Update 已投递给设备的累计字节数
	started bool
	done    bool
}

// prefix 返回当前角色的操作名前缀。
func (c *AuthCrypter) prefix() string {
	if c == nil {
		return "SDF_Auth"
	}
	if c.role == cryptEnc {
		return "SDF_AuthEnc"
	}
	return "SDF_AuthDec"
}

// aeadInit 校验共用参数并调用对应的 Init。
func (k *Key) aeadInit(encrypt bool, alg ALGID, startVar, aad []byte,
	authData []byte, totalLen int, op string,
) (*AuthCrypter, error) {
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	if err := aeadAlgCheck(alg, op); err != nil {
		return nil, err
	}
	if err := aeadStartVarCheck(alg, startVar, op); err != nil {
		return nil, err
	}
	if totalLen < 0 {
		return nil, argErr(op)
	}
	if totalLen > aeadMaxTotal {
		return nil, rvErr(op, SDR_NOBUFFER)
	}
	if len(aad) > aeadMaxAADMulti {
		return nil, rvErr(op, SDR_NOBUFFER)
	}
	var rv C.RV
	if encrypt {
		rv = C.auth_enc_init(ctx, sh, kh, C.UINT32(alg),
			bytePtr(startVar), C.UINT32(len(startVar)),
			bytePtr(aad), C.UINT32(len(aad)), C.UINT32(totalLen))
	} else {
		if len(authData) != aeadTagLen {
			return nil, argErr(op)
		}
		rv = C.auth_dec_init(ctx, sh, kh, C.UINT32(alg),
			bytePtr(startVar), C.UINT32(len(startVar)),
			bytePtr(aad), C.UINT32(len(aad)),
			bytePtr(authData), C.UINT32(len(authData)), C.UINT32(totalLen))
	}
	if rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	role := cryptDec
	if encrypt {
		role = cryptEnc
	}
	return &AuthCrypter{k: k, role: role, total: totalLen, started: true}, nil
}

// NewAuthEncer 初始化多步可鉴别加密(SDF_AuthEncInit)。
// totalLen 为将要 Update 的数据总量(上限 1MiB)。
func (k *Key) NewAuthEncer(alg ALGID, startVar, aad []byte, totalLen int) (*AuthCrypter, error) {
	return k.aeadInit(true, alg, startVar, aad, nil, totalLen, "SDF_AuthEncInit")
}

// NewAuthDecrypter 初始化多步可鉴别解密(SDF_AuthDecInit);
// authData 为 16 字节标签,随 Init 传入设备。
func (k *Key) NewAuthDecrypter(alg ALGID, startVar, aad, authData []byte, totalLen int) (*AuthCrypter, error) {
	return k.aeadInit(false, alg, startVar, aad, authData, totalLen, "SDF_AuthDecInit")
}

// Update 追加数据并返回设备本段输出(缓冲型设备返回空切片,流式设备返回
// 本段密文/明文);Init 声明的总量超出时报 SDR_NOBUFFER。
// Final 之后调用返回 SDR_STEPERR。
func (c *AuthCrypter) Update(p []byte) ([]byte, error) {
	op := c.prefix() + "Update"
	if c == nil || !c.started || c.done {
		return nil, rvErr(op, SDR_STEPERR)
	}
	if c.acc+len(p) > c.total {
		return nil, rvErr(op, SDR_NOBUFFER)
	}
	ctx, sh, _, err := c.k.handles(op)
	if err != nil {
		return nil, err
	}
	// 输出缓冲按本段输入长度分配(另加一个标签长度的余量,避免空输入时
	// 传入零容量缓冲)。缓冲型设备 outLen 返回 0;流式设备返回本段输出。
	out := make([]byte, len(p)+aeadTagLen)
	outLen := C.UINT32(len(out))
	var rv C.RV
	if c.role == cryptEnc {
		rv = C.auth_enc_update(ctx, sh, bytePtr(p), C.UINT32(len(p)),
			bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	} else {
		rv = C.auth_dec_update(ctx, sh, bytePtr(p), C.UINT32(len(p)),
			bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	}
	if rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	if outLen > C.UINT32(len(out)) {
		return nil, rvErr(op, SDR_OUTARGERR)
	}
	c.acc += len(p)
	return out[:outLen], nil
}

// Final 结束运算并返回尾部输出:加密侧为 (尾部密文,标签),
// 解密侧为 (尾部明文,nil);标签验证失败返回 SDR_VERIFYERR。
// 调用方须与 Update 返回的各段输出按顺序拼接。之后再调用返回 SDR_STEPERR。
func (c *AuthCrypter) Final() ([]byte, []byte, error) {
	op := c.prefix() + "Final"
	if c == nil || !c.started || c.done {
		return nil, nil, rvErr(op, SDR_STEPERR)
	}
	ctx, sh, _, err := c.k.handles(op)
	if err != nil {
		return nil, nil, err
	}
	last := make([]byte, c.total)
	lastLen := C.UINT32(len(last))
	var rv C.RV
	if c.role == cryptEnc {
		auth := make([]byte, aeadTagLen)
		authLen := C.UINT32(len(auth))
		rv = C.auth_enc_final(ctx, sh, bytePtr(last),
			(*C.UINT32)(unsafe.Pointer(&lastLen)),
			bytePtr(auth), (*C.UINT32)(unsafe.Pointer(&authLen)))
		if rv != 0 {
			c.done = true
			return nil, nil, rvErr(op, RV(rv))
		}
		if lastLen > C.UINT32(len(last)) || authLen != C.UINT32(len(auth)) {
			c.done = true
			return nil, nil, rvErr(op, SDR_OUTARGERR)
		}
		c.done = true
		return last[:lastLen], auth[:authLen], nil
	}
	rv = C.auth_dec_final(ctx, sh, bytePtr(last),
		(*C.UINT32)(unsafe.Pointer(&lastLen)))
	if rv != 0 {
		c.done = true
		return nil, nil, rvErr(op, RV(rv))
	}
	if lastLen > C.UINT32(len(last)) {
		c.done = true
		return nil, nil, rvErr(op, SDR_OUTARGERR)
	}
	c.done = true
	return last[:lastLen], nil, nil
}
