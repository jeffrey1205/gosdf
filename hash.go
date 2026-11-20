package gosdf

/*
#include "sdf.h"
*/
import "C"

import (
	"crypto/ecdsa"
	"unsafe"
)

// Hasher 设备杂凑多步运算句柄(普通杂凑 SDF_Hash* 与带密钥杂凑 SDF_HMAC*)。
// 初始化失败的错误在 Update/Final 时原样返回;Final 之后再调用返回 SDR_STEPERR。
type Hasher struct {
	s       *Session
	key     *Key  // 带密钥杂凑(SDF_HMACInit)的密钥;nil 表示普通杂凑
	err     error // HashInit/HMACInit 失败时保存,后续调用原样返回
	started bool  // Init 是否已成功
	done    bool
}

// NewHash 初始化杂凑运算(普通杂凑,不做 ZA 预处理)。
// alg 仅接受 SGD_SM3/SGD_SHA256;HMAC 类标识(SGD_SM3_HMAC/SGD_SHA256_HMAC)
// 或其他值不被接受,错误延迟到 Update/Final 返回 SDR_ALGNOTSUPPORT。
// (2012 时代 .so 上 0x08/0x10 被厂商定义为 SHA-512/SHA-384,放行会静默错配算法。)
func (s *Session) NewHash(alg ALGID) *Hasher {
	const op = "SDF_HashInit"
	h := &Hasher{s: s}
	ctx, sh, err := s.handles(op)
	if err != nil {
		h.err = err
		return h
	}
	if !hashAlgOK(alg) {
		h.err = rvErr(op, SDR_ALGNOTSUPPORT)
		return h
	}
	if rv := C.hash_init(ctx, sh, C.UINT32(alg), nil, nil, 0); rv != 0 {
		h.err = rvErr(op, RV(rv))
		return h
	}
	h.started = true
	return h
}

// NewSM2ZAHash 初始化 SM2 ZA 值杂凑(GB/T 32918.1)。
// pub 为签名/验签公钥(SM2 曲线);uid 为空时使用默认用户 ID "1234567812345678"。
func (s *Session) NewSM2ZAHash(pub *ecdsa.PublicKey, uid []byte) (*Hasher, error) {
	const op = "SDF_HashInit"
	if pub == nil {
		return nil, argErr(op)
	}
	epub, err := pubToECC(pub)
	if err != nil {
		return nil, err
	}
	if len(uid) == 0 {
		uid = defaultID
	}
	ctx, sh, err := s.handles(op)
	if err != nil {
		return nil, err
	}
	if rv := C.hash_init(ctx, sh, C.UINT32(SGD_SM3),
		(*C.ECCrefPublicKey)(unsafe.Pointer(epub)),
		bytePtr(uid), C.UINT32(len(uid))); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Hasher{s: s, started: true}, nil
}

// op 返回当前运算的 SDF 操作名(带密钥杂凑为 SDF_HMAC*,普通杂凑为 SDF_Hash*)。
func (h *Hasher) op(method string) string {
	if h.key != nil {
		return "SDF_HMAC" + method
	}
	return "SDF_Hash" + method
}

// Update 追加杂凑数据。
func (h *Hasher) Update(p []byte) error {
	if h.err != nil {
		return h.err
	}
	op := h.op("Update")
	if !h.started || h.done {
		return rvErr(op, SDR_STEPERR)
	}
	ctx, sh, err := h.s.handles(op)
	if err != nil {
		return err
	}
	var rv C.RV
	if h.key != nil {
		rv = C.hmac_update(ctx, sh, bytePtr(p), C.UINT32(len(p)))
	} else {
		rv = C.hash_update(ctx, sh, bytePtr(p), C.UINT32(len(p)))
	}
	if rv != 0 {
		return rvErr(op, RV(rv))
	}
	return nil
}

// Final 输出杂凑值,之后 Update/Final 返回 SDR_STEPERR。
func (h *Hasher) Final() ([]byte, error) {
	if h.err != nil {
		return nil, h.err
	}
	op := h.op("Final")
	if !h.started || h.done {
		return nil, rvErr(op, SDR_STEPERR)
	}
	ctx, sh, err := h.s.handles(op)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	outLen := C.UINT32(64)
	var rv C.RV
	if h.key != nil {
		rv = C.hmac_final(ctx, sh, bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	} else {
		rv = C.hash_final(ctx, sh, bytePtr(out), (*C.UINT32)(unsafe.Pointer(&outLen)))
	}
	if rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	h.done = true
	if outLen > C.UINT32(len(out)) { // 防御设备返回越界长度
		outLen = C.UINT32(len(out))
	}
	return out[:outLen], nil
}

// hashAlgOK 普通杂凑(SDF_HashInit)仅支持 SGD_SM3/SGD_SHA256。
func hashAlgOK(alg ALGID) bool {
	return alg == SGD_SM3 || alg == SGD_SHA256
}

// hmacHashAlg 校验带密钥杂凑的算法标识并映射为设备杂凑算法标识:
// SGD_SM3_HMAC→SGD_SM3、SGD_SHA256_HMAC→SGD_SHA256。
// 设备 ABI SDF_HMACInit(hSession, hKeyHandle, uiAlgID) 的 uiAlgID 按
// GMT 0018-2023 §6.6.2 是杂凑算法标识(运算符合 GB/T 15852.2),
// 故下发前做此映射;普通杂凑标识(SGD_SM3/SGD_SHA256)及其余值返回 false。
func hmacHashAlg(alg ALGID) (ALGID, bool) {
	switch alg {
	case SGD_SM3_HMAC:
		return SGD_SM3, true
	case SGD_SHA256_HMAC:
		return SGD_SHA256, true
	}
	return 0, false
}

// NewHMAC 初始化带密钥的杂凑运算(GM/T 0018-2023 6.6.2,SDF_HMACInit;
// 运算过程符合 GB/T 15852.2)。
// alg 必须是 HMAC 类算法标识 SGD_SM3_HMAC/SGD_SHA256_HMAC(不是普通杂凑标识);
// 内部映射为 SGD_SM3/SGD_SHA256 后作为 SDF_HMACInit 的 uiAlgID 下发。
// 其他算法返回 SDR_ALGNOTSUPPORT。
func (k *Key) NewHMAC(alg ALGID) (*Hasher, error) {
	const op = "SDF_HMACInit"
	ctx, sh, kh, err := k.handles(op)
	if err != nil {
		return nil, err
	}
	hashID, ok := hmacHashAlg(alg)
	if !ok {
		return nil, rvErr(op, SDR_ALGNOTSUPPORT)
	}
	if rv := C.hmac_init(ctx, sh, kh, C.UINT32(hashID)); rv != 0 {
		return nil, rvErr(op, RV(rv))
	}
	return &Hasher{s: k.s, key: k, started: true}, nil
}

// HMAC 一步式带密钥杂凑(NewHMAC + Update + Final)。
// alg 仅接受 HMAC 类标识 SGD_SM3_HMAC/SGD_SHA256_HMAC,内部映射为
// SGD_SM3/SGD_SHA256 下发 SDF_HMACInit;其他算法返回 SDR_ALGNOTSUPPORT。
func (k *Key) HMAC(alg ALGID, data []byte) ([]byte, error) {
	h, err := k.NewHMAC(alg)
	if err != nil {
		return nil, err
	}
	if err := h.Update(data); err != nil {
		return nil, err
	}
	return h.Final()
}

// SM2Digest 一步计算 SM2 ZA+SM3 摘要:NewSM2ZAHash + Update + Final。
// uid 为空时使用默认用户 ID。
func (s *Session) SM2Digest(pub *ecdsa.PublicKey, uid, message []byte) ([]byte, error) {
	h, err := s.NewSM2ZAHash(pub, uid)
	if err != nil {
		return nil, err
	}
	if err := h.Update(message); err != nil {
		return nil, err
	}
	return h.Final()
}
