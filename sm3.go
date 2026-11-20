package gosdf

import "hash"

// sm3hash 基于设备杂凑运算的 SM3 hash.Hash(缓冲式,原 sm3 子包并入根包)。
//
// Write 仅写入内存,Sum 每次在设备上开临时会话杂凑全部缓冲,不改变内部状态
// (满足 hash.Hash 契约)。设备错误时 panic(hash.Hash 接口无 error 路径)。
type sm3hash struct {
	d   *Device
	buf []byte
}

// 编译期断言:sm3hash 满足 hash.Hash 契约。
var _ hash.Hash = (*sm3hash)(nil)

// NewSM3Hash 返回基于设备杂凑运算的 SM3 hash.Hash。
func (d *Device) NewSM3Hash() hash.Hash {
	return &sm3hash{d: d}
}

// Write 追加数据到缓冲,永不失败。
func (h *sm3hash) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

// Sum 将当前杂凑值追加到 in 后返回,不改变已写入状态。
func (h *sm3hash) Sum(in []byte) []byte {
	digest, err := h.d.SM3Sum(h.buf)
	if err != nil {
		panic(err)
	}
	return append(in, digest...)
}

// Reset 清空缓冲。
func (h *sm3hash) Reset() {
	h.buf = h.buf[:0]
}

// Size 返回杂凑值长度(SM3 = 32)。
func (h *sm3hash) Size() int { return Sm3HashSize }

// BlockSize 返回底层分组长度(SM3 = 64)。
func (h *sm3hash) BlockSize() int { return 64 }

// SM3Sum 一次性计算 data 的 SM3 杂凑值,失败返回错误。
func (d *Device) SM3Sum(data []byte) ([]byte, error) {
	s, err := d.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	h := s.NewHash(SGD_SM3)
	if err := h.Update(data); err != nil {
		return nil, err
	}
	return h.Final()
}
