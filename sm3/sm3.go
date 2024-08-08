package sm3

import (
	"fmt"
	"hash"
	"runtime"

	"gitee.com/zhujingfeng/gosdf"
)

type SM3 struct {
	session int
}

// 关闭session
func (sm3 *SM3) Close() {
	gosdf.CloseSession(sm3.session)
}

// 创建哈希计算实例
func New() hash.Hash {
	session, ret := gosdf.OpenSession()
	if ret != 0 {
		return nil
	}

	if ret := gosdf.Sm3Init(session); ret != 0 {
		return nil
	}

	sm3 := &SM3{session: session}
	runtime.SetFinalizer(sm3, func(sm3 *SM3) { sm3.Close() })
	return sm3
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (sm3 *SM3) BlockSize() int { return 64 }

// Size returns the number of bytes Sum will return.
func (sm3 *SM3) Size() int { return 32 }

func (sm3 *SM3) Reset() {
}

func (sm3 *SM3) Write(p []byte) (int, error) {
	toWrite := len(p)
	if ret := gosdf.Sm3Update(sm3.session, p, uint32(toWrite)); ret != 0 {
		return 0, fmt.Errorf("sm3 update error: %d", ret)
	}

	return toWrite, nil
}

func (sm3 *SM3) Sum(in []byte) []byte {
	hash, ret := gosdf.Sm3Final(sm3.session)
	if ret != 0 {
		return nil
	}

	return hash
}
