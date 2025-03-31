package sm3

import (
	"fmt"
	"hash"
	"runtime"

	sdf "github.com/jeffrey1205/gosdf"
)

type SM3 struct {
	session sdf.HANDLE
}

// 关闭session
func (sm3 *SM3) Close() {
	sdf.CloseSession(sm3.session)
}

// 创建哈希计算实例
func New() hash.Hash {
	session, err := sdf.OpenSession()
	if err != sdf.SDR_OK {
		panic(err.Error())
	}

	if err := sdf.HashInit(session, sdf.SGD_SM3, nil, nil); err != sdf.SDR_OK {
		panic(err.Error())
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
func (sm3 *SM3) Size() int { return sdf.Sm3HashSize }

func (sm3 *SM3) Reset() {
	// 是否需要重新调用sm3init？
}

func (sm3 *SM3) Write(p []byte) (int, error) {
	if err := sdf.HashUpdate(sm3.session, p); err != sdf.SDR_OK {
		return 0, fmt.Errorf("sm3 update error: %v", err.Error())
	}

	return len(p), nil
}

func (sm3 *SM3) Sum(in []byte) []byte {
	if len(in) > 0 {
		_, _ = sm3.Write(in)
	}

	hash, err := sdf.HashFinal(sm3.session)
	if err != sdf.SDR_OK {
		panic(fmt.Sprintf("session %x final error: %v", sm3.session, err))
	}

	return hash
}

func Sm3Sum(data []byte) []byte {
	sm3 := New()
	_, _ = sm3.Write(data)
	return sm3.Sum(nil)
}
