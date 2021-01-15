package gosdf

import (
	"fmt"
	"testing"
)

func TestSm3(t *testing.T) {
	fmt.Println("ccore test start")

	if err := SdfInit("/home/go-test/ccore/libsdf_crypto.so"); err != nil {
		fmt.Println("sdf init error:", err)
		return
	}
	defer SdfExit()

	session := SdfOpenSession()
	if session == 0 {
		fmt.Println("sdf open session error")
		return
	}
	defer SdfCloseSession(session)

	ret := SdfSm3Init(session)
	fmt.Println("sdf sm3 init:", ret)

	ret = SdfSm3Update(session, []byte("test"), 4)
	fmt.Println("sdf sm3 update:", ret)

	ret, hash := SdfSm3Final(session)
	var hashStr string
	for i := 0; i < len(hash); i++ {
		hashStr += fmt.Sprintf("%02X", hash[i])
	}
	fmt.Printf("sdf sm3 final ret %d, hash: %s\n", ret, hashStr)
}
