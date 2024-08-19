package gosdf

import (
	"fmt"
	"testing"
)

var enginePath string = "./libsdf_crypto.so"

func TestSm3(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	session, ret := OpenSession()
	if ret != 0 {
		fmt.Println("SDF Open Session error")
		return
	}
	defer CloseSession(session)

	if ret := Sm3Init(session); ret != 0 {
		fmt.Println("SM3 Init error:", ret)
		return
	}

	//55E12E91650D2FEC56EC74E1D3E4DDBFCE2EF3A65890C2A19ECF88A307E76A23
	if ret := Sm3Update(session, []byte("test")); ret != 0 {
		fmt.Println("SM3 Update error:", ret)
	}

	hash, ret := Sm3Final(session)
	fmt.Printf("SM3 Final ret %d, hash: %x\n", ret, hash)
}
