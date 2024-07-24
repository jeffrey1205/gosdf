package gosdf

import (
	"crypto/hmac"
	"fmt"
	"testing"
)

var enginePath string = "./libsdf_crypto.so"

func TestSm3Hash(t *testing.T) {
	if err := SdfInit(enginePath); err != nil {
		fmt.Println("SDF init error:", err)
		return
	}
	defer SdfExit()

	sm3 := New()
	sm3.Write([]byte("test"))
	fmt.Printf("SM3 Hash: %x\n", sm3.Sum(nil))
}

func TestSm3(t *testing.T) {
	if err := SdfInit(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer SdfExit()

	session := SdfOpenSession()
	if session == 0 {
		fmt.Println("SDF Open Session error")
		return
	}
	defer SdfCloseSession(session)

	if ret := SdfSm3Init(session); ret != 0 {
		fmt.Println("SM3 Init error:", ret)
		return
	}

	//55E12E91650D2FEC56EC74E1D3E4DDBFCE2EF3A65890C2A19ECF88A307E76A23
	if ret := SdfSm3Update(session, []byte("test"), 4); ret != 0 {
		fmt.Println("SM3 Update error:", ret)
	}

	ret, hash := SdfSm3Final(session)
	fmt.Printf("SM3 Final ret %d, hash: %x\n", ret, hash)
}

func TestHmacSm3(t *testing.T) {
	if err := SdfInit(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer SdfExit()

	mac := hmac.New(New, []byte("123456"))
	mac.Write([]byte("test"))
	fmt.Printf("HMAC-SM3: %x\n", mac.Sum(nil))
}
