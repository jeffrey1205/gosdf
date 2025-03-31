package sm3

import (
	"crypto/hmac"
	"fmt"
	"testing"

	"github.com/jeffrey1205/gosdf"
)

var enginePath string = "./libsdf_crypto.so"

func TestSm3Hash(t *testing.T) {
	if err := gosdf.Init(enginePath); err != gosdf.SDR_OK {
		fmt.Println("SDF init error:", err.Error())
		return
	}
	defer gosdf.Exit()

	//55E12E91650D2FEC56EC74E1D3E4DDBFCE2EF3A65890C2A19ECF88A307E76A23
	sm3 := New()
	sm3.Write([]byte("test"))
	fmt.Printf("SM3 Hash: %x\n", sm3.Sum(nil))
	fmt.Printf("SM3 Hash: %x\n", Sm3Sum([]byte("test")))
}

func TestHmacSm3(t *testing.T) {
	if err := gosdf.Init(enginePath); err != gosdf.SDR_OK {
		fmt.Println("SDF Init error:", err.Error())
		return
	}
	defer gosdf.Exit()

	mac := hmac.New(New, []byte("123456"))
	mac.Write([]byte("test"))
	fmt.Printf("HMAC-SM3: %x\n", mac.Sum(nil))
}
