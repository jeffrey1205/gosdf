package sm3

import (
	"crypto/hmac"
	"fmt"
	"testing"

	"gitee.com/zhujingfeng/gosdf"
)

var enginePath string = "./libsdf_crypto.so"

func TestSm3Hash(t *testing.T) {
	if err := gosdf.Init(enginePath); err != nil {
		fmt.Println("SDF init error:", err)
		return
	}
	defer gosdf.Exit()

	sm3 := New()
	sm3.Write([]byte("test"))
	fmt.Printf("SM3 Hash: %x\n", sm3.Sum(nil))
	fmt.Printf("SM3 Hash: %x\n", Sm3Sum([]byte("test")))
}

func TestHmacSm3(t *testing.T) {
	if err := gosdf.Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer gosdf.Exit()

	mac := hmac.New(New, []byte("123456"))
	mac.Write([]byte("test"))
	fmt.Printf("HMAC-SM3: %x\n", mac.Sum(nil))
}
