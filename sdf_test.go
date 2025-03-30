package gosdf

import (
	"fmt"
	"testing"
)

var enginePath string = "./libsdf_crypto.so"

func TestSm4Enc(t *testing.T) {
	if ret := Init(enginePath); ret != SDR_OK {
		fmt.Println("SDF Init error:", ret.Error())
		return
	}
	defer Exit()

	crypter := NewCrypter(SM4_CBC, uint(Sm4BlockSize), true)
	if crypter == nil {
		fmt.Println("SM4 New error")
		return
	}
	defer crypter.Destroy()

	err := crypter.NewKey(1)
	if err != nil {
		fmt.Printf("SDF NewKey error: %v\n", err)
		return
	}

	cipherText, err := crypter.Encrypt([]byte("1234567890abcdef"),
		[]byte("test1111test1111"))
	fmt.Printf("Ciper %x, err %v", cipherText, err)
}

func TestSm4MAC(t *testing.T) {
	if ret := Init(enginePath); ret != SDR_OK {
		fmt.Println("SDF Init error:", ret.Error())
		return
	}
	defer Exit()

	crypter := NewCrypter(SM4_CBC, uint(Sm4BlockSize), true)
	if crypter == nil {
		fmt.Println("SM4 New error")
		return
	}
	defer crypter.Destroy()

	err := crypter.NewKey(1)
	if err != nil {
		fmt.Printf("SDF NewKey error: %v\n", err)
		return
	}

	mac, err := crypter.CBCMAC(zeroIV, []byte("test1111test1111"))
	fmt.Printf("mac %x, err %v", mac, err)
}

func TestSm2(t *testing.T) {
	if ret := Init(enginePath); ret != SDR_OK {
		fmt.Println("SDF Init error:", ret.Error())
		return
	}
	defer Exit()

	// 签名验签
	sm2Sig, err := Sm2SignData(1, []byte("test"))
	fmt.Printf("sm2 sign data: %x, err: %v\n", sm2Sig, err)

	err = Sm2VerifyData(1, []byte("test"), sm2Sig)
	fmt.Printf("sm2 verify data err: %v\n", err)
}
