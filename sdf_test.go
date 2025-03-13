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
	if ret != SDR_OK {
		fmt.Println("SDF Open Session error")
		return
	}
	defer CloseSession(session)

	if ret := Sm3Init(session); ret != SDR_OK {
		fmt.Println("SM3 Init error:", ret)
		return
	}

	//55E12E91650D2FEC56EC74E1D3E4DDBFCE2EF3A65890C2A19ECF88A307E76A23
	if ret := Sm3Update(session, []byte("test")); ret != SDR_OK {
		fmt.Println("SM3 Update error:", ret)
	}

	hash, ret := Sm3Final(session)
	fmt.Printf("SM3 Final ret %d, hash: %x\n", ret, hash)
}

func TestSm4Enc(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	session, ret := OpenSession()
	if ret != SDR_OK {
		fmt.Println("SDF Open Session error")
		return
	}
	defer CloseSession(session)

	key, keyHandle, ret := GenerateKeyWithKEK(session, 1, 16)
	if ret != SDR_OK {
		fmt.Println("SDF GenerateKeyWithKEK error")
		return
	}
	defer DestroyKey(session, keyHandle)
	fmt.Printf("key: %x\n", key)

	cipherText, ret := SM4EncryptECB(session, keyHandle, []byte("test"))
	fmt.Printf("ecb cipher: %x, ret: %d\n", cipherText, ret)

	cipherText, ret = SM4EncryptCBC(session, keyHandle, []byte("test"), []byte("1234567890abcdef"))
	fmt.Printf("ebc cipher: %x, ret: %d\n", cipherText, ret)
}
