package gosdf

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"
)

var enginePath string = "./libsdf_crypto.so"

func TestSm3(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Printf("SDF Init error: %x\n", err)
		return
	}
	defer Exit()

	session, ret := OpenSession()
	if ret != SDR_OK {
		fmt.Printf("SDF Open Session error: %x\n", ret)
		return
	}
	defer CloseSession(session)

	if ret := Sm3Init(session); ret != SDR_OK {
		fmt.Printf("SM3 Init error: %x\n", ret)
		return
	}

	//55E12E91650D2FEC56EC74E1D3E4DDBFCE2EF3A65890C2A19ECF88A307E76A23
	if ret := Sm3Update(session, []byte("test")); ret != SDR_OK {
		fmt.Printf("SM3 Update error: %x\n", ret)
	}

	hash, ret := Sm3Final(session)
	fmt.Printf("SM3 Final ret %x, hash: %x\n", ret, hash)
}

func TestSm4Enc(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	session, ret := OpenSession()
	if ret != SDR_OK {
		fmt.Printf("SDF Open Session error: %x\n", ret)
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	key, keyHandle, ret := GenerateKeyWithKEK(session, 1, 128)
	if ret != SDR_OK {
		fmt.Printf("SDF GenerateKeyWithKEK error: %x\n", ret)
		CloseSession(session)
		return
	}
	fmt.Printf("key: %x, handle: %x\n", key, keyHandle)

	cipherText, ret := SM4EncryptECB(session, keyHandle, []byte("test1111test1111"))
	fmt.Printf("ecb cipher: %x, ret: %x\n", cipherText, ret)

	cipherText, ret = SM4EncryptCBC(session, keyHandle, []byte("1234567890abcdef"), []byte("test1111test1111"))
	fmt.Printf("cbc cipher: %x, ret: %x\n", cipherText, ret)

	DestroyKey(session, keyHandle)
}

func TestSm4Dec(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	session, ret := OpenSession()
	if ret != SDR_OK {
		fmt.Printf("SDF Open Session error: %x\n", ret)
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	keyByte, _ := hex.DecodeString("d9d858ba5784328e95c420c35c4873442ed6392531e1c149d2ff5696b2352018")
	keyHandle, ret := ImportKeyWithKEK(session, 1, keyByte)
	if ret != SDR_OK {
		fmt.Printf("SDF ImportKeyWithKEK error: %x\n", ret)
		CloseSession(session)
		return
	}

	fmt.Printf("key: %x\n", keyHandle)

	cipherText, _ := hex.DecodeString("ae61aa3ffef6b2efd30d0d9fd508be45")
	plainText, ret := SM4DecryptECB(session, keyHandle, cipherText)
	fmt.Printf("ecb plain: %s, ret: %x\n", plainText, ret)

	cipherText, _ = hex.DecodeString("91788d836d8ffb35e58d9ffbc572a956")
	plainText, ret = SM4DecryptCBC(session, keyHandle, []byte("1234567890abcdef"), cipherText)
	fmt.Printf("cbc plain: %s, ret: %x\n", plainText, ret)

	DestroyKey(session, keyHandle)
}
