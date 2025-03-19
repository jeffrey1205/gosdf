package gosdf

import (
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
)

var enginePath string = "./libsdf_crypto.so"
var sessionKey []byte //会话密钥
var ecbCipher []byte
var cbcCipher []byte

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

	key, keyHandle, ret := GenerateKeyWithKEK(session, 1, 128)
	if ret != SDR_OK {
		fmt.Printf("SDF GenerateKeyWithKEK error: %x\n", ret)
		CloseSession(session)
		return
	}
	fmt.Printf("key: %x, handle: %x\n", key, keyHandle)
	sessionKey = key

	ecbCipher, ret = SM4EncryptECB(session, keyHandle, []byte("test1111test1111"))
	fmt.Printf("ecb cipher: %x, ret: %x\n", ecbCipher, ret)

	cbcCipher, ret = SM4EncryptCBC(session, keyHandle, []byte("1234567890abcdef"), []byte("test1111test1111"))
	fmt.Printf("cbc cipher: %x, ret: %x\n", cbcCipher, ret)

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

	keyHandle, ret := ImportKeyWithKEK(session, 1, sessionKey)
	if ret != SDR_OK {
		fmt.Printf("SDF ImportKeyWithKEK error: %x\n", ret)
		CloseSession(session)
		return
	}

	fmt.Printf("key: %x\n", keyHandle)

	plainText, ret := SM4DecryptECB(session, keyHandle, ecbCipher)
	fmt.Printf("ecb plain: %s, ret: %x\n", plainText, ret)

	plainText, ret = SM4DecryptCBC(session, keyHandle, []byte("1234567890abcdef"), cbcCipher)
	fmt.Printf("cbc plain: %s, ret: %x\n", plainText, ret)

	DestroyKey(session, keyHandle)
}

func TestSm4MAC(t *testing.T) {
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

	keyHandle, ret := ImportKeyWithKEK(session, 1, sessionKey)
	if ret != SDR_OK {
		fmt.Printf("SDF ImportKeyWithKEK error: %x\n", ret)
		CloseSession(session)
		return
	}

	fmt.Printf("key: %x\n", keyHandle)

	// 加密两个分组,IV设置为0,最后一个密文分组即为MAC
	iv := make([]byte, 16)                                  // IV设置为0
	plainText := []byte("test1111test1111test1111test1111") // 加密两个分组
	cipherText, ret := SM4EncryptCBC(session, keyHandle, iv, plainText)
	fmt.Printf("cbc cipher mac:%x, ret: %x\n", cipherText[16:], ret)

	// 一次计算两个分组的MAC
	iv = make([]byte, 16) // IV设置为0
	mac, ret := SM4CalculateCBCMAC(session, keyHandle, iv, plainText)
	fmt.Printf("cbc mac: %x, ret: %x\n", mac, ret)

	// 分两步计算两个分组的MAC
	iv = make([]byte, 16) // IV设置为0
	mac, ret = SM4CalculateCBCMAC(session, keyHandle, iv, plainText[:16])
	fmt.Printf("cbc mac 1: %x, ret: %x\n", mac, ret)
	mac, ret = SM4CalculateCBCMAC(session, keyHandle, mac, plainText[16:])
	fmt.Printf("cbc mac 2: %x, ret: %x\n", mac, ret)

	DestroyKey(session, keyHandle)
}

func TestSm3(t *testing.T) {
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

func TestSm3HMAC(t *testing.T) {
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
	defer CloseSession(session)

	keyByte, _ := hex.DecodeString("d9d858ba5784328e95c420c35c4873442ed6392531e1c149d2ff5696b2352018")
	if ret := Sm3HMACInit(session, 1, keyByte); ret != SDR_OK {
		fmt.Printf("HMAC Init error: %x\n", ret)
		return
	}

	if ret := Sm3HMACUpdate(session, []byte("test")); ret != SDR_OK {
		fmt.Printf("HMAC Update error: %x\n", ret)
	}

	hash, ret := Sm3HMACFinal(session)
	fmt.Printf("HMAC Final ret %x, hash: %x\n", ret, hash)
}

func TestISO9797M3Padding(t *testing.T) {
	data1, _ := hex.DecodeString("00112233445566778899")
	padded, _ := ISO9797M3Padding(data1, 16)
	fmt.Printf("data1 padded: %x\n", padded)

	data2, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	padded, _ = ISO9797M3Padding(data2, 16)
	fmt.Printf("data2 padded: %x\n", padded)
}

func TestSm4MultiThread(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		session, ret := OpenSession()
		if ret != SDR_OK {
			fmt.Printf("SDF Open Session error: %x\n", ret)
			return
		}

		fmt.Printf("[1]session: %x\n", session)

		keyHandle, ret := ImportKeyWithKEK(session, 1, sessionKey)
		if ret != SDR_OK {
			fmt.Printf("SDF ImportKeyWithKEK error: %x\n", ret)
			CloseSession(session)
			return
		}

		fmt.Printf("[1]key: %x\n", keyHandle)

		// 加密两个分组,IV设置为0,最后一个密文分组即为MAC
		iv := make([]byte, 16)                                  // IV设置为0
		plainText := []byte("test1111test1111test1111test1111") // 加密两个分组
		cipherText, ret := SM4EncryptCBC(session, keyHandle, iv, plainText)
		fmt.Printf("[1]cbc cipher mac:%x, ret: %x\n", cipherText[16:], ret)

		// 一次计算两个分组的MAC
		iv = make([]byte, 16) // IV设置为0
		mac, ret := SM4CalculateCBCMAC(session, keyHandle, iv, plainText)
		fmt.Printf("[1]cbc mac: %x, ret: %x\n", mac, ret)

		DestroyKey(session, keyHandle)
	}()

	go func() {
		defer wg.Done()
		session, ret := OpenSession()
		if ret != SDR_OK {
			fmt.Printf("SDF Open Session error: %x\n", ret)
			return
		}

		fmt.Printf("[2]session: %x\n", session)

		keyHandle, ret := ImportKeyWithKEK(session, 1, sessionKey)
		if ret != SDR_OK {
			fmt.Printf("SDF ImportKeyWithKEK error: %x\n", ret)
			CloseSession(session)
			return
		}

		fmt.Printf("[2]key: %x\n", keyHandle)
		// 分两步计算两个分组的MAC
		iv := make([]byte, 16)                                  // IV设置为0
		plainText := []byte("test1111test1111test1111test1111") // 加密两个分组
		mac, ret := SM4CalculateCBCMAC(session, keyHandle, iv, plainText[:16])
		fmt.Printf("[2]cbc mac 1: %x, ret: %x\n", mac, ret)
		mac, ret = SM4CalculateCBCMAC(session, keyHandle, mac, plainText[16:])
		fmt.Printf("[2]cbc mac 2: %x, ret: %x\n", mac, ret)

		DestroyKey(session, keyHandle)
	}()

	wg.Wait()
}

func TestSm2(t *testing.T) {
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

	// 导出签名公钥
	signPub, ret := ExportSignPublicKeyECC(session, 1)
	fmt.Printf("signPub: %x, ret: %x\n", signPub, ret)
	// 导出加密公钥
	encPub, ret := ExportSignPublicKeyECC(session, 1)
	fmt.Printf("encPub: %x, ret: %x\n", encPub, ret)
	// 导出会话密钥
	cipherKey, key, ret := GenerateKeyWithIPKECC(session, 1, 128)
	fmt.Printf("cipherKey: %x, key: %x, ret: %x\n", cipherKey, key, ret)
	DestroyKey(session, key)

	// 导入会话密钥
	session, ret = OpenSession()
	if ret != SDR_OK {
		fmt.Printf("SDF Open Session error: %x\n", ret)
		return
	}

	ret = GetPrivateKeyAccessRight(session, 1, []byte("12345678"))
	if ret != SDR_OK {
		fmt.Printf("SDF GetPrivateKeyAccessRight error: %x\n", ret)
		return
	}

	key, ret = ImportKeyWithISKECC(session, 1, cipherKey)
	fmt.Printf("import key: %x, ret: %x\n", key, ret)

	ReleasePrivateKeyAccessRight(session, 1)
	DestroyKey(session, key)

	// 签名验签
	session, ret = OpenSession()
	if ret != SDR_OK {
		fmt.Printf("SDF Open Session error: %x\n", ret)
		return
	}

	// 预处理
	ret = Sm3InitWithPubKey(session, signPub, []byte("1234567812345678"))
	if ret != SDR_OK {
		fmt.Printf("SDF sm3 hash pre handle error: %x\n", ret)
		return
	}

	_ = Sm3Update(session, []byte("test"))
	hash, ret := Sm3Final(session)
	fmt.Printf("sm3 hash pre handle: %x ret: %x\n", hash, ret)

	ret = GetPrivateKeyAccessRight(session, 1, []byte("12345678"))
	if ret != SDR_OK {
		fmt.Printf("SDF GetPrivateKeyAccessRight error: %x\n", ret)
		return
	}

	sig, ret := InternalSignECC(session, 1, hash)
	fmt.Printf("sig: %x, ret: %x\n", sig, ret)

	ReleasePrivateKeyAccessRight(session, 1)

	ret = InternalVerifyECC(session, 1, hash, sig)
	fmt.Printf("verify ret: %x\n", ret)

	// 加密
	cipherText, ret := ExternalEncryptECC(session, encPub, []byte("test"))
	fmt.Printf("enc txt: %x, ret: %x\n", cipherText, ret)

	CloseSession(session)
}
