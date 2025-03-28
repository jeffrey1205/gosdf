package gosdf

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var enginePath string = "./libsdf_crypto.so"

func TestSm4Enc(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	crypter := Sm4New(SM4_CBC, true)
	if crypter == nil {
		fmt.Println("SM4 New error")
		return
	}

	ret := crypter.NewKey(1)
	if ret != SDR_OK {
		fmt.Printf("SDF NewKey error: %x\n", ret)
		return
	}
	defer crypter.Destroy()

	cipherText, ret := crypter.Encrypt([]byte("1234567890abcdef"), []byte("test1111test1111"))
	fmt.Printf("Ciper %x, ret %d", cipherText, ret)
}

func TestSm4MAC(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	crypter := Sm4New(SM4_CBC, true)
	if crypter == nil {
		fmt.Println("SM4 New error")
		return
	}

	ret := crypter.NewKey(1)
	if ret != SDR_OK {
		fmt.Printf("SDF NewKey error: %x\n", ret)
		return
	}
	defer crypter.Destroy()

	mac, ret := crypter.CBCMAC(zeroIV, []byte("test1111test1111"))
	fmt.Printf("mac %x, ret %d", mac, ret)
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
	if ret := HashUpdate(session, []byte("test")); ret != SDR_OK {
		fmt.Printf("SM3 Update error: %x\n", ret)
	}

	hash, ret := HashFinal(session)
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
	ret = HashInit(session, SGD_SM3, &signPub, []byte("1234567812345678"))
	if ret != SDR_OK {
		fmt.Printf("SDF sm3 hash pre handle error: %x\n", ret)
		return
	}

	_ = HashUpdate(session, []byte("test"))
	hash, ret := HashFinal(session)
	fmt.Printf("sm3 hash pre handle: %x ret: %x\n", hash, ret)

	ret = GetPrivateKeyAccessRight(session, 1, []byte("12345678"))
	if ret != SDR_OK {
		fmt.Printf("SDF GetPrivateKeyAccessRight error: %x\n", ret)
		return
	}

	sig, ret := InternalSignECC(session, 1, hash)
	fmt.Printf("sig: %x, ret: %x\n", sig, ret)

	sm2Sig, ret := Sm2InternalSign(session, 1, hash)
	fmt.Printf("sm2 sig: %x, ret: %x\n", sm2Sig, ret)

	sm2Sig, ret = Sm2SignData(1, []byte("test"))
	fmt.Printf("sm2 sign data: %x, ret: %x\n", sm2Sig, ret)

	ReleasePrivateKeyAccessRight(session, 1)

	ret = InternalVerifyECC(session, 1, hash, sig)
	fmt.Printf("verify ret: %x\n", ret)

	ret = Sm2InternalVerify(session, 1, hash, sm2Sig)
	fmt.Printf("sm2 verify ret: %x\n", ret)

	ret = Sm2VerifyData(1, []byte("test"), sm2Sig)
	fmt.Printf("sm2 verify data ret: %x\n", ret)

	// 加密
	cipherText, ret := ExternalEncryptECC(session, encPub, []byte("test"))
	fmt.Printf("enc txt: %x, ret: %x\n", cipherText, ret)

	CloseSession(session)
}
