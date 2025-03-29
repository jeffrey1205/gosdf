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

	crypter := NewCrypter(SM4_CBC, uint(Sm4BlockSize), true)
	if crypter == nil {
		fmt.Println("SM4 New error")
		return
	}

	err := crypter.NewKey(1)
	if err != nil {
		fmt.Printf("SDF NewKey error: %v\n", err)
		return
	}
	defer crypter.Destroy()

	cipherText, err := crypter.Encrypt([]byte("1234567890abcdef"), []byte("test1111test1111"))
	fmt.Printf("Ciper %x, err %v", cipherText, err)
}

func TestSm4MAC(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	crypter := NewCrypter(SM4_CBC, uint(Sm4BlockSize), true)
	if crypter == nil {
		fmt.Println("SM4 New error")
		return
	}

	err := crypter.NewKey(1)
	if err != nil {
		fmt.Printf("SDF NewKey error: %v\n", err)
		return
	}
	defer crypter.Destroy()

	mac, err := crypter.CBCMAC(zeroIV, []byte("test1111test1111"))
	fmt.Printf("mac %x, err %v", mac, err)
}

func TestSm3(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	session, err := OpenSession()
	if err != nil {
		fmt.Printf("SDF Open Session error: %v\n", err)
		return
	}
	defer CloseSession(session)

	if err := Sm3Init(session); err != nil {
		fmt.Printf("SM3 Init error: %v\n", err)
		return
	}

	//55E12E91650D2FEC56EC74E1D3E4DDBFCE2EF3A65890C2A19ECF88A307E76A23
	if err := HashUpdate(session, []byte("test")); err != nil {
		fmt.Printf("SM3 Update error: %v\n", err)
	}

	hash, err := HashFinal(session)
	fmt.Printf("SM3 Final err %v, hash: %x\n", err, hash)
}

func TestSm3HMAC(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	session, err := OpenSession()
	if err != nil {
		fmt.Printf("SDF Open Session error: %v\n", err)
		return
	}
	defer CloseSession(session)

	keyByte, _ := hex.DecodeString("d9d858ba5784328e95c420c35c4873442ed6392531e1c149d2ff5696b2352018")
	if err := Sm3HMACInit(session, 1, keyByte); err != nil {
		fmt.Printf("HMAC Init error: %v\n", err)
		return
	}

	if err := Sm3HMACUpdate(session, []byte("test")); err != nil {
		fmt.Printf("HMAC Update error: %v\n", err)
	}

	hash, err := Sm3HMACFinal(session)
	fmt.Printf("HMAC Final err %v, hash: %x\n", err, hash)
}

func TestSm2(t *testing.T) {
	if err := Init(enginePath); err != nil {
		fmt.Println("SDF Init error:", err)
		return
	}
	defer Exit()

	session, err := OpenSession()
	if err != nil {
		fmt.Printf("SDF Open Session error: %v\n", err)
		return
	}

	// 导出签名公钥
	signPub, err := ExportSignPublicKeyECC(session, 1)
	fmt.Printf("signPub: %x, err: %v\n", signPub, err)
	// 导出加密公钥
	encPub, err := ExportSignPublicKeyECC(session, 1)
	fmt.Printf("encPub: %x, err: %v\n", encPub, err)
	// 导出会话密钥
	cipherKey, key, err := GenerateKeyWithIPKECC(session, 1, 128)
	fmt.Printf("cipherKey: %x, key: %x, err: %v\n", cipherKey, key, err)
	DestroyKey(session, key)

	// 导入会话密钥
	session, err = OpenSession()
	if err != nil {
		fmt.Printf("SDF Open Session error: %v\n", err)
		return
	}

	err = GetPrivateKeyAccessRight(session, 1, []byte("12345678"))
	if err != nil {
		fmt.Printf("SDF GetPrivateKeyAccessRight error: %v\n", err)
		return
	}

	key, err = ImportKeyWithISKECC(session, 1, cipherKey)
	fmt.Printf("import key: %x, err: %v\n", key, err)

	ReleasePrivateKeyAccessRight(session, 1)
	DestroyKey(session, key)

	// 签名验签
	session, err = OpenSession()
	if err != nil {
		fmt.Printf("SDF Open Session error: %v\n", err)
		return
	}

	// 预处理
	err = HashInit(session, SGD_SM3, &signPub, []byte("1234567812345678"))
	if err != nil {
		fmt.Printf("SDF sm3 hash pre handle error: %v\n", err)
		return
	}

	_ = HashUpdate(session, []byte("test"))
	hash, err := HashFinal(session)
	fmt.Printf("sm3 hash pre handle: %x err: %x\n", hash, err)

	err = GetPrivateKeyAccessRight(session, 1, []byte("12345678"))
	if err != nil {
		fmt.Printf("SDF GetPrivateKeyAccessRight error: %v\n", err)
		return
	}

	sig, err := InternalSignECC(session, 1, hash)
	fmt.Printf("sig: %x, err: %v\n", sig, err)

	sm2Sig, err := Sm2InternalSign(session, 1, hash)
	fmt.Printf("sm2 sig: %x, err: %v\n", sm2Sig, err)

	sm2Sig, err = Sm2SignData(1, []byte("test"))
	fmt.Printf("sm2 sign data: %x, err: %v\n", sm2Sig, err)

	ReleasePrivateKeyAccessRight(session, 1)

	err = InternalVerifyECC(session, 1, hash, sig)
	fmt.Printf("verify err: %v\n", err)

	err = Sm2InternalVerify(session, 1, hash, sm2Sig)
	fmt.Printf("sm2 verify err: %v\n", err)

	err = Sm2VerifyData(1, []byte("test"), sm2Sig)
	fmt.Printf("sm2 verify data err: %v\n", err)

	// 加密
	cipherText, err := ExternalEncryptECC(session, encPub, []byte("test"))
	fmt.Printf("enc txt: %x, err: %v\n", cipherText, err)

	CloseSession(session)
}
