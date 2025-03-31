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

	// 加密测试
	encCrypter := NewCrypter(SM4_CBC)
	if encCrypter == nil {
		fmt.Println("SM4 New error")
		return
	}
	defer encCrypter.Destroy()

	err := encCrypter.NewKey(1)
	if err != nil {
		fmt.Printf("SDF NewKey error: %v\n", err)
		return
	}

	cipherText, err := encCrypter.Encrypt([]byte("1234567890abcdef"),
		[]byte("test1111test1111"))
	fmt.Printf("Cipher %x, err %v\n", cipherText, err)

	// 解密测试
	decCrypter := NewCrypter(SM4_CBC)
	if decCrypter == nil {
		fmt.Println("SM4 New error")
		return
	}
	defer decCrypter.Destroy()

	err = decCrypter.SetKey(1, encCrypter.Key())
	if err != nil {
		fmt.Printf("SDF SetKey error: %v\n", err)
		return
	}

	plainText, err := decCrypter.Decrypt([]byte("1234567890abcdef"), cipherText)
	fmt.Printf("Plain %s, err %v\n", plainText, err)
}

func TestSm4MAC(t *testing.T) {
	if ret := Init(enginePath); ret != SDR_OK {
		fmt.Println("SDF Init error:", ret.Error())
		return
	}
	defer Exit()

	crypter := NewCrypter(SM4_MAC)
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
	fmt.Printf("mac %x, err %v\n", mac, err)
}

func TestSm2(t *testing.T) {
	if ret := Init(enginePath); ret != SDR_OK {
		fmt.Println("SDF Init error:", ret.Error())
		return
	}
	defer Exit()

	// 导出公钥
	pubKey, err := Sm2ExportEncPublicKey(1)
	fmt.Printf("sm2 public key: %x, err: %v\n", pubKey, err)
	// 公钥加密
	cipherText, err := Sm2Encrypt(pubKey, []byte("test"))
	fmt.Printf("sm2 cipher: %x, err: %v\n", cipherText, err)

	// 签名验签
	sm2Sig, err := Sm2SignData(1, []byte("test"))
	fmt.Printf("sm2 sign data: %x, err: %v\n", sm2Sig, err)

	err = Sm2VerifyData(1, []byte("test"), sm2Sig)
	fmt.Printf("sm2 verify data err: %v\n", err)
}
