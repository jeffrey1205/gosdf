package gosdf

import (
	"encoding/asn1"
	"errors"
	"math/big"
)

// 默认用户ID,用于数据签名验证
var defaultID = []byte("1234567812345678")

// SM2处理,均使用ASN.1编码格式
// SignatureMarshal: 将ECCSignature签名转换为ASN.1格式
func SignatureMarshal(sig ECCSignature) ([]byte, error) {
	return asn1.Marshal(sm2Signature{R: new(big.Int).SetBytes(sig.R[32:]),
		S: new(big.Int).SetBytes(sig.S[32:])})
}

// SignatureUnmarshal: 将ASN.1格式签名转换为ECCSignature结构
func SignatureUnmarshal(sig []byte) (ECCSignature, error) {
	var sm2Sig sm2Signature
	var eccSig ECCSignature

	_, err := asn1.Unmarshal(sig, &sm2Sig)
	if err != nil {
		return eccSig, err
	}

	copy(eccSig.R[32:], sm2Sig.R.Bytes())
	copy(eccSig.S[32:], sm2Sig.S.Bytes())
	return eccSig, nil
}

// PublicKeyMarshal: 将ECCrefPublicKey转换为04||x||y
func PublicKeyMarshal(pubKey ECCrefPublicKey) []byte {
	// 暂时不支持压缩格式
	key := []byte{0x04}
	key = append(key, pubKey.X[32:]...)
	key = append(key, pubKey.Y[32:]...)
	return key
}

// PublicKeyUmmarshal: 将04||x||y转换为ECCrefPublicKey
func PublicKeyUmmarshal(pubkey []byte) (ECCrefPublicKey, error) {
	var pub ECCrefPublicKey

	if len(pubkey) != 65 || pubkey[0] != 0x04 {
		return pub, errors.New("Invalid public key format")
	}

	pub.Bits = 256
	copy(pub.X[32:], pubkey[1:33])
	copy(pub.Y[32:], pubkey[33:])
	return pub, nil
}

// CipherMarshal: 将ECCCipher转换为ASN.1格式
func CipherMarshal(ciphertext ECCCipher) ([]byte, error) {
	sm2Cipher := sm2Cipher{
		X:          new(big.Int).SetBytes(ciphertext.X[32:]),
		Y:          new(big.Int).SetBytes(ciphertext.Y[32:]),
		HASH:       ciphertext.M[:],
		CipherText: ciphertext.C[:ciphertext.L],
	}
	return asn1.Marshal(sm2Cipher)
}

// CipherUnmarshal: 将ASN.1格式签名转换为ECCCipher结构
func CipherUnmarshal(ciphertext []byte) (ECCCipher, error) {
	var sm2Cipher sm2Cipher

	_, err := asn1.Unmarshal(ciphertext, &sm2Cipher)
	if err != nil {
		return ECCCipher{}, err
	}

	// 使用SM3 Hash必须为32字节长度,CipherText最大为128字节
	if len(sm2Cipher.HASH) != 32 ||
		len(sm2Cipher.CipherText) > int(ECCref_MAX_CIPHER_LEN) {
		return ECCCipher{}, errors.New("Invalid cipher format")
	}

	eccCipher := ECCCipher{}
	copy(eccCipher.X[32:], sm2Cipher.X.Bytes())
	copy(eccCipher.Y[32:], sm2Cipher.Y.Bytes())
	copy(eccCipher.M[:], sm2Cipher.HASH)
	eccCipher.L = uint32(len(sm2Cipher.CipherText))
	copy(eccCipher.C[:], sm2Cipher.CipherText)

	return eccCipher, nil
}

// Sm2PubkeyVerify:ECC外部签名公钥验签,需要先对数据预处理,验证ASN.1格式签名
func Sm2PubkeyVerify(session HANDLE, pubKey []byte, hash []byte, sig []byte) error {
	sm2Sig, err := SignatureUnmarshal(sig)
	if err != nil {
		return err
	}

	pub, err := PublicKeyUmmarshal(pubKey)
	if err != nil {
		return err
	}

	if ret := ExternalVerifyECC(session, pub, hash, sm2Sig); ret != SDR_OK {
		return ret.Error()
	}
	return nil
}

// Sm2PubkeyVerifyData:ECC外部签名公钥验签,直接对数据验证ASN.1格式签名
func Sm2PubkeyVerifyData(pubKey []byte, data []byte, sig []byte) error {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return ret.Error()
	}
	defer CloseSession(session)

	pub, err := PublicKeyUmmarshal(pubKey)
	if err != nil {
		return err
	}

	// 对数据预处理,使用默认用户ID
	ret = HashInit(session, SGD_SM3, &pub, defaultID)
	if ret != SDR_OK {
		return ret.Error()
	}

	ret = HashUpdate(session, data)
	if ret != SDR_OK {
		return ret.Error()
	}

	hash, ret := HashFinal(session)
	if ret != SDR_OK {
		return ret.Error()
	}

	return Sm2PubkeyVerify(session, pubKey, hash, sig)
}

// Sm2ExportEncPublicKey:导出加密公钥,返回04||x||y格式
func Sm2ExportEncPublicKey(keyIndex uint32) ([]byte, error) {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return nil, ret.Error()
	}
	defer CloseSession(session)

	pubKey, ret := ExportEncPublicKeyECC(session, keyIndex)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	return PublicKeyMarshal(pubKey), nil
}

// Sm2Encrypt:使用公钥加密
func Sm2Encrypt(pubKey []byte, data []byte) ([]byte, error) {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return nil, ret.Error()
	}
	defer CloseSession(session)

	pub, err := PublicKeyUmmarshal(pubKey)
	if err != nil {
		return nil, err
	}

	cipherEcc, ret := ExternalEncryptECC(session, pub, data)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	cipher, err := CipherMarshal(cipherEcc)
	if err != nil {
		return nil, err
	}

	return cipher, nil
}

// Sm2InternalSign:内部ECC签名私钥签名,需要先对数据预处理,生成ASN.1格式签名
func Sm2InternalSign(session HANDLE, keyIndex uint32, hash []byte) ([]byte, error) {
	// 获取私钥使用权限?
	sig, ret := InternalSignECC(session, keyIndex, hash)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	sm2Sig, err := SignatureMarshal(sig)
	if err != nil {
		return nil, err
	}

	return sm2Sig, nil
}

// Sm2SignData:内部ECC签名私钥签名,直接对数据进行签名.返回ASN.1格式签名
func Sm2SignData(keyIndex uint32, data []byte) ([]byte, error) {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return nil, ret.Error()
	}
	defer CloseSession(session)

	// 导出内部公钥用于预处理
	signPub, ret := ExportSignPublicKeyECC(session, keyIndex)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	// 对数据预处理,使用默认用户ID
	ret = HashInit(session, SGD_SM3, &signPub, defaultID)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	ret = HashUpdate(session, data)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	hash, ret := HashFinal(session)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	// 对HASH签名
	return Sm2InternalSign(session, keyIndex, hash)
}

// Sm2InternalVerify:内部ECC签名公钥验签,验证ASN.1格式签名
func Sm2InternalVerify(session HANDLE, keyIndex uint32, hash []byte, sig []byte) error {
	sm2Sig, err := SignatureUnmarshal(sig)
	if err != nil {
		return err
	}

	if ret := InternalVerifyECC(session, keyIndex, hash, sm2Sig); ret != SDR_OK {
		return ret.Error()
	}

	return nil
}

// Sm2VerifyData:内部ECC签名公钥验签,直接对数据进行验证,输入ASN.1格式签名
func Sm2VerifyData(keyIndex uint32, data, sig []byte) error {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return ret.Error()
	}
	defer CloseSession(session)

	// 导出内部公钥用于预处理
	signPub, ret := ExportSignPublicKeyECC(session, keyIndex)
	if ret != SDR_OK {
		return ret.Error()
	}

	// 对数据预处理,使用默认用户ID
	ret = HashInit(session, SGD_SM3, &signPub, defaultID)
	if ret != SDR_OK {
		return ret.Error()
	}

	ret = HashUpdate(session, data)
	if ret != SDR_OK {
		return ret.Error()
	}

	hash, ret := HashFinal(session)
	if ret != SDR_OK {
		return ret.Error()
	}

	// 对HASH签名验签
	return Sm2InternalVerify(session, keyIndex, hash, sig)
}

// TODO:数字信封 SM2-SM4-CBC
// 封装:GenerateKeyWithEPKECC/Encrypt
// 解封:ImportKeyWithISKECC/Decrypt
