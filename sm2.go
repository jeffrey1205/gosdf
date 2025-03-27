package gosdf

import (
	"encoding/asn1"
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

// Sm2ExternalVerify:ECC外部签名公钥验签,验证ASN.1格式签名
func Sm2ExternalVerify(session HANDLE, pubKey ECCrefPublicKey, hash []byte, sig []byte) RV {
	sm2Sig, err := SignatureUnmarshal(sig)
	if err != nil {
		return SDR_INARGERR
	}

	return ExternalVerifyECC(session, pubKey, hash, sm2Sig)
}

// Sm2ExternalVerifyData:ECC外部签名公钥验签,直接对数据验证ASN.1格式签名
func Sm2ExternalVerifyData(pubKey ECCrefPublicKey, data []byte, sig []byte) RV {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return ret
	}
	defer CloseSession(session)

	// 对数据预处理,使用默认用户ID
	ret = Sm3InitWithPubKey(session, pubKey, defaultID)
	if ret != SDR_OK {
		return ret
	}

	ret = HashUpdate(session, data)
	if ret != SDR_OK {
		return ret
	}

	hash, ret := HashFinal(session)
	if ret != SDR_OK {
		return ret
	}

	return Sm2ExternalVerify(session, pubKey, hash, sig)
}

// Sm2InternalSign:内部ECC签名私钥签名,生成ASN.1格式签名
func Sm2InternalSign(session HANDLE, keyIndex uint32, hash []byte) ([]byte, RV) {
	sig, ret := InternalSignECC(session, keyIndex, hash)
	if ret != SDR_OK {
		return nil, ret
	}

	sm2Sig, err := SignatureMarshal(sig)
	if err != nil {
		return nil, SDR_SIGNERR
	}

	return sm2Sig, SDR_OK
}

// Sm2SignData:内部ECC签名私钥签名,直接对数据进行签名.返回ASN.1格式签名
func Sm2SignData(keyIndex uint32, data []byte) ([]byte, RV) {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return nil, ret
	}
	defer CloseSession(session)

	// 导出内部公钥用于预处理
	signPub, ret := ExportSignPublicKeyECC(session, keyIndex)
	if ret != SDR_OK {
		return nil, ret
	}

	// 对数据预处理,使用默认用户ID
	ret = Sm3InitWithPubKey(session, signPub, defaultID)
	if ret != SDR_OK {
		return nil, ret
	}

	ret = HashUpdate(session, data)
	if ret != SDR_OK {
		return nil, ret
	}

	hash, ret := HashFinal(session)
	if ret != SDR_OK {
		return nil, ret
	}

	// 对HASH签名
	return Sm2InternalSign(session, keyIndex, hash)
}

// Sm2InternalVerify:内部ECC签名公钥验签,验证ASN.1格式签名
func Sm2InternalVerify(session HANDLE, keyIndex uint32, hash []byte, sig []byte) RV {
	sm2Sig, err := SignatureUnmarshal(sig)
	if err != nil {
		return SDR_INARGERR
	}
	return InternalVerifyECC(session, keyIndex, hash, sm2Sig)
}

// Sm2VerifyData:内部ECC签名公钥验签,直接对数据进行验证,输入ASN.1格式签名
func Sm2VerifyData(keyIndex uint32, data, sig []byte) RV {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return ret
	}
	defer CloseSession(session)

	// 导出内部公钥用于预处理
	signPub, ret := ExportSignPublicKeyECC(session, keyIndex)
	if ret != SDR_OK {
		return ret
	}

	// 对数据预处理,使用默认用户ID
	ret = Sm3InitWithPubKey(session, signPub, defaultID)
	if ret != SDR_OK {
		return ret
	}

	ret = HashUpdate(session, data)
	if ret != SDR_OK {
		return ret
	}

	hash, ret := HashFinal(session)
	if ret != SDR_OK {
		return ret
	}

	// 对HASH签名验签
	return Sm2InternalVerify(session, keyIndex, hash, sig)
}
