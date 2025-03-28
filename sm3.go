package gosdf

// Sm3Init:sm3 init，传入打开的会话
func Sm3Init(session HANDLE) RV {
	return HashInit(session, SGD_SM3, nil, nil)
}

// Sm3InitWithPubKey:sm3 init，传入打开的会话,公钥进行预处理，用于签名验签
// 公钥使用04||X||Y的格式
func Sm3InitWithPubKey(session HANDLE, pubKey []byte, id []byte) RV {
	pub, err := PublicKeyUmmarshal(pubKey)
	if err != nil {
		return SDR_INARGERR
	}

	return HashInit(session, SGD_SM3, &pub, id)
}
