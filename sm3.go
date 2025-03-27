package gosdf

// Sm3Init:sm3 init，传入打开的会话
func Sm3Init(session HANDLE) RV {
	return HashInit(session, SGD_SM3, nil, nil)
}

// Sm3InitWithPubKey:sm3 init，传入打开的会话,公钥进行预处理，用于签名验签
func Sm3InitWithPubKey(session HANDLE, pubKey ECCrefPublicKey, id []byte) RV {
	return HashInit(session, SGD_SM3, &pubKey, id)
}
