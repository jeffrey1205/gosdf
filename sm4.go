package gosdf

import "github.com/emmansun/gmsm/padding"

// SM4EncryptECB:sm4加密，ECB模式，无需填充
func SM4EncryptECB(session, key HANDLE, data []byte) ([]byte, RV) {
	iv := make([]byte, SM4_BLOCKSIZE)
	if len(data)%SM4_BLOCKSIZE != 0 { // 不是满分组进行填充
		pad := padding.NewPKCS7Padding(uint(SM4_BLOCKSIZE)) // PKCS7Padding
		data = pad.Pad(data)
	}
	return Encrypt(session, key, SM4_ECB, iv, data)
}

// SM4EncryptCBC:sm4加密，CBC模式，无需填充
func SM4EncryptCBC(session, key HANDLE, iv, data []byte) ([]byte, RV) {
	if len(data)%SM4_BLOCKSIZE != 0 { // 不是满分组进行填充
		pad := padding.NewPKCS7Padding(uint(SM4_BLOCKSIZE)) // PKCS7Padding
		data = pad.Pad(data)
	}
	return Encrypt(session, key, SM4_CBC, iv, data)
}

// SM4DecryptECB:sm4解密，ECB模式
func SM4DecryptECB(session, key HANDLE, data []byte) ([]byte, RV) {
	iv := make([]byte, SM4_BLOCKSIZE)
	pad := padding.NewPKCS7Padding(uint(SM4_BLOCKSIZE)) // PKCS7 UnPadding
	plainText, err := Decrypt(session, key, SM4_ECB, iv, data)
	if err != 0 {
		return nil, err
	}

	plainText, errPad := pad.Unpad(plainText)
	if errPad != nil {
		return nil, SDR_FILESIZEERR
	}
	return plainText, err
}

// SM4DecryptCBC:sm4解密，CBC模式
func SM4DecryptCBC(session, key HANDLE, iv, data []byte) ([]byte, RV) {
	pad := padding.NewPKCS7Padding(uint(SM4_BLOCKSIZE)) // PKCS7 UnPadding
	plainText, err := Decrypt(session, key, SM4_CBC, iv, data)
	if err != 0 {
		return nil, err
	}

	plainText, errPad := pad.Unpad(plainText)
	if errPad != nil {
		return nil, SDR_FILESIZEERR
	}
	return plainText, err
}

// SM4CalculateCBCMAC:计算SM4 CBC-MAC,此函数为单包计算,若要多包计算,使用IV进行控制
// CBC-MAC在长度不固定时有长度扩展攻击问题.使用ISO9797-1 M3填充方式抵御攻击
func SM4CalculateCBCMAC(session, key HANDLE, iv []byte, data []byte) ([]byte, RV) {
	pad := padding.NewISO9797M3Padding(uint(SM4_BLOCKSIZE)) // M3 Padding
	return CalculateMAC(session, key, SM4_MAC, iv, pad.Pad(data))
}
