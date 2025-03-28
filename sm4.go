package gosdf

import "github.com/emmansun/gmsm/padding"

type Sm4Crypter struct {
	session   HANDLE
	keyHandle HANDLE
	KeyByte   []byte
	Pad       bool // 每次调用不满整分组是否填充,PKCS7
	mode      ALGID
	p7pad     padding.Padding // 加密使用
	m3pad     padding.Padding // MAC使用
}

// ECB模式初始IV均为0
var zeroIV = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Sm4New:新建一个SM4加密器
func Sm4New(mode ALGID, pad bool) *Sm4Crypter {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return nil
	}

	return &Sm4Crypter{
		session:   session,
		keyHandle: nil,
		mode:      mode,
		p7pad:     padding.NewPKCS7Padding(uint(SM4_BLOCKSIZE)),
		m3pad:     padding.NewISO9797M3Padding(uint(SM4_BLOCKSIZE)),
		KeyByte:   nil,
		Pad:       pad,
	}
}

func (c *Sm4Crypter) Destroy() {
	if c.keyHandle != nil {
		DestroyKey(c.session, c.keyHandle)
	} else if c.session != nil {
		CloseSession(c.session)
	}
}

// GenerateKey:使用内部密钥生成SM4会话密钥
func (c *Sm4Crypter) NewKey(kek uint32) RV {
	key, handle, ret := GenerateKeyWithKEK(c.session, kek, SM4_ECB, uint32(SM4_BLOCKSIZE))
	if ret != SDR_OK {
		return ret
	}

	c.keyHandle = handle
	c.KeyByte = key
	return SDR_OK
}

// SetKey:import会话密钥
func (c *Sm4Crypter) SetKey(kek uint32, key []byte) RV {
	handle, ret := ImportKeyWithKEK(c.session, kek, SM4_CBC, key)
	if ret != SDR_OK {
		return ret
	}

	c.keyHandle = handle
	return SDR_OK
}

// Encrypt:sm4加密，CBC等需要IV、Nonce模式须16字节IV,ECB可不填
func (c *Sm4Crypter) Encrypt(iv, data []byte) ([]byte, RV) {
	if c.Pad && len(data)%SM4_BLOCKSIZE != 0 { // 不是满分组进行填充
		data = c.p7pad.Pad(data)
	}

	if iv == nil { // 此处补上空IV,防止传入空IV导致panic
		iv = zeroIV
	}

	return Encrypt(c.session, c.keyHandle, c.mode, iv, data)
}

// Decrypt:sm4解密，CBC等需要IV、Nonce模式须16字节IV,ECB可不填
func (c *Sm4Crypter) Decrypt(iv, data []byte) ([]byte, RV) {
	if iv == nil { // 此处补上空IV,防止传入空IV导致panic
		iv = zeroIV
	}

	plainText, err := Decrypt(c.session, c.keyHandle, c.mode, iv, data)
	if err != 0 {
		return nil, err
	}

	if c.Pad { // 此处有可能没有填充
		plainText, _ = c.p7pad.Unpad(plainText)
	}
	return plainText, err
}

// CBCMAC:计算SM4 CBC-MAC,此函数为单包计算,若要多包计算,使用IV进行控制
// CBC-MAC在长度不固定时有长度扩展攻击问题.使用ISO9797-1 M3填充方式抵御攻击
func (c *Sm4Crypter) CBCMAC(iv []byte, data []byte) ([]byte, RV) {
	if c.Pad {
		return CalculateMAC(c.session, c.keyHandle, SM4_MAC, iv, c.m3pad.Pad(data))
	}
	return CalculateMAC(c.session, c.keyHandle, SM4_MAC, iv, data)
}
