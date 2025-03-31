package gosdf

import "github.com/emmansun/gmsm/padding"

type BlockCrypter struct {
	session   HANDLE          // 会话句柄
	keyHandle HANDLE          // 密钥句柄
	keyByte   []byte          // 密钥密文
	blockSize uint            // 分组长度
	pad       bool            // 每次调用不满整分组是否填充,PKCS7
	mode      ALGID           // 加密/MAC模式
	p7pad     padding.Padding // 加密使用
	m3pad     padding.Padding // MAC使用
}

// ECB模式初始IV均为0
var zeroIV = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// NewCrypter:新建一个分组模式加密器.默认填充
// ECB/CBC多包加密、解密时,先关闭填充,最后一次打开填充.CTR/CFB/OFB直接填充
// 多包MAC时,可关闭填充,手动填充
func NewCrypter(mode ALGID) *BlockCrypter {
	session, ret := OpenSession()
	if ret != SDR_OK {
		return nil
	}

	return &BlockCrypter{
		session:   session,
		keyHandle: nil,
		blockSize: uint(Sm4BlockSize),
		pad:       true,
		mode:      mode,
		p7pad:     padding.NewPKCS7Padding(uint(Sm4BlockSize)),
		m3pad:     padding.NewISO9797M3Padding(uint(Sm4BlockSize)),
		keyByte:   nil,
	}
}

// Key:获取会话密钥密文
func (c *BlockCrypter) Key() []byte {
	return c.keyByte
}

// EnablePad:开启或者禁用填充
func (c *BlockCrypter) EnablePad(pad bool) {
	c.pad = pad
}

// Destroy:释放密钥和会话句柄,释放资源
func (c *BlockCrypter) Destroy() {
	if c.keyHandle != nil {
		DestroyKey(c.session, c.keyHandle)
	} else if c.session != nil {
		CloseSession(c.session)
	}
}

// GenerateKey:使用内部密钥生成会话密钥,用SM4-ECB加密
func (c *BlockCrypter) NewKey(kek uint32) error {
	key, handle, ret := GenerateKeyWithKEK(c.session, kek, SM4_ECB, uint32(c.blockSize)*8)
	if ret != SDR_OK {
		return ret.Error()
	}

	c.keyHandle = handle
	c.keyByte = key
	return nil
}

// SetKey:import会话密钥
func (c *BlockCrypter) SetKey(kek uint32, key []byte) error {
	handle, ret := ImportKeyWithKEK(c.session, kek, SM4_ECB, key)
	if ret != SDR_OK {
		return ret.Error()
	}

	c.keyHandle = handle
	return nil
}

// Encrypt:加密，CBC等需要IV、Nonce模式须16字节IV,ECB可不填
func (c *BlockCrypter) Encrypt(iv, plain []byte) ([]byte, error) {
	if c.pad && len(plain)%int(c.blockSize) != 0 { // 不是满分组进行填充
		plain = c.p7pad.Pad(plain)
	}

	if iv == nil { // 此处补上空IV,防止传入空IV导致panic
		iv = zeroIV
	}

	if cipher, ret := Encrypt(c.session, c.keyHandle, c.mode, iv, plain); ret != SDR_OK {
		return nil, ret.Error()
	} else {
		return cipher, nil
	}
}

// Decrypt:解密，CBC等需要IV、Nonce模式须16字节IV,ECB可不填
func (c *BlockCrypter) Decrypt(iv, cipher []byte) ([]byte, error) {
	if iv == nil { // 此处补上空IV,防止传入空IV导致panic
		iv = zeroIV
	}

	plainText, ret := Decrypt(c.session, c.keyHandle, c.mode, iv, cipher)
	if ret != SDR_OK {
		return nil, ret.Error()
	}

	if c.pad { // 此处有可能没有填充
		if unPadText, err := c.p7pad.Unpad(plainText); err != nil {
			return plainText, nil // 去填充失败,可能没有填充.返回原数据
		} else {
			return unPadText, nil
		}
	}
	return plainText, nil
}

// CBCMAC:CBC-MAC,此函数为单包计算,若要多包计算,使用IV进行控制
// CBC-MAC在长度不固定时可能有长度扩展攻击问题.
// 单包计算时,使用ISO9797-1 M3填充方式抵御攻击.多包计算先填充再计算
func (c *BlockCrypter) CBCMAC(iv []byte, data []byte) ([]byte, error) {
	var mac []byte
	var ret RV

	if c.pad {
		mac, ret = CalculateMAC(c.session, c.keyHandle, c.mode, iv, c.m3pad.Pad(data))
	} else {
		mac, ret = CalculateMAC(c.session, c.keyHandle, c.mode, iv, data)
	}

	if ret != SDR_OK {
		return nil, ret.Error()
	}
	return mac, nil
}
