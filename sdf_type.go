package gosdf

import (
	"fmt"
	"math/big"
)

// 数据类型
type HANDLE *int
type ALGID uint32

// 算法标识
const (
	SM1_ECB ALGID = 0x00000101
	SM1_CBC ALGID = 0x00000102
	SM1_CFB ALGID = 0x00000104
	SM1_OFB ALGID = 0x00000108
	SM1_MAC ALGID = 0x00000110
	SM1_CTR ALGID = 0x00000120

	SM4_ECB ALGID = 0x00000401
	SM4_CBC ALGID = 0x00000402
	SM4_CFB ALGID = 0x00000404
	SM4_OFB ALGID = 0x00000408
	SM4_MAC ALGID = 0x00000410
	SM4_CTR ALGID = 0x00000420
	SM4_XTS ALGID = 0x00000440

	SM7_ECB ALGID = 0x00001001
	SM7_CBC ALGID = 0x00001002
	SM7_CFB ALGID = 0x00001004
	SM7_OFB ALGID = 0x00001008
	SM7_MAC ALGID = 0x00001010
	SM7_CTR ALGID = 0x00001020

	AES_ECB ALGID = 0x00008001
	AES_CBC ALGID = 0x00008002
	AES_CFB ALGID = 0x00008004
	AES_OFB ALGID = 0x00008008
	AES_MAC ALGID = 0x00008010
	AES_CTR ALGID = 0x00008020

	SGD_SM3    ALGID = 0x00000001
	SGD_SHA1   ALGID = 0x00000002
	SGD_SHA256 ALGID = 0x00000004
	SGD_SHA512 ALGID = 0x00000008
	SGD_SHA384 ALGID = 0x00000010
	SGD_SHA224 ALGID = 0x00000020
	SGD_MD5    ALGID = 0x00000080
)

// 错误码定义
type RV uint32

const (
	SDR_OK               RV = 0x0                   // 操作成功
	SDR_BASE             RV = 0x01000000            // 错误码基础值
	SDR_UNKNOWERR        RV = SDR_BASE + 0x00000001 // 未知错误
	SDR_NOTSUPPORT       RV = SDR_BASE + 0x00000002 // 不支持的接口调用
	SDR_COMMFAIL         RV = SDR_BASE + 0x00000003 // 与设备通信失败
	SDR_HARDFAIL         RV = SDR_BASE + 0x00000004 // 运算模块无响应
	SDR_OPENDEVICE       RV = SDR_BASE + 0x00000005 // 打开设备失败
	SDR_OPENSESSION      RV = SDR_BASE + 0x00000006 // 创建会话失败
	SDR_PARDENY          RV = SDR_BASE + 0x00000007 // 无私钥使用权限
	SDR_KEYNOTEXIST      RV = SDR_BASE + 0x00000008 // 不存在的密钥调用
	SDR_ALGNOTSUPPORT    RV = SDR_BASE + 0x00000009 // 不支持的算法调用
	SDR_ALGMODNOTSUPPORT RV = SDR_BASE + 0x0000000A // 不支持的算法模式调用
	SDR_PKOPERR          RV = SDR_BASE + 0x0000000B // 公钥运算失败
	SDR_SKOPERR          RV = SDR_BASE + 0x0000000C // 私钥运算失败
	SDR_SIGNERR          RV = SDR_BASE + 0x0000000D // 签名运算失败
	SDR_VERIFYERR        RV = SDR_BASE + 0x0000000E // 验证签名失败
	SDR_SYMOPERR         RV = SDR_BASE + 0x0000000F // 对称算法运算失败
	SDR_STEPERR          RV = SDR_BASE + 0x00000010 // 多步运算步骤错误
	SDR_FILESIZEERR      RV = SDR_BASE + 0x00000011 // 文件长度超出限制
	SDR_FILENOEXIST      RV = SDR_BASE + 0x00000012 // 指定的文件不存在
	SDR_FILEOFSERR       RV = SDR_BASE + 0x00000013 // 文件起始位置错误
	SDR_KEYTYPEERR       RV = SDR_BASE + 0x00000014 // 密钥类型错误
	SDR_KEYERR           RV = SDR_BASE + 0x00000015 // 密钥错误
	SDR_ENCDATAERR       RV = SDR_BASE + 0x00000016 // ECC加密数据错误
	SDR_RANDERR          RV = SDR_BASE + 0x00000017 // 随机数产生错误
	SDR_PRKRERR          RV = SDR_BASE + 0x00000018 // 私钥使用权限获取失败
	SDR_MACERR           RV = SDR_BASE + 0x00000019 // MAC运算失败
	SDR_FILEEXISTS       RV = SDR_BASE + 0x0000001A // 指定文件已存在
	SDR_FILEWERR         RV = SDR_BASE + 0x0000001B // 文件写入失败
	SDR_NOBUFFER         RV = SDR_BASE + 0x0000001C // 存储空间不足
	SDR_INARGERR         RV = SDR_BASE + 0x0000001D // 输入参数错误
	SDR_OUTARGERR        RV = SDR_BASE + 0x0000001E // 输出参数错误
)

func (rv RV) Error() error {
	return fmt.Errorf("SGD Error code: %x", rv)
}

const (
	ECCref_MAX_BITS              int32 = 512
	ECCref_MAX_LEN               int32 = ((ECCref_MAX_BITS + 7) / 8)
	ECCref_MAX_CIPHER_LEN        int32 = 128
	ECC_MAX_XCOORDINATE_BITS_LEN int32 = 512
	ECC_MAX_YCOORDINATE_BITS_LEN int32 = ECC_MAX_XCOORDINATE_BITS_LEN
	ECC_MAX_MODULUS_BITS_LEN     int32 = ECC_MAX_XCOORDINATE_BITS_LEN
)

const Sm4BlockSize int = 16
const Sm3HashSize int = 32

type ECCrefPublicKey struct {
	Bits uint32
	X    [ECCref_MAX_LEN]byte
	Y    [ECCref_MAX_LEN]byte
}

type ECCrefPrivateKey struct {
	Bits uint32
	K    [ECCref_MAX_LEN]byte
}

// ECC加密结果. GM/T 0018格式
type ECCCipher struct {
	X [ECCref_MAX_LEN]byte
	Y [ECCref_MAX_LEN]byte
	M [Sm3HashSize]byte
	L uint32                      // 密文长度,单位字节
	C [ECCref_MAX_CIPHER_LEN]byte // 密文内容,更长的加密需求使用数字信封
}

type sm2Cipher struct {
	X          *big.Int
	Y          *big.Int
	HASH       []byte
	CipherText []byte
}

// 数字签名结果. GM/T 0018格式
type ECCSignature struct {
	R [ECCref_MAX_LEN]byte
	S [ECCref_MAX_LEN]byte
}

type sm2Signature struct {
	R, S *big.Int
}

type ECCPUBLICKEYBLOB struct {
	BitLen      uint32
	XCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	YCoordinate [ECC_MAX_YCOORDINATE_BITS_LEN / 8]byte
}

type ECCCIPHERBLOB struct {
	XCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	YCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	Hash        [Sm3HashSize]byte
	CipherLen   uint32
	Cipher      [ECCref_MAX_CIPHER_LEN]byte
}
