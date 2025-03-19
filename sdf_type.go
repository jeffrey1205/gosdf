package gosdf

// 错误码定义
type RV uint32
type HANDLE *int

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

const (
	ECCref_MAX_BITS              int32 = 512
	ECCref_MAX_LEN               int32 = ((ECCref_MAX_BITS + 7) / 8)
	ECCref_MAX_CIPHER_LEN        int32 = 136
	ECC_MAX_XCOORDINATE_BITS_LEN int32 = 512
	ECC_MAX_YCOORDINATE_BITS_LEN int32 = ECC_MAX_XCOORDINATE_BITS_LEN
	ECC_MAX_MODULUS_BITS_LEN     int32 = ECC_MAX_XCOORDINATE_BITS_LEN
)

type ECCrefPublicKey struct {
	Bits uint32
	X    [ECCref_MAX_LEN]byte
	Y    [ECCref_MAX_LEN]byte
}

type ECCrefPrivateKey struct {
	Bits uint32
	K    [ECCref_MAX_LEN]byte
}

type ECCCipher struct {
	X [ECCref_MAX_LEN]byte
	Y [ECCref_MAX_LEN]byte
	M [32]byte
	L uint32                      // 密文长度,单位字节
	C [ECCref_MAX_CIPHER_LEN]byte // 密文内容,更长的加密需求使用数字信封
}

type ECCSignature struct {
	R [ECCref_MAX_LEN]byte
	S [ECCref_MAX_LEN]byte
}

type ECCPUBLICKEYBLOB struct {
	BitLen      uint32
	XCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	YCoordinate [ECC_MAX_YCOORDINATE_BITS_LEN / 8]byte
}

type ECCCIPHERBLOB struct {
	XCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	YCoordinate [ECC_MAX_XCOORDINATE_BITS_LEN / 8]byte
	Hash        [32]byte
	CipherLen   uint32
	Cipher      [128]byte
}
