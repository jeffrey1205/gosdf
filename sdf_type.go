package gosdf

// 错误码定义
type SDR int32

const (
	SDR_OK               SDR = 0x0                   // 操作成功
	SDR_BASE             SDR = 0x01000000            // 错误码基础值
	SDR_UNKNOWERR        SDR = SDR_BASE + 0x00000001 // 未知错误
	SDR_NOTSUPPORT       SDR = SDR_BASE + 0x00000002 // 不支持的接口调用
	SDR_COMMFAIL         SDR = SDR_BASE + 0x00000003 // 与设备通信失败
	SDR_HARDFAIL         SDR = SDR_BASE + 0x00000004 // 运算模块无响应
	SDR_OPENDEVICE       SDR = SDR_BASE + 0x00000005 // 打开设备失败
	SDR_OPENSESSION      SDR = SDR_BASE + 0x00000006 // 创建会话失败
	SDR_PARDENY          SDR = SDR_BASE + 0x00000007 // 无私钥使用权限
	SDR_KEYNOTEXIST      SDR = SDR_BASE + 0x00000008 // 不存在的密钥调用
	SDR_ALGNOTSUPPORT    SDR = SDR_BASE + 0x00000009 // 不支持的算法调用
	SDR_ALGMODNOTSUPPORT SDR = SDR_BASE + 0x0000000A // 不支持的算法模式调用
	SDR_PKOPERR          SDR = SDR_BASE + 0x0000000B // 公钥运算失败
	SDR_SKOPERR          SDR = SDR_BASE + 0x0000000C // 私钥运算失败
	SDR_SIGNERR          SDR = SDR_BASE + 0x0000000D // 签名运算失败
	SDR_VERIFYERR        SDR = SDR_BASE + 0x0000000E // 验证签名失败
	SDR_SYMOPERR         SDR = SDR_BASE + 0x0000000F // 对称算法运算失败
	SDR_STEPERR          SDR = SDR_BASE + 0x00000010 // 多步运算步骤错误
	SDR_FILESIZEERR      SDR = SDR_BASE + 0x00000011 // 文件长度超出限制
	SDR_FILENOEXIST      SDR = SDR_BASE + 0x00000012 // 指定的文件不存在
	SDR_FILEOFSERR       SDR = SDR_BASE + 0x00000013 // 文件起始位置错误
	SDR_KEYTYPEERR       SDR = SDR_BASE + 0x00000014 // 密钥类型错误
	SDR_KEYERR           SDR = SDR_BASE + 0x00000015 // 密钥错误
	SDR_ENCDATAERR       SDR = SDR_BASE + 0x00000016 // ECC加密数据错误
	SDR_RANDERR          SDR = SDR_BASE + 0x00000017 // 随机数产生错误
	SDR_PRKRERR          SDR = SDR_BASE + 0x00000018 // 私钥使用权限获取失败
	SDR_MACERR           SDR = SDR_BASE + 0x00000019 // MAC运算失败
	SDR_FILEEXISTS       SDR = SDR_BASE + 0x0000001A // 指定文件已存在
	SDR_FILEWERR         SDR = SDR_BASE + 0x0000001B // 文件写入失败
	SDR_NOBUFFER         SDR = SDR_BASE + 0x0000001C // 存储空间不足
	SDR_INARGERR         SDR = SDR_BASE + 0x0000001D // 输入参数错误
	SDR_OUTARGERR        SDR = SDR_BASE + 0x0000001E // 输出参数错误
)

const (
	ECCref_MAX_BITS              int32 = 512
	ECCref_MAX_LEN               int32 = ((ECCref_MAX_BITS + 7) / 8)
	ECC_MAX_XCOORDINATE_BITS_LEN int32 = 512
	ECC_MAX_YCOORDINATE_BITS_LEN int32 = ECC_MAX_XCOORDINATE_BITS_LEN
	ECC_MAX_MODULUS_BITS_LEN     int32 = ECC_MAX_XCOORDINATE_BITS_LEN
)

type ECCrefPublicKey struct {
	bits uint32
	x    [ECCref_MAX_LEN]byte
	y    [ECCref_MAX_LEN]byte
}

type ECCrefPrivateKey struct {
	bits uint32
	K    [ECCref_MAX_LEN]byte
}

type ECCCipher struct {
	x [ECCref_MAX_LEN]byte
	y [ECCref_MAX_LEN]byte
	M [32]byte
	L uint32
	C [1]byte
}

type ECCSignature struct {
	r [ECCref_MAX_LEN]byte
	s [ECCref_MAX_LEN]byte
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
