package gosdf

import "fmt"

// 数据类型
type (
	HANDLE *int
	ALGID  uint32
)

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
	SM4_GCM ALGID = 0x02000400 // SGD_SM4_GCM,GMT 0006-2023 表1(2012 时代厂商 sdf.h 定义同值)
	SM4_CCM ALGID = 0x04000400 // SGD_SM4_CCM,GMT 0006-2023 表1(2012 时代厂商 sdf.h 定义同值)

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

	// 杂凑/HMAC 标识:GMT 0006-2023 表3。SDF_HashInit/SDF_HMACInit 的 uiAlgID
	// 为杂凑算法标识(SGD_SM3/SGD_SHA256);SGD_SM3_HMAC/SGD_SHA256_HMAC 为
	// GMT 0006 定义的 HMAC 算法标识。2012 时代 sdf.h:365-371 的
	// SHA1/SHA224/SHA512/SHA384/MD5 已废弃,不再定义。
	SGD_SM3         ALGID = 0x00000001
	SGD_SHA256      ALGID = 0x00000004
	SGD_SM3_HMAC    ALGID = 0x00000008
	SGD_SHA256_HMAC ALGID = 0x00000010

	SGD_SM2   ALGID = 0x00020100 // SM2算法
	SGD_SM2_1 ALGID = 0x00020200 // SM2签名
	SGD_SM2_2 ALGID = 0x00020400 // SM2密钥交换
	SGD_SM2_3 ALGID = 0x00020800 // SM2加密
)

// BlockSize 返回对称算法的分组长度:SM1/SM4/SM7/AES 系列(含 MAC/CTR 等模式变体)为 16,
// 其余(杂凑、SM2、RSA 等,以及 GCM/CCM 等流式 AEAD 模式无分组语义)返回 0。
func (a ALGID) BlockSize() int {
	switch a & 0xFFFFFF00 {
	case 0x00000100, 0x00000400, 0x00001000, 0x00008000:
		return 16
	}
	return 0
}

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
	SDR_USERIDERR        RV = SDR_BASE + 0x0000001F // 用户标识错误(2023 附录 A)
)

// Error 实现 error 接口,RV 即设备错误值。
func (rv RV) Error() string {
	return fmt.Sprintf("SGD error 0x%08x", uint32(rv))
}

// rvErr 将设备错误码包装为带操作名的 error,支持 errors.Is/As。
func rvErr(op string, rv RV) error {
	return fmt.Errorf("gosdf: %s: %w", op, rv)
}

// argErr 参数校验失败,统一包装 SDR_INARGERR。
func argErr(op string) error {
	return rvErr(op, SDR_INARGERR)
}

// padLeft 将 src 右对齐拷入定长 dst,左侧补零。
// src 超过 dst 长度时报 SDR_INARGERR。
func padLeft(dst, src []byte) error {
	if len(src) > len(dst) {
		return argErr("padLeft")
	}
	clear(dst)
	copy(dst[len(dst)-len(src):], src)
	return nil
}

const (
	ECCref_MAX_BITS       int32 = 512
	ECCref_MAX_LEN        int32 = ((ECCref_MAX_BITS + 7) / 8)
	ECCref_MAX_CIPHER_LEN int32 = 136 // 密文内容 C 的字节上限(ECCref_MAX_CIPHER_LEN=136,2012 时代厂商 sdf.h 的 ECCCipher.C 容量)
)

// RSAref_* 对应 sdf.h RSA 密钥结构位长上限:模数 2048 位、素因子 1024 位。
const (
	RSAref_MAX_BITS  int32 = 2048
	RSAref_MAX_LEN   int32 = ((RSAref_MAX_BITS + 7) / 8)
	RSAref_MAX_PBITS int32 = ((RSAref_MAX_BITS + 1) / 2)
	RSAref_MAX_PLEN  int32 = ((RSAref_MAX_PBITS + 7) / 8)
)

const (
	Sm4BlockSize int = 16
	Sm3HashSize  int = 32
)

// ECCrefPublicKey 对应 sdf.h ECCrefPublicKey(bits + X + Y,132 字节)。
type eccRefPublicKey struct {
	Bits uint32
	X    [ECCref_MAX_LEN]byte
	Y    [ECCref_MAX_LEN]byte
}

// eccRefPrivateKey 对应 sdf.h ECCrefPrivateKey(privFromECC/GenerateKeyPairECC 使用的私钥布局)。
type eccRefPrivateKey struct {
	Bits uint32
	K    [ECCref_MAX_LEN]byte
}

// eccSignature 对应 sdf.h ECCSignature(R||S 各 64 字节)。
type eccSignature struct {
	R [ECCref_MAX_LEN]byte
	S [ECCref_MAX_LEN]byte
}

// rsaRefPublicKey 对应 sdf.h RSArefPublicKey(bits+m+e,共 516 字节):
// bits@0(uint32)、m@4、e@260;模数与指数为无符号大端定长数组(左补零)。
type rsaRefPublicKey struct {
	Bits uint32
	M    [RSAref_MAX_LEN]byte
	E    [RSAref_MAX_LEN]byte
}

// rsaRefPrivateKey 对应 sdf.h RSArefPrivateKey(共 1412 字节):
// bits@0(uint32)、m@4、e@260、d@516、prime@772(2×128)、pexp@1028(2×128)、
// coef@1284;均为无符号大端定长数组(左补零),CRT 参数
// prime=[P|Q]、pexp=[dP|dQ]、coef=[qInv]。
type rsaRefPrivateKey struct {
	Bits  uint32
	M     [RSAref_MAX_LEN]byte
	E     [RSAref_MAX_LEN]byte
	D     [RSAref_MAX_LEN]byte
	Prime [2][RSAref_MAX_PLEN]byte
	Pexp  [2][RSAref_MAX_PLEN]byte
	Coef  [RSAref_MAX_PLEN]byte
}

// DeviceInfo 设备信息,对应 sdf.h DEVICEINFO(字符串为去尾部 NUL 的 C 字节串)。
type DeviceInfo struct {
	IssuerName      string // 生产厂商名称
	DeviceName      string // 设备型号
	DeviceSerial    string // 设备序列号
	DeviceVersion   uint32 // 设备实现版本
	StandardVersion uint32 // 符合的标准版本
	AsymAlgAbility  [2]uint32
	SymAlgAbility   uint32 // 对称算法能力
	HashAlgAbility  uint32 // 杂凑算法能力
	BufferSize      uint32 // 设备可接收的最大数据长度
}
