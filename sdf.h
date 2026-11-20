
#ifndef _GM_SDS_H_
#define _GM_SDS_H_ 1

#ifdef __cplusplus
	extern "C"{
#endif

/*数据类型定义*/
typedef char				CHAR;
typedef char				INT8;
typedef short				INT16;
typedef int					INT32;
typedef long long			INT64;
typedef unsigned char		UCHAR;
typedef unsigned char		UINT8;
typedef unsigned char		BYTE;
typedef unsigned short		UINT16;
typedef unsigned int		UINT32;
typedef unsigned long long	UINT64;
typedef unsigned int		RV;
typedef void*				OBJ;
typedef int					BOOL;
typedef void*				HANDLE;

/*设备信息*/
typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
} DEVICEINFO;


/*RSA密钥*/
#define RSAref_MAX_BITS    2048
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKey_st
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;



/*2012版密码设备应用接口规范ECC密钥数据结构定义*/

#define ECCref_MAX_BITS					512
#define ECCref_MAX_LEN					((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN			136

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
	unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*ECC 密文*/
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int  L;
	unsigned char C[1];
} ECCCipher;

/*ECC 签名*/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

#define SM9ref_MAX_BITS		256
#define SM9ref_MAX_LEN		((SM9ref_MAX_BITS+7) / 8)

#define MAX_SM9_ID_LENGTH					128

typedef struct SM9refSignMasterPrivateKey_st
{
	unsigned int bits;
	unsigned char s[SM9ref_MAX_LEN];
} SM9refSignMasterPrivateKey;

typedef struct SM9refSignMasterPublicKey_st
{
	unsigned int bits;
	unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
	unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
	unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
	unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
} SM9refSignMasterPublicKey;

typedef struct SM9refSignMasterKeyPair_st
{
	SM9refSignMasterPrivateKey MasterPrivateKey;
	SM9refSignMasterPublicKey MasterPublicKey;
	unsigned char MasterKeyPairG[1536];
} SM9refSignMasterKeyPair;

typedef struct SM9refEncMasterPrivateKey_st
{
	unsigned int bits;
	unsigned char s[SM9ref_MAX_LEN];
} SM9refEncMasterPrivateKey;

typedef struct SM9refEncMasterPublicKey_st
{
	unsigned int bits;
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9refEncMasterPublicKey;

typedef struct SM9refEncMasterKeyPair_st
{
	SM9refEncMasterPrivateKey MasterPrivateKey;
	SM9refEncMasterPublicKey MasterPublicKey;
	unsigned char MasterKeyPairG[384];
} SM9refEncMasterKeyPair;

typedef struct SM9refPublicUserID_st
{
	unsigned int IDLen;
	unsigned char ID[MAX_SM9_ID_LENGTH];
} SM9refPublicUserID;

typedef struct SM9refSignUserPrivateKey_st
{
	unsigned int bits;
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9refSignUserPrivateKey;

typedef struct SM9refSignUserKeyPair_st
{
	SM9refSignUserPrivateKey PrivateKey;
	SM9refPublicUserID PublicUserID;
} SM9refSignUserKeyPair;

typedef struct SM9refEncUserPrivateKey_st
{
	unsigned int bits;
	unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
	unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
	unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
	unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
} SM9refEncUserPrivateKey;

typedef struct SM9refEncUserKeyPair_st
{
	SM9refEncUserPrivateKey PrivateKey;
	SM9refPublicUserID PublicUserID;
} SM9refEncUserKeyPair;

typedef struct SM9Signature_st
{
	unsigned char h[SM9ref_MAX_LEN];
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9Signature;

typedef struct SM9Cipher_st
{
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
	unsigned char h[SM9ref_MAX_LEN];
	unsigned int L;
	unsigned char C[1024];
} SM9Cipher;

typedef struct SM9refKeyPackage_st
{
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9refKeyPackage;

typedef struct SM9AgreementParam_st
{
	UINT32 nHandleFlag;
	unsigned char pucRandom[32];
	unsigned int uiRandomLength;
	unsigned char pucRA[64];
	unsigned int uiRALength;
} SM9AgreementParam;


/*常量定义*/

/*算法标识*/
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210

#define SGD_SM4_ECB		0x00000401
#define SGD_SM4_CBC		0x00000402
#define SGD_SM4_CFB		0x00000404
#define SGD_SM4_OFB		0x00000408
#define SGD_SM4_MAC		0x00000410
#define SGD_SM4_CTR		0x00000420
#define SGD_SM4_GCM     0x02000400
#define SGD_SM4_CCM     0x04000400

#define SGD_ZUC_EEA3	0x00000801	//ZUC祖冲之机密性算法128-EEA3
#define SGD_ZUC_EIA3	0x00000802	//ZUC祖冲之完整性算法128-EIA3

#define SGD_SM7_ECB		0x00001001
#define SGD_SM7_CBC		0x00001002
#define SGD_SM7_CFB		0x00001004
#define SGD_SM7_OFB		0x00001008
#define SGD_SM7_MAC		0x00001010

#define SGD_RSA			0x00010000

#define SGD_SM2			0x00020100  // SM2算法
#define SGD_SM2_1		0x00020200  // SM2签名
#define SGD_SM2_2		0x00020400  // SM2密钥交换
#define SGD_SM2_3		0x00020800  // SM2加密

#define SGD_SM3			0x00000001
#define SGD_SHA1		0x00000002
#define SGD_SHA256		0x00000004
// GMT0006-2023 定义，HMAC接口使用
#define SGD_SM3_HMAC	0x00000008
#define SGD_SHA256_HMAC	0x00000010


/*标准错误码定义*/
#define SDR_OK					0x0						   /*成功*/
#define SDR_BASE				0x01000000
#define SDR_UNKNOWERR			(SDR_BASE + 0x00000001)	   /*未知错误*/
#define SDR_NOTSUPPORT			(SDR_BASE + 0x00000002)	   /*不支持*/
#define SDR_COMMFAIL			(SDR_BASE + 0x00000003)    /*通信错误*/
#define SDR_HARDFAIL			(SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE			(SDR_BASE + 0x00000005)    /*打开设备错误*/
#define SDR_OPENSESSION			(SDR_BASE + 0x00000006)    /*打开会话句柄错误*/
#define SDR_PARDENY				(SDR_BASE + 0x00000007)    /*权限不满足*/
#define SDR_KEYNOTEXIST			(SDR_BASE + 0x00000008)    /*密钥不存在*/
#define SDR_ALGNOTSUPPORT		(SDR_BASE + 0x00000009)    /*不支持的算法*/
#define SDR_ALGMODNOTSUPPORT	(SDR_BASE + 0x0000000A)    /*不支持的算法模式*/
#define SDR_PKOPERR				(SDR_BASE + 0x0000000B)    /*公钥运算错误*/
#define SDR_SKOPERR				(SDR_BASE + 0x0000000C)    /*私钥运算错误*/
#define SDR_SIGNERR				(SDR_BASE + 0x0000000D)    /*签名错误*/
#define SDR_VERIFYERR			(SDR_BASE + 0x0000000E)    /*验证错误*/
#define SDR_SYMOPERR			(SDR_BASE + 0x0000000F)    /*对称运算错误*/
#define SDR_STEPERR				(SDR_BASE + 0x00000010)    /*步骤错误*/
#define SDR_FILESIZEERR			(SDR_BASE + 0x00000011)    /*文件大小错误或输入数据长度非法*/
#define SDR_FILENOEXIST			(SDR_BASE + 0x00000012)    /*文件不存在*/
#define SDR_FILEOFSERR			(SDR_BASE + 0x00000013)    /*文件操作偏移量错误*/
#define SDR_KEYTYPEERR			(SDR_BASE + 0x00000014)    /*密钥类型错误*/
#define SDR_KEYERR				(SDR_BASE + 0x00000015)    /*密钥错误*/
#define SDR_ENCDATAERR			(SDR_BASE + 0x00000016)    /*ECC加密数据错误*/
#define SDR_RANDERR				(SDR_BASE + 0x00000017)    /*随机数产生错误*/
#define SDR_PRKRERR				(SDR_BASE + 0x00000018)    /*私钥使用权限获取失败*/
#define SDR_MACERR				(SDR_BASE + 0x00000019)    /*MAC运算失败*/
#define SDR_FILEEXISTS			(SDR_BASE + 0x0000001A)    /*指定文件已存在*/
#define SDR_FILEWERR			(SDR_BASE + 0x0000001B)    /*文件读写错误*/
#define SDR_NOBUFFER			(SDR_BASE + 0x0000001C)    /*缓冲区错误*/
#define SDR_INARGERR			(SDR_BASE + 0x0000001D)    /*输入参数错误*/
#define SDR_OUTARGERR			(SDR_BASE + 0x0000001E)    /*输出参数错误*/
#define SDR_USERIDERR			(SDR_BASE + 0x0000001F)    /*用户标识错误*/

/*设备管理类函数*/
RV SDF_OpenDevice(HANDLE *phDeviceHandle);
RV SDF_CloseDevice(HANDLE hDeviceHandle);
RV SDF_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle);
RV SDF_CloseSession(HANDLE hSessionHandle);
RV SDF_GetDeviceInfo(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
RV SDF_GenerateRandom(HANDLE hSessionHandle, UINT32  uiLength, UCHAR *pucRandom);
RV SDF_GetPrivateKeyAccessRight(HANDLE hSessionHandle, UINT32 uiKeyIndex,UCHAR *pucPassword, UINT32  uiPwdLength);
RV SDF_ReleasePrivateKeyAccessRight(HANDLE hSessionHandle, UINT32  uiKeyIndex);

/*密钥管理类函数*/
RV SDF_GenerateKeyPair_RSA(HANDLE hSessionHandle, UINT32  uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
RV SDF_ExportSignPublicKey_RSA(HANDLE hSessionHandle, UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
RV SDF_ExportEncPublicKey_RSA(HANDLE hSessionHandle, UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
RV SDF_GenerateKeyWithIPK_RSA(HANDLE hSessionHandle, UINT32 uiIPKIndex, UINT32 uiKeyBits, UCHAR *pucKey, UINT32 *puiKeyLength, HANDLE *phKeyHandle);
RV SDF_GenerateKeyWithEPK_RSA(HANDLE hSessionHandle, UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey, UCHAR *pucKey, UINT32 *puiKeyLength, HANDLE *phKeyHandle);
RV SDF_ImportKeyWithISK_RSA(HANDLE hSessionHandle, UINT32 uiISKIndex, UCHAR *pucKey, UINT32 uiKeyLength, HANDLE *phKeyHandle);
RV SDF_ExchangeDigitEnvelopeBaseOnRSA(HANDLE hSessionHandle, UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey, UCHAR *pucDEInput, UINT32 uiDELength, UCHAR *pucDEOutput, UINT32  *puiDELength);

RV SDF_ImportKey(HANDLE hSessionHandle, UCHAR *pucKey, UINT32 uiKeyLength, HANDLE *phKeyHandle);
RV SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle);
RV SDF_GenerateKeyWithKEK(HANDLE hSessionHandle, UINT32 uiKeyBits, UINT32 uiAlgID,UINT32 uiKEKIndex, UCHAR *pucKey, UINT32 *puiKeyLength, HANDLE *phKeyHandle);
RV SDF_ImportKeyWithKEK(HANDLE hSessionHandle, UINT32 uiAlgID, UINT32 uiKEKIndex, UCHAR *pucKey, UINT32 uiKeyLength, HANDLE *phKeyHandle);

RV SDF_GenerateKeyPair_ECC(HANDLE hSessionHandle, UINT32 uiAlgID,UINT32  uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
RV SDF_ExportSignPublicKey_ECC(HANDLE hSessionHandle, UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
RV SDF_ExportEncPublicKey_ECC(HANDLE hSessionHandle, UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
RV SDF_GenerateAgreementDataWithECC(HANDLE hSessionHandle, UINT32 uiISKIndex, UINT32 uiKeyBits, UCHAR *pucSponsorID, UINT32 uiSponsorIDLength, \
										ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, HANDLE *phAgreementHandle);
RV SDF_GenerateKeyWithECC(HANDLE hSessionHandle, UCHAR *pucResponseID, UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, \
							  ECCrefPublicKey *pucResponseTmpPublicKey, HANDLE hAgreementHandle, HANDLE *phKeyHandle);
RV SDF_GenerateAgreementDataAndKeyWithECC(HANDLE hSessionHandle, UINT32 uiISKIndex, UINT32 uiKeyBits, UCHAR *pucResponseID, UINT32 uiResponseIDLength, \
											  UCHAR *pucSponsorID, UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, \
											  ECCrefPublicKey  *pucResponsePublicKey, ECCrefPublicKey  *pucResponseTmpPublicKey, HANDLE *phKeyHandle);
RV SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, UINT32 uiIPKIndex, UINT32 uiKeyBits, ECCCipher *pucKey, HANDLE *phKeyHandle);
RV SDF_GenerateKeyWithEPK_ECC(HANDLE hSessionHandle, UINT32 uiKeyBits, UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, HANDLE *phKeyHandle);
RV SDF_ImportKeyWithISK_ECC(HANDLE hSessionHandle, UINT32 uiISKIndex, ECCCipher *pucKey, HANDLE *phKeyHandle);
RV SDF_ExchangeDigitEnvelopeBaseOnECC(HANDLE hSessionHandle, UINT32 uiKeyIndex, UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut);

/*非对称密码运算函数*/
RV SDF_ExternalPublicKeyOperation_RSA(HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey, UCHAR *pucDataInput, UINT32 uiInputLength, UCHAR *pucDataOutput, UINT32 *puiOutputLength);
RV SDF_InternalPublicKeyOperation_RSA(HANDLE hSessionHandle, UINT32 uiKeyIndex, UCHAR *pucDataInput, UINT32 uiInputLength, UCHAR *pucDataOutput, UINT32  *puiOutputLength);
RV SDF_InternalPrivateKeyOperation_RSA(HANDLE hSessionHandle, UINT32 uiKeyIndex, UCHAR *pucDataInput, UINT32 uiInputLength, UCHAR *pucDataOutput, UINT32 *puiOutputLength);

RV SDF_ExternalSign_ECC(HANDLE hSessionHandle, UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, UCHAR *pucData, UINT32 uiDataLength, ECCSignature *pucSignature);
RV SDF_ExternalVerify_ECC(HANDLE hSessionHandle, UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, UCHAR *pucDataInput, UINT32 uiInputLength, ECCSignature *pucSignature);
RV SDF_InternalSign_ECC(HANDLE hSessionHandle, UINT32 uiISKIndex, UCHAR *pucData, UINT32 uiDataLength, ECCSignature *pucSignature);
RV SDF_InternalVerify_ECC(HANDLE hSessionHandle, UINT32 uiISKIndex, UCHAR *pucData, UINT32 uiDataLength, ECCSignature *pucSignature);
RV SDF_ExternalEncrypt_ECC(HANDLE hSessionHandle, UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, UCHAR *pucData, UINT32 uiDataLength, ECCCipher *pucEncData);
RV SDF_ExternalDecrypt_ECC(HANDLE hSessionHandle, UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, UCHAR *pucData, UINT32 *puiDataLength);

/*对称密码运算函数*/
RV SDF_Encrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV, UCHAR *pucData, UINT32 uiDataLength, UCHAR *pucEncData, \
				   UINT32 *puiEncDataLength);
RV SDF_Decrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV, UCHAR *pucEncData, UINT32 uiEncDataLength, UCHAR *pucData, \
				   UINT32 *puiDataLength);
RV SDF_CalculateMAC(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV, UCHAR *pucData, UINT32 uiDataLength, UCHAR *pucMAC, \
						UINT32 *puiMACLength);

/*对称密码运算(多包,GM/T 0018-2023 6.5)*/
RV SDF_EncryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV, UINT32 uiIVLength);
RV SDF_EncryptUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength, UCHAR *pucEncData, UINT32 *puiEncDataLength);
RV SDF_EncryptFinal(HANDLE hSessionHandle, UCHAR *pucEncData, UINT32 *puiEncDataLength);
RV SDF_DecryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV, UINT32 uiIVLength);
RV SDF_DecryptUpdate(HANDLE hSessionHandle, UCHAR *pucEncData, UINT32 uiEncDataLength, UCHAR *pucData, UINT32 *puiDataLength);
RV SDF_DecryptFinal(HANDLE hSessionHandle, UCHAR *pucData, UINT32 *puiDataLength);
RV SDF_CalculateMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV, UINT32 uiIVLength);
RV SDF_CalculateMACUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength);
RV SDF_CalculateMACFinal(HANDLE hSessionHandle, UCHAR *pucMAC, UINT32 *puiMACLength);

/*可鉴别加解密(2023 表13 6.5.5~6.5.21,GCM/CCM,2023 新增) */
RV SDF_AuthEnc(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucStartVar, UINT32 uiStartVarLength, \
				UCHAR *pucAad, UINT32 uiAadLength, UCHAR *pucData, UINT32 uiDataLength, UCHAR *pucEncData, UINT32 *puiEncDataLength, \
				UCHAR *pucAuthData, UINT32 *puiAuthDataLength);
RV SDF_AuthDec(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucStartVar, UINT32 uiStartVarLength, \
				UCHAR *pucAad, UINT32 uiAadLength, UCHAR *pucAuthData, UINT32 uiAuthDataLength, UCHAR *pucEncData, UINT32 uiEncDataLength, \
				UCHAR *pucData, UINT32 *puiDataLength);
RV SDF_AuthEncInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucStartVar, UINT32 uiStartVarLength, \
				UCHAR *pucAad, UINT32 uiAadLength, UINT32 uiDataLength);
RV SDF_AuthEncUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength, UCHAR *pucEncData, UINT32 *puiEncDataLength);
RV SDF_AuthEncFinal(HANDLE hSessionHandle, UCHAR *pucLastEncData, UINT32 *puiLastEncDataLength, \
				UCHAR *pucAuthData, UINT32 *puiAuthDataLength);
RV SDF_AuthDecInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucStartVar, UINT32 uiStartVarLength, \
				UCHAR *pucAad, UINT32 uiAadLength, UCHAR *pucAuthData, UINT32 uiAuthDataLength, UINT32 uiDataLength);
RV SDF_AuthDecUpdate(HANDLE hSessionHandle, UCHAR *pucEncData, UINT32 uiEncDataLength, UCHAR *pucData, UINT32 *puiDataLength);
RV SDF_AuthDecFinal(HANDLE hSessionHandle, UCHAR *pucLastData, UINT32 *puiLastDataLength);

/*杂凑运算函数*/
RV SDF_HashInit(HANDLE hSessionHandle, UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, UCHAR *pucID, UINT32 uiIDLength);
RV SDF_HashUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength);
RV SDF_HashFinal(HANDLE hSessionHandle, UCHAR *pucHash, UINT32 *puiHashLength);

/*带密钥的杂凑(GM/T 0018-2023 6.6,密钥句柄 ABI)*/
RV SDF_HMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID);
RV SDF_HMACUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength);
RV SDF_HMACFinal(HANDLE hSessionHandle, UCHAR *pucMAC, UINT32 *puiMACLength);

/*用户文件操作函数*/
RV SDF_CreateFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen, UINT32 uiFileSize);
RV SDF_ReadFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen, UINT32 uiOffset, UINT32 *puiReadLength, UCHAR *pucBuffer);
RV SDF_WriteFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen, UINT32 uiOffset, UINT32 uiWriteLength, UCHAR *pucBuffer);
RV SDF_DeleteFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen);

/* gosdf 垫片 ABI(cgo 调用面):wrapper 为 (sdf_ctx*, long* 会话/密钥句柄, ...) 形态。
 * gosdf C 垫片:持有不透明设备上下文,通过 dlopen/dlsym 绑定厂商 SDF_* 符号。
 * 除 SDF_OpenDevice/SDF_CloseDevice/SDF_OpenSession/SDF_CloseSession 外,
 * 其余符号均可选,缺失时对应 wrapper 返回 SDR_NOTSUPPORT。 */

/* 不透明设备上下文(库句柄、设备句柄、全部函数指针) */
typedef struct sdf_ctx sdf_ctx;

/* 生命周期 */
sdf_ctx *sdf_open(const char *path, RV *err);
void sdf_close(sdf_ctx *c);
int sdf_has(sdf_ctx *c, const char *sdf_symbol);

/* 设备管理 */
RV open_session(sdf_ctx *c, long **session);
RV close_session(sdf_ctx *c, long *session);
RV get_device_info(sdf_ctx *c, long *session, DEVICEINFO *info);
RV gen_random(sdf_ctx *c, long *session, UINT32 len, UCHAR *buf);
RV verify_pin(sdf_ctx *c, long *session, UINT32 key_index, UCHAR *pin, UINT32 pin_len);
RV release_pin(sdf_ctx *c, long *session, UINT32 key_index);

/* 杂凑运算 */
RV hash_init(sdf_ctx *c, long *session, UINT32 alg, ECCrefPublicKey *pub, BYTE *id, UINT32 id_len);
RV hash_update(sdf_ctx *c, long *session, UCHAR *buf, UINT32 buf_len);
RV hash_final(sdf_ctx *c, long *session, UCHAR *hash, UINT32 *hash_len);

/* 带密钥的杂凑(GM/T 0018-2023 6.6.2~6.6.4,SDF_HMACInit/Update/Final) */
RV hmac_init(sdf_ctx *c, long *session, long *key, UINT32 alg);
RV hmac_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len);
RV hmac_final(sdf_ctx *c, long *session, UCHAR *mac, UINT32 *mac_len);

/* 密钥管理 */
RV export_sign_pubkey_ecc(sdf_ctx *c, long *session, UINT32 key_index, ECCrefPublicKey *pub);
RV export_enc_pubkey_ecc(sdf_ctx *c, long *session, UINT32 key_index, ECCrefPublicKey *pub);
/* RSA/通用密钥管理(2012 6.3.1~6.3.7、6.3.10、6.3.17、6.3.20;GenerateKeyPair 亦见 2023 表16) */
RV export_sign_pubkey_rsa(sdf_ctx *c, long *session, UINT32 key_index, RSArefPublicKey *pub);
RV export_enc_pubkey_rsa(sdf_ctx *c, long *session, UINT32 key_index, RSArefPublicKey *pub);
RV gen_keypair_rsa(sdf_ctx *c, long *session, UINT32 key_bits,
	RSArefPublicKey *pub, RSArefPrivateKey *priv);
RV gen_keypair_ecc(sdf_ctx *c, long *session, UINT32 alg, UINT32 key_bits,
	ECCrefPublicKey *pub, ECCrefPrivateKey *priv);
RV gen_key_with_ipk_rsa(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	BYTE *key_buf, UINT32 *key_len, long **key_handle);
RV gen_key_with_epk_rsa(sdf_ctx *c, long *session, UINT32 key_bits, RSArefPublicKey *pub,
	BYTE *key_buf, UINT32 *key_len, long **key_handle);
RV import_key_with_isk_rsa(sdf_ctx *c, long *session, UINT32 key_index,
	BYTE *key_buf, UINT32 key_len, long **key_handle);
RV exchange_envelope_rsa(sdf_ctx *c, long *session, UINT32 key_index, RSArefPublicKey *pub,
	UCHAR *de_in, UINT32 de_in_len, UCHAR *de_out, UINT32 *de_out_len);
/* ECCCipher 输入/输出均按 cipher_buf/cipher_cap 约定由调用方分配 */
RV exchange_envelope_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 alg,
	ECCrefPublicKey *pub, void *in_cipher, UINT32 in_cap,
	void *out_cipher, UINT32 out_cap);
RV import_key(sdf_ctx *c, long *session, BYTE *key_buf, UINT32 key_len, long **key_handle);
/* ECCCipher 输出类:调用方分配缓冲(含柔性数组),cipher_cap 为缓冲总容量 */
RV gen_key_with_ipk_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	void *cipher_buf, UINT32 cipher_cap, long **key_handle);
RV gen_key_with_epk_ecc(sdf_ctx *c, long *session, UINT32 key_bits, UINT32 alg, ECCrefPublicKey *pub,
	void *cipher_buf, UINT32 cipher_cap, long **key_handle);
RV import_key_with_isk_ecc(sdf_ctx *c, long *session, UINT32 key_index,
	void *cipher_buf, UINT32 cipher_cap, long **key_handle);
RV gen_key_with_kek(sdf_ctx *c, long *session, UINT32 key_bits, UINT32 alg_id, UINT32 kek_index,
	BYTE *key_buf, UINT32 *key_len, long **key_handle);
RV import_key_with_kek(sdf_ctx *c, long *session, UINT32 alg_id, UINT32 kek_index,
	BYTE *key_buf, UINT32 key_len, long **key_handle);
/* session 与 key 两个句柄分别透传 */
RV destroy_key(sdf_ctx *c, long *session, long *key);

/* SM2 密钥协商(2023 表11 6.3.12~6.3.14,与 SDF_GenerateAgreementData* 原型同形) */
RV gen_agreement_data_with_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	UCHAR *sponsor_id, UINT32 sponsor_id_len,
	ECCrefPublicKey *sponsor_pub, ECCrefPublicKey *sponsor_tmp_pub, long **handle);
RV gen_key_with_ecc(sdf_ctx *c, long *session,
	UCHAR *response_id, UINT32 response_id_len,
	ECCrefPublicKey *response_pub, ECCrefPublicKey *response_tmp_pub,
	long *handle, long **key_handle);
RV gen_agreement_data_and_key_with_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	UCHAR *response_id, UINT32 response_id_len, UCHAR *sponsor_id, UINT32 sponsor_id_len,
	ECCrefPublicKey *sponsor_pub, ECCrefPublicKey *sponsor_tmp_pub,
	ECCrefPublicKey *response_pub, ECCrefPublicKey *response_tmp_pub, long **key_handle);

/* 非对称运算 */
RV external_verify_ecc(sdf_ctx *c, long *session, UINT32 alg, ECCrefPublicKey *pub,
	UCHAR *buf, UINT32 buf_len, ECCSignature *sig);
RV internal_sign_ecc(sdf_ctx *c, long *session, UINT32 key_index,
	UCHAR *data, UINT32 data_len, ECCSignature *sig);
RV internal_verify_ecc(sdf_ctx *c, long *session, UINT32 key_index,
	UCHAR *data, UINT32 data_len, ECCSignature *sig);
RV external_encrypt_ecc(sdf_ctx *c, long *session, UINT32 alg, ECCrefPublicKey *pub,
	UCHAR *data, UINT32 data_len, void *cipher_buf, UINT32 cipher_cap);

/* 对称运算(单包) */
RV encrypt(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv,
	BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len);
RV decrypt(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv,
	BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len);
RV cbc_mac(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv,
	BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len);

/* 对称运算(多包,2023 6.5 原型;厂商 .so 可能缺失) */
RV enc_init(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv, UINT32 iv_len);
RV enc_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len, UCHAR *out, UINT32 *out_len);
RV enc_final(sdf_ctx *c, long *session, UCHAR *out, UINT32 *out_len);
RV dec_init(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv, UINT32 iv_len);
RV dec_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len, UCHAR *out, UINT32 *out_len);
RV dec_final(sdf_ctx *c, long *session, UCHAR *out, UINT32 *out_len);
RV mac_init(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv, UINT32 iv_len);
RV mac_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len);
RV mac_final(sdf_ctx *c, long *session, UCHAR *out, UINT32 *out_len);

/* 可鉴别加解密(2023 表13;GCM/CCM,厂商 .so 可能缺失) */
RV auth_enc(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len,
	BYTE *data, UINT32 data_len,
	BYTE *enc_buf, UINT32 *enc_len,
	BYTE *auth_buf, UINT32 *auth_len);
RV auth_dec(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len,
	BYTE *auth, UINT32 auth_len,
	BYTE *enc, UINT32 enc_len,
	BYTE *data_buf, UINT32 *data_len);
RV auth_enc_init(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len, UINT32 data_len);
RV auth_enc_update(sdf_ctx *c, long *session, BYTE *data, UINT32 data_len,
	BYTE *enc_buf, UINT32 *enc_len);
RV auth_enc_final(sdf_ctx *c, long *session, BYTE *enc_buf, UINT32 *enc_len,
	BYTE *auth_buf, UINT32 *auth_len);
RV auth_dec_init(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len,
	BYTE *auth, UINT32 auth_len, UINT32 data_len);
RV auth_dec_update(sdf_ctx *c, long *session, BYTE *enc, UINT32 enc_len,
	BYTE *data_buf, UINT32 *data_len);
RV auth_dec_final(sdf_ctx *c, long *session, BYTE *data_buf, UINT32 *data_len);

/* 文件操作 */
RV create_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len, UINT32 size);
RV read_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len,
	UINT32 offset, UINT32 *length, UCHAR *buf);
RV write_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len,
	UINT32 offset, UINT32 length, UCHAR *buf);
RV delete_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len);

#ifdef __cplusplus
}
#endif

#endif
