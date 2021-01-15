#ifndef __SDF_TYPE_DEF_H__
#define __SDF_TYPE_DEF_H__



typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int DeviceVersion;
	unsigned int StandardVersion;
	unsigned int AsymAlgAbility[2];
	unsigned int SymAlgAbility;
	unsigned int HashAlgAbility;
	unsigned int BufferSize;
}DEVICEINFO;


/* RSA */
#define RSAref_MAX_BITS		2048
#define RSAref_MAX_LEN  		((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS		((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN		((RSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKey_st
{
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
}RSArefPublicKey;

typedef struct RSArefPrivateKey_st
{
	unsigned int bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
}RSArefPrivateKey;


/* ECC */
#define ECCref_MAX_BITS		512
#define ECCref_MAX_LEN 		((ECCref_MAX_BITS + 7) / 8)

typedef struct ECCrefPublicKey_st
{
	unsigned int bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
}ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int bits;
	unsigned char K[ECCref_MAX_LEN];
}ECCrefPrivateKey;

typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int L;
	unsigned char C[1];
}ECCCipher;

typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
}ECCSignature;


/*ecc enveloped key struct*/
#define ECC_MAX_XCOORDINATE_BITS_LEN		512
#define ECC_MAX_YCOORDINATE_BITS_LEN		ECC_MAX_XCOORDINATE_BITS_LEN
#define ECC_MAX_MODULUS_BITS_LEN			ECC_MAX_XCOORDINATE_BITS_LEN
typedef struct eccpubkeyblob_st 
{
	unsigned int	BitLen; 
	unsigned char	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	unsigned char	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8]; 
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct ecccipherblob_st
{ 
	unsigned char  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	unsigned char  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	unsigned char  Hash[32]; 
	unsigned int	CipherLen;
	unsigned char  Cipher[128]; 
}ECCCIPHERBLOB, *PECCCIPHERBLOB;

typedef struct SDF_ENVELOPEDKEYBLOB{
	unsigned long ulAsymmAlgID; 
	unsigned long ulSymmAlgID; 
	ECCCIPHERBLOB ECCCipherBlob; 
	ECCPUBLICKEYBLOB PubKey; 
	unsigned char cbEncryptedPrikey[64]; 
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;



typedef struct SlotKeyInfo_st
{
	unsigned int slot_key_index;
	unsigned int rsa_sign_key_flag;
	unsigned int rsa_enc_key_flag;
	unsigned int ecc_sign_key_flag;
	unsigned int ecc_enc_key_flag;
}SlotKeyInfo;

#ifndef TRUE
#define TRUE		1
#endif
#ifndef FALSE
#define FALSE 		0
#endif

#define ADMIN_TYPE	1
#define USER_TYPE		0

#define SDF_MAX_PWD_LEN			0x20
#define SDF_MAX_KEY_INDEX		0x0F
#define SDF_MAX_FILE_LEN			0x4000
#define SDF_MODE_RSA_2048		0x800
#define SDF_MODE_RSA_1024		0x400
#define SDF_MODE_ECC_512		0x200
#define SDF_MODE_ECC_256		0x100
#define SDF_ALGO_KEY_LEN_MASK	0x0F00

#define SGD_SLOT_KEY_EXIST_MASK		0x80000000

#define SDF_FILE_NAME_MAX_LEN	128
#define SDF_FILE_MAX_COUNT		16

/* algorithm */
#define SGD_SM1				0x00000100
#define SGD_SM1_ECB			0x00000101
#define SGD_SM1_CBC			0x00000102   
#define SGD_SM1_CFB			0x00000104      
#define SGD_SM1_OFB			0x00000108       
#define SGD_SM1_MAC			0x00000110 
#define SGD_SSF33			0x00000200 
#define SGD_SSF33_ECB       		0x00000201    
#define SGD_SSF33_CBC      		 0x00000202      
#define SGD_SSF33_CFB      		 0x00000204      
#define SGD_SSF33_OFB     		0x00000208        
#define SGD_SSF33_MAC       	0x00000210    
#define SGD_SMS4			0x00000400  
#define SGD_SMS4_ECB			0x00000401      
#define SGD_SMS4_CBC			0x00000402        
#define SGD_SMS4_CFB			0x00000404       
#define SGD_SMS4_OFB			0x00000408        
#define SGD_SMS4_MAC		0x00000410     
#define SGD_SM6				0x00000600
#define SGD_SM6_ECB			0x00000601
#define SGD_SM6_CBC			0x00000602   
#define SGD_SM6_CFB			0x00000604      
#define SGD_SM6_OFB			0x00000608       
#define SGD_SM6_MAC			0x00000610 
#define SGD_AES				0x80000200
#define SGD_AES_ECB			0x80000201
#define SGD_AES_CBC			0x80000202   
#define SGD_AES_CFB			0x80000204      
#define SGD_AES_OFB			0x80000208       
#define SGD_AES_MAC			0x80000210			

#if 0
#define SGD_RSA				0x00010000
#define SGD_SM2				0x00020000
#define SGD_SM2_1			0x00020100   
#define SGD_SM2_2			0x00020200
#define SGD_SM2_3			0x00020400
#else//V_GMT0006
#define SGD_RSA				0x00010000
#define SGD_SM2				0x00020000
#define SGD_SM2_1			0x00020200   
#define SGD_SM2_2			0x00020400
#define SGD_SM2_3			0x00020800
#endif

#define SGD_SM3				0x00000001      
#define SGD_SHA1				0x00000002        
#define SGD_SHA256			0x00000004  
#define SGD_SHA512			0x00000008
#define SGD_SHA0				0x00000010
#define SGD_SHA224			0x00000020
#define SGD_SHA384			0x00000040


/* return value */
#define SDR_OK 					0x00000000
#define SDR_BASE					0x01000000
#define SDR_UNKNOWERR			SDR_BASE + 0x00000001
#define SDR_NOTSUPPORT			SDR_BASE + 0x00000002
#define SDR_COMMFAIL				SDR_BASE + 0x00000003
#define SDR_HARDFAIL				SDR_BASE + 0x00000004
#define SDR_OPENDEVICE			SDR_BASE + 0x00000005
#define SDR_OPENSESSION			SDR_BASE + 0x00000006
#define SDR_PARDENY				SDR_BASE + 0x00000007
#define SDR_KEYNOTEXIT			SDR_BASE + 0x00000008
#define SDR_ALGNOTSUPPORT		SDR_BASE + 0x00000009
#define SDR_ALGMODNOTSUPPORT	SDR_BASE + 0x0000000A
#define SDR_PKOPERR				SDR_BASE + 0x0000000B
#define SDR_SKOPERR				SDR_BASE + 0x0000000C
#define SDR_SIGNERR				SDR_BASE + 0x0000000D
#define SDR_VERIFYERR			SDR_BASE + 0x0000000E
#define SDR_SYMOPERR			SDR_BASE + 0x0000000F
#define SDR_STEPERR				SDR_BASE + 0x00000010
#define SDR_FILESIZEERR			SDR_BASE + 0x00000011
#define SDR_FILENOEXIST			SDR_BASE + 0x00000012
#define SDR_FILEOFSERR			SDR_BASE + 0x00000013
#define SDR_KEYTYPEERR			SDR_BASE + 0x00000014
#define SDR_KEYERR				SDR_BASE + 0x00000015
#define SDR_ENCDATAERR			SDR_BASE + 0x00000016
#define SDR_RANDERR				SDR_BASE + 0x00000017
#define SDR_PRKRERR				SDR_BASE + 0x00000018
#define SDR_MACERR				SDR_BASE + 0x00000019
#define SDR_FILEEXISTS			SDR_BASE + 0x0000001A
#define SDR_FILEWERR				SDR_BASE + 0x0000001B
#define SDR_NOBUFFER				SDR_BASE + 0x0000001C
#define SDR_INARGERR				SDR_BASE + 0x0000001D
#define SDR_OUTARGERR			SDR_BASE + 0x0000001E
#define SDR_LENGTHERR			SDR_BASE + 0x0000001F
#define SDR_HANDLEINVALID		SDR_BASE + 0x00000020
#define SDR_PARLOCK				SDR_BASE + 0x00000021
#define SDR_DEVINITERR				SDR_BASE + 0x00000022


/*
 * Management account module
 */
#define MAX_MANAGER_COUNT	8

enum UMG_ui_user_type {
	OPERATOR_ACCOUNT = 0,
	MGR_ACCOUNT = 1,
};
typedef struct DeviceStatus_st{
	unsigned int InitStatus;
	unsigned int ManagerCount;
	unsigned int ManagerExist[MAX_MANAGER_COUNT];
	unsigned int ManagerLogin[MAX_MANAGER_COUNT];
	unsigned int OperatorExist;
	unsigned int OperatorLogin;
}DEVICESTATUS;

#endif /*__SDF_TYPE_DEF_H__*/
