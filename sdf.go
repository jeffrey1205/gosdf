package gosdf

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -ldl
#include <stdio.h>
#include <dlfcn.h>

#include "sdf.h"

static void *gs_sdf_device = NULL; //加密设备
static void *gs_lib_handle = NULL; //so库

//设备管理
typedef int (* OPEN_DEVICE)(void **);
OPEN_DEVICE OpenDevice;

typedef int (* CLOSE_DEVICE)(void *);
CLOSE_DEVICE CloseDevice;

typedef int (* OPEN_SESSION)(void *, void **);
OPEN_SESSION OpenSession;

typedef int (* CLOSE_SESSION)(void *);
CLOSE_SESSION CloseSession;

//杂凑运算
typedef int (* HASH_INIT)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int);
HASH_INIT HashInit;

typedef int (* HASH_UPDATE)(void *, unsigned char *, unsigned int);
HASH_UPDATE HashUpdate;

typedef int (* HASH_FINAL)(void *, unsigned char *, unsigned int *);
HASH_FINAL HashFinal;

//密钥管理
typedef int (*ExportSignPublicKey_ECC)(void *, unsigned int, ECCrefPublicKey *);
ExportSignPublicKey_ECC ExportSignPublicKeyECC;

typedef int (*ExportEncPublicKey_ECC)(void *, unsigned int, ECCrefPublicKey *);
ExportEncPublicKey_ECC ExportEncPublicKeyECC;

typedef int (*GenerateKeyPair_ECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *,ECCrefPrivateKey *);
GenerateKeyPair_ECC GenerateKeyPairECC;

typedef int (*GenerateKeyWithIPK_ECC)(void *, unsigned int, unsigned int, ECCCipher *, void **);
GenerateKeyWithIPK_ECC GenerateKeyWithIPKECC;

typedef int (*GenerateKeyWithEPK_ECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *, ECCCipher *, void **);
GenerateKeyWithEPK_ECC GenerateKeyWithEPKECC;

typedef int (*ImportKeyWithISK_ECC)(void *, unsigned int, ECCCipher *, void **);
ImportKeyWithISK_ECC ImportKeyWithISKECC;

typedef int (*GenerateAgreementData_ECC)(void *, unsigned int, unsigned int, unsigned char *, unsigned int, ECCrefPublicKey *, ECCrefPublicKey *, void **);
GenerateAgreementData_ECC GenerateAgreementDataWithECC;

typedef int (*GenerateKey_ECC)(void *, unsigned char *, unsigned int, ECCrefPublicKey *, ECCrefPublicKey *, void *, void **);
GenerateKey_ECC GenerateKeyWithECC;

typedef int (*GenerateAgreementDataAndKey_ECC)(void *, unsigned int, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int, ECCrefPublicKey *, ECCrefPublicKey *, ECCrefPublicKey *, ECCrefPublicKey *, void *, void **);
GenerateAgreementDataAndKey_ECC GenerateAgreementDataAndKeyWithECC;

typedef int (*ExchangeDigitEnvelope_ECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *, ECCCipher *, ECCCipher *);
ExchangeDigitEnvelope_ECC ExchangeDigitEnvelopeBaseOnECC;

typedef int (*Import_Key)(void *, unsigned char *, unsigned int , void **);
Import_Key ImportKey;

typedef int (*Destroy_Key)(void *, void *);
Destroy_Key DestroyKey;

//非对称运算
typedef int (*ExternalSign_ECC)(void *, unsigned int, ECCrefPrivateKey *, unsigned char *, unsigned int, ECCSignature *);
ExternalSign_ECC ExternalSignECC;

typedef int (*ExternalVerify_ECC)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int, ECCSignature *);
ExternalVerify_ECC ExternalVerifyECC;

typedef int (*InternalSign_ECC)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature *);
InternalSign_ECC InternalSignECC;

typedef int (*InternalVerify_ECC)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature *);
InternalVerify_ECC InternalVerifyECC;

typedef int (*ExternalEncrypt_ECC)(void *, unsigned int, ECCrefPublicKey *,unsigned char *, unsigned int, ECCCipher *);
ExternalEncrypt_ECC ExternalEncryptECC;

typedef int (*ExternalDecrypt_ECC)(void *, unsigned int, ECCrefPrivateKey *, ECCCipher *, unsigned char *, unsigned int *);
ExternalDecrypt_ECC ExternalDecryptECC;

typedef int (*InternalEncrypt_ECC)(void *, unsigned int, unsigned char *, unsigned int, ECCCipher *);
InternalEncrypt_ECC InternalEncryptECC;

typedef int (*InternalDecrypt_ECC)(void *, unsigned int, ECCCipher *, unsigned char *, unsigned int *);
InternalDecrypt_ECC InternalDecryptECC;

//对称运算
typedef int (*ENCRYPT)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
ENCRYPT Encrypt;

typedef int (*DECRYPT)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
DECRYPT Decrypt;

typedef int (*Calculate_MAC)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
Calculate_MAC CalculateMAC;

//文件管理
typedef int (*Create_File)(void *, unsigned char *, unsigned int, unsigned int);
Create_File CreateFile;

typedef int (*Read_File)(void *, unsigned char *, unsigned int, unsigned int, unsigned int *, unsigned char *);
Read_File ReadFile;

typedef int (*Write_File)(void *, unsigned char *, unsigned int, unsigned int, unsigned int, unsigned char *);
Write_File WriteFile;

typedef int (*Delete_File)(void *, unsigned char *, unsigned int);
Delete_File DeleteFile;

struct func_name_pair
{
	char name[64]; 	//函数名
	long **func; 	//函数指针
};

int plugin_init(char *path)
{
	int i;
	long *sym;
	struct func_name_pair gs_func_name_arr[] = {
		{"SDF_OpenDevice", (long **)&OpenDevice},
		{"SDF_CloseDevice", (long **)&CloseDevice},
		{"SDF_OpenSession", (long **)&OpenSession},
		{"SDF_CloseSession", (long **)&CloseSession},

		{"SDF_HashInit", (long **)&HashInit},
		{"SDF_HashUpdate", (long **)&HashUpdate},
		{"SDF_HashFinal", (long **)&HashFinal},

		{"SDF_ExportSignPublicKey_ECC", (long **)&ExportSignPublicKeyECC},
		{"SDF_ExportEncPublicKey_ECC", (long **)&ExportEncPublicKeyECC},
		{"SDF_GenerateKeyPair_ECC", (long **)&GenerateKeyPairECC},
		{"SDF_GenerateKeyWithIPK_ECC", (long **)&GenerateKeyWithIPKECC},
		{"SDF_GenerateKeyWithEPK_ECC", (long **)&GenerateKeyWithEPKECC},
		{"SDF_ImportKeyWithISK_ECC", (long **)&ImportKeyWithISKECC},
		{"SDF_GenerateAgreementDataWithECC", (long **)&GenerateAgreementDataWithECC},
		{"SDF_GenerateKeyWithECC", (long **)&GenerateKeyWithECC},
		{"SDF_GenerateAgreementDataAndKeyWithECC", (long **)&GenerateAgreementDataAndKeyWithECC},
		{"SDF_ExchangeDigitEnvelopeBaseOnECC", (long **)&ExchangeDigitEnvelopeBaseOnECC},
		{"SDF_ImportKey", (long **)&ImportKey},
		{"SDF_DestroyKey", (long **)&DestroyKey},

		{"SDF_ExternalSign_ECC", (long **)&ExternalSignECC},
		{"SDF_ExternalVerify_ECC", (long **)&ExternalVerifyECC},
		{"SDF_InternalSign_ECC", (long **)&InternalSignECC},
		{"SDF_InternalVerify_ECC", (long **)&InternalVerifyECC},
		{"SDF_ExternalEncrypt_ECC", (long **)&ExternalEncryptECC},
		{"SDF_ExternalDecrypt_ECC", (long **)&ExternalDecryptECC},
		{"SDF_InternalEncrypt_ECC", (long **)&InternalEncryptECC},
		{"SDF_InternalDecrypt_ECC", (long **)&InternalDecryptECC},

		{"SDF_Encrypt", (long **)&Encrypt},
		{"SDF_Decrypt", (long **)&Decrypt},
		{"SDF_CalculateMAC", (long **)&CalculateMAC},

		{"SDF_CreateFile", (long **)&CreateFile},
		{"SDF_ReadFile", (long **)&ReadFile},
		{"SDF_WriteFile", (long **)&WriteFile},
		{"SDF_DeleteFile", (long **)&DeleteFile},
	};

	gs_lib_handle = dlopen(path, RTLD_LAZY);
	if (gs_lib_handle == NULL)
	{
		printf("open %s error\n", path);
		return -1;
	}

	//查找符号
	for (i = 0; i < (sizeof(gs_func_name_arr) / sizeof(struct func_name_pair)); i++)
	{
		sym = (long *)dlsym(gs_lib_handle, gs_func_name_arr[i].name);
		if (sym == NULL)
		{
			printf("lookup %s error\n", gs_func_name_arr[i].name);
			goto error;
		}

		printf("%s addr %p\n", gs_func_name_arr[i].name, sym);
		*gs_func_name_arr[i].func = sym;
	}

	//打开设备
	if (!OpenDevice(&gs_sdf_device))
	{
		return 0;
	}
	printf("open device error\n");

error:
	dlclose(gs_lib_handle);
	return -2;
}

void plugin_exit(void)
{
	//关闭设备
	if (gs_sdf_device != NULL)
	{
		if (CloseDevice(gs_sdf_device))
			printf("close device error\n");
	}

	if (gs_lib_handle != NULL)
		dlclose(gs_lib_handle);
}

long open_session(void)
{
	int ret;
	void *session;

	ret = OpenSession(gs_sdf_device, &session);
	if (ret != 0)
	{
		return 0;
	}

	return (long)session;
}

int close_session(long session)
{
	return CloseSession((void *)session);
}

int hash_init(long session, unsigned int alg)
{
	return HashInit((void *)session, alg, NULL, NULL, 0);
}

int hash_update(long session, unsigned char *buf, unsigned int buf_len)
{
	return HashUpdate((void *)session, buf, buf_len);
}

int hash_final(long session, unsigned char *hash, unsigned int *hash_len)
{
	return HashFinal((void *)session, hash, hash_len);
}

int external_sign_ecc(long session, unsigned int alg, ECCrefPrivateKey *key, unsigned char *buf, unsigned int buf_len, ECCSignature *sig)
{
	return ExternalSignECC((void *)session, alg, key, buf, buf_len, sig);
}

int external_verify_ecc(long session, unsigned int alg, ECCrefPublicKey *key, unsigned char *buf, unsigned int buf_len, ECCSignature *sig)
{
	return ExternalVerifyECC((void *)session, alg, key, buf, buf_len, sig);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

//SdfInit:模块初始化,打开device、so库,查找符号表
func SdfInit(libPath string) error {
	if ret := C.plugin_init(C.CString(libPath)); ret != 0 {
		return fmt.Errorf("sdf_sym_init error: %d", ret)
	}

	return nil
}

//SdfExit:模块退出
func SdfExit() {
	C.plugin_exit()
}

//SdfOpenSession:打开会话,成功返回session_id >0,失败返回0
func SdfOpenSession() int64 {
	return int64(C.open_session())
}

//SdfCloseSession:关闭会话
func SdfCloseSession(session int64) int32 {
	return int32(C.close_session(C.long(session)))
}

//SdfSm3Init:sm3 init，传入打开的会话
func SdfSm3Init(session int64) int32 {
	return int32(C.hash_init(C.long(session), C.unsigned(C.SGD_SM3)))
}

//SdfSm3Update:sm3 update
func SdfSm3Update(session int64, buf []byte, len uint32) int32 {
	return int32(C.hash_update(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])), (C.unsigned)(len)))
}

//SdfSm3Update:sm3 final，返回32字节的hash数组
func SdfSm3Final(session int64) (int32, [32]byte) {
	var len C.unsigned
	var hash [32]byte

	return int32(C.hash_final(C.long(session), (*C.uchar)(unsafe.Pointer(&hash[0])), (*C.unsigned)(unsafe.Pointer(&len)))), hash
}

//SdfExternalSignEcc:外部密钥ECC签名, alg:C.SGD_SM2 or C.SGD_RSA
func SdfExternalSignEcc(session int64, alg uint32, privKey ECCrefPrivateKey, buf []byte, len uint32) (int32, ECCSignature) {
	var sig ECCSignature

	return int32(C.external_sign_ecc(C.long(session), C.unsigned(alg), (*C.ECCrefPrivateKey)(unsafe.Pointer(&privKey)), (*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len), (*C.ECCSignature)(unsafe.Pointer(&sig)))), sig
}

//SdfExternalVerifyEcc:外部密钥ECC签名, alg:C.SGD_SM2 or C.SGD_RSA
func SdfExternalVerifyEcc(session int64, alg uint32, pubKey ECCrefPublicKey, buf []byte, len uint32, sig ECCSignature) int32 {
	return int32(C.external_verify_ecc(C.long(session), C.unsigned(alg), (*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)), (*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len), (*C.ECCSignature)(unsafe.Pointer(&sig))))
}
