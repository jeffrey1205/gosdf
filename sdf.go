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
int (* OpenDevice)(void **);
int (* CloseDevice)(void *);
int (* OpenSession)(void *, void **);
int (* CloseSession)(void *);

//杂凑运算
int (* HashInit)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int);
int (* HashUpdate)(void *, unsigned char *, unsigned int);
int (* HashFinal)(void *, unsigned char *, unsigned int *);

//密钥管理
int (*ExportSignPublicKeyECC)(void *, unsigned int, ECCrefPublicKey *);
int (*ExportEncPublicKeyECC)(void *, unsigned int, ECCrefPublicKey *);
int (*GenerateKeyPairECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *,ECCrefPrivateKey *);
int (*GenerateKeyWithIPKECC)(void *, unsigned int, unsigned int, ECCCipher *, void **);
int (*GenerateKeyWithEPKECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *, ECCCipher *, void **);
int (*ImportKeyWithISKECC)(void *, unsigned int, ECCCipher *, void **);
int (*GenerateAgreementDataWithECC)(void *, unsigned int, unsigned int, unsigned char *, unsigned int, ECCrefPublicKey *, ECCrefPublicKey *, void **);
int (*GenerateKeyWithECC)(void *, unsigned char *, unsigned int, ECCrefPublicKey *, ECCrefPublicKey *, void *, void **);
int (*GenerateAgreementDataAndKeyWithECC)(void *, unsigned int, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int, ECCrefPublicKey *, ECCrefPublicKey *, ECCrefPublicKey *, ECCrefPublicKey *, void *, void **);
int (*ExchangeDigitEnvelopeBaseOnECC)(void *, unsigned int, unsigned int, ECCrefPublicKey *, ECCCipher *, ECCCipher *);
int (*ImportKey)(void *, unsigned char *, unsigned int , void **);
int (*DestroyKey)(void *, void *);

//非对称运算
int (*ExternalSignECC)(void *, unsigned int, ECCrefPrivateKey *, unsigned char *, unsigned int, ECCSignature *);
int (*ExternalVerifyECC)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int, ECCSignature *);
int (*InternalSignECC)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature *);
int (*InternalVerifyECC)(void *, unsigned int, unsigned char *, unsigned int, ECCSignature *);
int (*ExternalEncryptECC)(void *, unsigned int, ECCrefPublicKey *,unsigned char *, unsigned int, ECCCipher *);
int (*ExternalDecryptECC)(void *, unsigned int, ECCrefPrivateKey *, ECCCipher *, unsigned char *, unsigned int *);
int (*InternalEncryptECC)(void *, unsigned int, unsigned char *, unsigned int, ECCCipher *);
int (*InternalDecryptECC)(void *, unsigned int, ECCCipher *, unsigned char *, unsigned int *);

//对称运算
int (*Encrypt)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
int (*Decrypt)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);
int (*CalculateMAC)(void *, void *, unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned char *, unsigned int *);

//文件管理
int (*CreateFile)(void *, unsigned char *, unsigned int, unsigned int);
int (*ReadFile)(void *, unsigned char *, unsigned int, unsigned int, unsigned int *, unsigned char *);
int (*WriteFile)(void *, unsigned char *, unsigned int, unsigned int, unsigned int, unsigned char *);
int (*DeleteFile)(void *, unsigned char *, unsigned int);

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

int create_file(long session, unsigned char *name, unsigned int name_len, unsigned int size)
{
	return CreateFile((void *)session, name, name_len, size);
}

int read_file(long session, unsigned char *name, unsigned int name_len, unsigned int offset, unsigned int *file_len, unsigned char *buf)
{
	return ReadFile((void *)session, name, name_len, offset, file_len, buf);
}

int write_file(long session, unsigned char *name, unsigned int name_len, unsigned int offset, unsigned int file_len, unsigned char *buf)
{
	return WriteFile((void *)session, name, name_len, offset, file_len, buf);
}

int delete_file(long session, unsigned char *name, unsigned int name_len)
{
	return DeleteFile((void *)session, name, name_len);
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

//SdfSm2ExtKeySign:sm2外部key签名
func SdfSm2ExtKeySign(session int64, privKey ECCrefPrivateKey, buf []byte, len uint32) (int32, ECCSignature) {
	var sig ECCSignature

	return int32(C.external_sign_ecc(C.long(session), C.unsigned(C.SGD_SM2_1), (*C.ECCrefPrivateKey)(unsafe.Pointer(&privKey)), (*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len), (*C.ECCSignature)(unsafe.Pointer(&sig)))), sig
}

//SdfSm2ExtKeyVerify:sm2外部key验签
func SdfSm2ExtKeyVerify(session int64, pubKey ECCrefPublicKey, buf []byte, len uint32, sig ECCSignature) int32 {
	return int32(C.external_verify_ecc(C.long(session), C.unsigned(C.SGD_SM2_1), (*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)), (*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len), (*C.ECCSignature)(unsafe.Pointer(&sig))))
}

//SdfCreateFile:卡中创建文件
func SdfCreateFile(session int64, fileName string, fileSize uint32) int32 {
	buf := make([]byte, len(fileName))
	return int32(C.create_file(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len(fileName)), C.unsigned(fileSize)))
}

//SdfReadFile:读取卡中文件,从offset开始读取readLen字节
func SdfReadFile(session int64, fileName string, offSet, readLen uint32) (int32, []byte) {
	fileBytes := make([]byte, len(fileName))
	buf := make([]byte, readLen) //读取文件buf
	return int32(C.read_file(C.long(session), (*C.uchar)(unsafe.Pointer(&fileBytes[0])), C.unsigned(len(fileName)), C.unsigned(offSet), (*C.unsigned)(unsafe.Pointer(&readLen)), (*C.uchar)(unsafe.Pointer(&buf[0])))), buf
}

//SdfWriteFile:文件写入内容,从offset开始写入readLen字节
func SdfWriteFile(session int64, fileName string, offSet, writeLen uint32, buf []byte) int32 {
	fileBytes := make([]byte, len(fileName))
	return int32(C.write_file(C.long(session), (*C.uchar)(unsafe.Pointer(&fileBytes[0])), C.unsigned(len(fileName)), C.unsigned(offSet), C.unsigned(writeLen), (*C.uchar)(unsafe.Pointer(&buf[0]))))
}

//SdfDeleteFile:删除卡中文件
func SdfDeleteFile(session int64, fileName string) int32 {
	buf := make([]byte, len(fileName))
	return int32(C.delete_file(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len(fileName))))
}
