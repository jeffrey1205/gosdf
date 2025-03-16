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
int (*OpenDevice)(void **);
int (*CloseDevice)(void *);
int (*OpenSession)(void *, void **);
int (*CloseSession)(void *);

//杂凑运算
int (*HashInit)(void *, unsigned int, ECCrefPublicKey *, unsigned char *, unsigned int);
int (*HashUpdate)(void *, unsigned char *, unsigned int);
int (*HashFinal)(void *, unsigned char *, unsigned int *);

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
int (*GenerateKeyWithKEK)(void *, unsigned int, unsigned int , unsigned int, unsigned char *, unsigned int *, void **);
int (*ImportKeyWithKEK)(void *, unsigned int, unsigned int, unsigned char *, unsigned int, void **);
int (*DestroyKey)(void *, void *);

//非对称运算
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

// 随机数
int (*GenerateRandom)(void *, unsigned int, unsigned char *);

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
		{"SDF_GenerateKeyWithKEK", (long **)&GenerateKeyWithKEK},
		{"SDF_ImportKeyWithKEK", (long **)&ImportKeyWithKEK},
		{"SDF_DestroyKey", (long **)&DestroyKey},

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

		{"SDF_GenerateRandom", (long **)&GenerateRandom},
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

long open_session(int *ret)
{
	void *session = NULL;

	*ret = OpenSession(gs_sdf_device, &session);
	return (long)session;
}

int close_session(long session)
{
	return CloseSession((void *)session);
}

int hash_init(long session, unsigned int alg, ECCrefPublicKey *pub, BYTE *id, u32 id_len)
{
	return HashInit((void *)session, alg, pub, id, id_len);
}

int hash_update(long session, unsigned char *buf, unsigned int buf_len)
{
	return HashUpdate((void *)session, buf, buf_len);
}

int hash_final(long session, unsigned char *hash, unsigned int *hash_len)
{
	return HashFinal((void *)session, hash, hash_len);
}

int external_verify_ecc(long session, unsigned int alg, ECCrefPublicKey *key, unsigned char *buf, unsigned int buf_len, ECCSignature *sig)
{
	return ExternalVerifyECC((void *)session, alg, key, buf, buf_len, sig);
}

long gen_key_with_kek(long session, u32 key_bits, u32 alg_id, u32 kek_index, BYTE *key_buf, u32 *key_len, int *ret)
{
	void *key_handle = NULL;

	*ret = GenerateKeyWithKEK((HANDLE)session, key_bits, alg_id, kek_index, key_buf, key_len, &key_handle);
	return (long)key_handle;
}

int import_key_with_kek(long session, u32 alg_id, u32 kek_index, BYTE *key_buf, u32 key_len, int *ret)
{
	void *key_handle = NULL;

	*ret = ImportKeyWithKEK((HANDLE)session, alg_id, kek_index, key_buf, key_len, &key_handle);
	return (long)key_handle;
}

int destroy_key(long session, long key)
{
	return DestroyKey((HANDLE)session, (HANDLE)key);
}

int encrypt(long session, long key, u32 alg, BYTE *iv, BYTE *data, u32 data_len, BYTE *out_buf, u32 *out_len)
{
	return Encrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

int decrypt(long session, long key, u32 alg, BYTE *iv, BYTE *data, u32 data_len, BYTE *out_buf, u32 *out_len)
{
	return Decrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

int cbc_mac(long session, long key, u32 alg, BYTE *iv, BYTE *data, u32 data_len, BYTE *out_buf, u32 *out_len)
{
	return CalculateMAC((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
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

int gen_random(long session, unsigned int len, unsigned char *buf)
{
	return GenerateRandom((void *)session, len, buf);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Init:模块初始化,打开device、so库,查找符号表
func Init(libPath string) error {
	if ret := C.plugin_init(C.CString(libPath)); ret != 0 {
		return fmt.Errorf("sdf_sym_init error: %d", ret)
	}

	return nil
}

// Exit:模块退出
func Exit() {
	C.plugin_exit()
}

// OpenSession:打开会话,成功返回session_id >0,失败返回0和错误码
func OpenSession() (int, SDR) {
	var ret C.int
	session := C.open_session((*C.int)(unsafe.Pointer(&ret)))
	return int(session), SDR(ret)
}

// CloseSession:关闭会话
func CloseSession(session int) SDR {
	return SDR(C.close_session(C.long(session)))
}

// Sm3Init:sm3 init，传入打开的会话
func Sm3Init(session int) SDR {
	return SDR(C.hash_init(C.long(session), C.unsigned(C.SGD_SM3), nil, nil, 0))
}

// Sm3InitWithPubKey:sm3 init，传入打开的会话,公钥进行预处理，用于签名验签
func Sm3InitWithPubKey(session int, pubKey ECCrefPublicKey, id []byte) SDR {
	return SDR(C.hash_init(C.long(session), C.unsigned(C.SGD_SM3),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)),
		(*C.uchar)(unsafe.Pointer(&id[0])), C.unsigned(len(id))))
}

// Sm3Update:sm3 update
func Sm3Update(session int, buf []byte) SDR {
	return SDR(C.hash_update(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(buf))))
}

// SdfSm3Update:sm3 final，返回32字节的hash数组
func Sm3Final(session int) ([]byte, SDR) {
	var len C.unsigned = 32
	hash := make([]byte, 32)

	ret := C.hash_final(C.long(session), (*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.unsigned)(unsafe.Pointer(&len)))

	return hash, SDR(ret)
}

// GenerateKeyWithKEK: 生成会话密钥并导出,密钥会用PKCS7填充
func GenerateKeyWithKEK(session int, kekIndex uint32, keyBits uint32) ([]byte, int, SDR) {
	buf := make([]byte, 256)
	var keyLen C.unsigned
	var ret C.int

	handle := C.gen_key_with_kek(C.long(session), C.unsigned(keyBits),
		C.unsigned(C.SGD_SMS4_ECB), C.unsigned(kekIndex),
		(*C.uchar)(unsafe.Pointer(&buf[0])), (*C.unsigned)(unsafe.Pointer(&keyLen)),
		(*C.int)(unsafe.Pointer(&ret)))
	if ret != 0 {
		return nil, 0, SDR(ret)
	}

	keyBuf := make([]byte, keyLen)
	copy(keyBuf, buf[:keyLen])
	return keyBuf, int(handle), SDR(ret)
}

// ImportKeyWithKEK: 导入并解密会话密钥
func ImportKeyWithKEK(session int, kekIndex uint32, key []byte) (int, SDR) {
	var ret C.int

	handle := C.import_key_with_kek(C.long(session), C.unsigned(C.SGD_SMS4_ECB),
		C.unsigned(kekIndex), (*C.uchar)(unsafe.Pointer(&key[0])),
		C.unsigned(len(key)), (*C.int)(unsafe.Pointer(&ret)))

	return int(handle), SDR(ret)
}

// DestroyKey:销毁会话密钥,释放密钥句柄
func DestroyKey(session, keyHandle int) SDR {
	return SDR(C.destroy_key(C.long(session), C.long(keyHandle)))
}

// SM4EncryptECB:sm4加密，ECB模式，调用者须填充
func SM4EncryptECB(session, key int, data []byte) ([]byte, SDR) {
	outBuf := make([]byte, len(data))
	iv := make([]byte, 16)
	var outLen C.unsigned = 0

	ret := C.encrypt(C.long(session), C.long(key), C.unsigned(C.SGD_SMS4_ECB),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, SDR(ret)
}

// SM4EncryptCBC:sm4加密，CBC模式，调用者须填充
func SM4EncryptCBC(session, key int, iv, data []byte) ([]byte, SDR) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := C.encrypt(C.long(session), C.long(key), C.unsigned(C.SGD_SMS4_CBC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, SDR(ret)
}

// SM4DecryptECB:sm4解密，ECB模式
func SM4DecryptECB(session, key int, data []byte) ([]byte, SDR) {
	outBuf := make([]byte, len(data))
	iv := make([]byte, 16)
	var outLen C.unsigned = 0

	ret := C.decrypt(C.long(session), C.long(key), C.unsigned(C.SGD_SMS4_ECB),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, SDR(ret)
}

// SM4DecryptCBC:sm4解密，CBC模式
func SM4DecryptCBC(session, key int, iv, data []byte) ([]byte, SDR) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := C.decrypt(C.long(session), C.long(key), C.unsigned(C.SGD_SMS4_CBC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, SDR(ret)
}

// 计算SM4 CBC-MAC,此函数为单包计算,若要多包计算,使用IV进行控制
func SM4CalculateCBCMAC(session, key int, iv []byte, data []byte) ([]byte, SDR) {
	outBuf := make([]byte, 16) // SM4 CBC-MAC固定16字节
	var outLen C.unsigned = 0

	ret := C.cbc_mac(C.long(session), C.long(key), C.unsigned(C.SGD_SMS4_CBC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))

	return outBuf, SDR(ret)
}

// Sm2ExtKeyVerify:sm2外部key验签
func Sm2ExtKeyVerify(session int, pubKey ECCrefPublicKey, buf []byte, sig ECCSignature) SDR {
	return SDR(C.external_verify_ecc(C.long(session), C.unsigned(C.SGD_SM2_1),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)), (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(buf)), (*C.ECCSignature)(unsafe.Pointer(&sig))))
}

// CreateFile:卡中创建文件
func CreateFile(session int, fileName string, fileSize uint32) SDR {
	buf := make([]byte, len(fileName))
	return SDR(C.create_file(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(fileName)), C.unsigned(fileSize)))
}

// ReadFile:读取卡中文件,从offset开始读取readLen字节
func ReadFile(session int, fileName string, offSet, readLen uint32) ([]byte, SDR) {
	fileBytes := make([]byte, len(fileName))
	buf := make([]byte, readLen) //读取文件buf

	ret := C.read_file(C.long(session), (*C.uchar)(unsafe.Pointer(&fileBytes[0])),
		C.unsigned(len(fileName)), C.unsigned(offSet),
		(*C.unsigned)(unsafe.Pointer(&readLen)),
		(*C.uchar)(unsafe.Pointer(&buf[0])))

	return buf, SDR(ret)
}

// WriteFile:文件写入内容,从offset开始写入readLen字节
func WriteFile(session int, fileName string, offSet uint32, buf []byte) SDR {
	fileBytes := make([]byte, len(fileName))
	return SDR(C.write_file(C.long(session), (*C.uchar)(unsafe.Pointer(&fileBytes[0])),
		C.unsigned(len(fileName)), C.unsigned(offSet), C.unsigned(len(buf)),
		(*C.uchar)(unsafe.Pointer(&buf[0]))))
}

// DeleteFile:删除卡中文件
func DeleteFile(session int, fileName string) SDR {
	buf := make([]byte, len(fileName))
	return SDR(C.delete_file(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(fileName))))
}

// GenerateRandom:生成随机数
func GenerateRandom(len int) ([]byte, SDR) {
	session, ret := OpenSession()
	if ret != 0 {
		return nil, ret
	}
	defer CloseSession(session)

	buf := make([]byte, len)
	ret = SDR(C.gen_random(C.long(session), C.unsigned(len), (*C.uchar)(unsafe.Pointer(&buf[0]))))
	return buf, ret
}
