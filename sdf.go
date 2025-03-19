package gosdf

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -ldl
#include <stdio.h>
#include <dlfcn.h>

#include "sdf.h"

#define SW_GM0018_2012 // SW加密卡2012版本接口

static HANDLE gs_sdf_device = NULL; //加密设备
static HANDLE gs_lib_handle = NULL; //so库

//设备管理
RV (*OpenDevice)(HANDLE*);
RV (*CloseDevice)(HANDLE);
RV (*OpenSession)(HANDLE, HANDLE*);
RV (*CloseSession)(HANDLE);
RV (*GetPrivateKeyAccessRight)(HANDLE, UINT32, UCHAR *, UINT32);
RV (*ReleasePrivateKeyAccessRight)(HANDLE, UINT32);

//杂凑运算
RV (*HashInit)(HANDLE, UINT32, ECCrefPublicKey *, UCHAR *, UINT32);
RV (*HashUpdate)(HANDLE, UCHAR *, UINT32);
RV (*HashFinal)(HANDLE, UCHAR *, UINT32 *);

//HMAC运算函数:该实现为三未信安提供,跟0018-2023不一致
RV (*HMACInit)(HANDLE, UINT32, UINT32, UCHAR*, UINT32);
RV (*HMACUpdate)(HANDLE, UCHAR*, UINT32);
RV (*HMACFinal)(HANDLE, UCHAR*, UINT32*);

//密钥管理
RV (*ExportSignPublicKeyECC)(HANDLE, UINT32, ECCrefPublicKey *);
RV (*ExportEncPublicKeyECC)(HANDLE, UINT32, ECCrefPublicKey *);
RV (*GenerateKeyWithIPKECC)(HANDLE, UINT32, UINT32, ECCCipher *, HANDLE*);
RV (*GenerateKeyWithEPKECC)(HANDLE, UINT32, UINT32, ECCrefPublicKey *, ECCCipher *, HANDLE*);
RV (*ImportKeyWithISKECC)(HANDLE, UINT32, ECCCipher *, HANDLE*);
RV (*GenerateKeyWithKEK)(HANDLE, UINT32, UINT32 , UINT32, UCHAR *, UINT32 *, HANDLE*);
RV (*ImportKeyWithKEK)(HANDLE, UINT32, UINT32, UCHAR *, UINT32, HANDLE*);
RV (*DestroyKey)(HANDLE, HANDLE);

//非对称运算
RV (*ExternalVerifyECC)(HANDLE, UINT32, ECCrefPublicKey *, UCHAR *, UINT32, ECCSignature *);
RV (*InternalSignECC)(HANDLE, UINT32, UCHAR *, UINT32, ECCSignature *);
RV (*InternalVerifyECC)(HANDLE, UINT32, UCHAR *, UINT32, ECCSignature *);
RV (*ExternalEncryptECC)(HANDLE, UINT32, ECCrefPublicKey *,UCHAR *, UINT32, ECCCipher *);

//对称运算
RV (*Encrypt)(HANDLE, HANDLE, UINT32, UCHAR *, UCHAR *, UINT32, UCHAR *, UINT32 *);
RV (*Decrypt)(HANDLE, HANDLE, UINT32, UCHAR *, UCHAR *, UINT32, UCHAR *, UINT32 *);
RV (*CalculateMAC)(HANDLE, HANDLE, UINT32, UCHAR *, UCHAR *, UINT32, UCHAR *, UINT32 *);

//文件管理
RV (*CreateFile)(HANDLE, UCHAR *, UINT32, UINT32);
RV (*ReadFile)(HANDLE, UCHAR *, UINT32, UINT32, UINT32 *, UCHAR *);
RV (*WriteFile)(HANDLE, UCHAR *, UINT32, UINT32, UINT32, UCHAR *);
RV (*DeleteFile)(HANDLE, UCHAR *, UINT32);

// 随机数
RV (*GenerateRandom)(HANDLE, UINT32, UCHAR *);

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
		{"SDF_GetPrivateKeyAccessRight", (long **)&GetPrivateKeyAccessRight},
		{"SDF_ReleasePrivateKeyAccessRight", (long **)&ReleasePrivateKeyAccessRight},

		{"SDF_HashInit", (long **)&HashInit},
		{"SDF_HashUpdate", (long **)&HashUpdate},
		{"SDF_HashFinal", (long **)&HashFinal},

#ifdef SW_GM0018_2012
		{"SDF_HMAC_Init", (long **)&HMACInit},
		{"SDF_HMAC_Update", (long **)&HMACUpdate},
		{"SDF_HMAC_Final", (long **)&HMACFinal},
#endif

		{"SDF_ExportSignPublicKey_ECC", (long **)&ExportSignPublicKeyECC},
		{"SDF_ExportEncPublicKey_ECC", (long **)&ExportEncPublicKeyECC},
		{"SDF_GenerateKeyWithIPK_ECC", (long **)&GenerateKeyWithIPKECC},
		{"SDF_GenerateKeyWithEPK_ECC", (long **)&GenerateKeyWithEPKECC},
		{"SDF_ImportKeyWithISK_ECC", (long **)&ImportKeyWithISKECC},
		{"SDF_GenerateKeyWithKEK", (long **)&GenerateKeyWithKEK},
		{"SDF_ImportKeyWithKEK", (long **)&ImportKeyWithKEK},
		{"SDF_DestroyKey", (long **)&DestroyKey},

		{"SDF_ExternalVerify_ECC", (long **)&ExternalVerifyECC},
		{"SDF_InternalSign_ECC", (long **)&InternalSignECC},
		{"SDF_InternalVerify_ECC", (long **)&InternalVerifyECC},
		{"SDF_ExternalEncrypt_ECC", (long **)&ExternalEncryptECC},

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

RV open_session(long **session)
{
	return OpenSession(gs_sdf_device, (HANDLE *)session);
}

RV close_session(long *session)
{
	return CloseSession(session);
}

RV hash_init(long *session, UINT32 alg, ECCrefPublicKey *pub, BYTE *id, UINT32 id_len)
{
	return HashInit((HANDLE)session, alg, pub, id, id_len);
}

RV hash_update(long *session, UCHAR *buf, UINT32 buf_len)
{
	return HashUpdate((HANDLE)session, buf, buf_len);
}

RV hash_final(long *session, UCHAR *hash, UINT32 *hash_len)
{
	return HashFinal((HANDLE)session, hash, hash_len);
}

RV hmac_init(long *session, UINT32 alg, UINT32 kek, UCHAR* pucKey, UINT32 key_len)
{
	return HMACInit((HANDLE)session, alg, kek, pucKey, key_len);
}

RV hmac_update(long *session, UCHAR* data, UINT32 data_len)
{
	return HMACUpdate((HANDLE)session, data, data_len);
}

RV hmac_final(long *session, UCHAR* mac, UINT32* mac_len)
{
	return HMACFinal((HANDLE)session, mac, mac_len);
}

RV verify_pin(long *session, UINT32 key_index, UCHAR *pin, UINT32 pin_len)
{
	return GetPrivateKeyAccessRight((HANDLE)session, key_index, pin, pin_len);
}

RV release_pin(long *session, UINT32 key_index)
{
	return ReleasePrivateKeyAccessRight((HANDLE)session, key_index);
}

RV export_sign_pubkey_ecc(long *session, UINT32 key_index, ECCrefPublicKey *pub)
{
	return ExportSignPublicKeyECC((HANDLE)session, key_index, pub);
}

RV export_enc_pubkey_ecc(long *session, UINT32 key_index, ECCrefPublicKey *pub)
{
	return ExportEncPublicKeyECC((HANDLE)session, key_index, pub);
}

RV gen_key_with_ipk_ecc(long *session, UINT32 key_index, UINT32 key_bits, ECCCipher *key, long **key_handle)
{
	return GenerateKeyWithIPKECC((HANDLE)session, key_index, key_bits, key, (HANDLE *)key_handle);
}

RV gen_key_with_epk_ecc(long *session, UINT32 key_bits, UINT32 alg, ECCrefPublicKey *pub, ECCCipher *key, long **key_handle)
{
	return GenerateKeyWithEPKECC((HANDLE)session, key_bits, alg, pub, key, (HANDLE *)key_handle);
}

RV import_key_with_isk_ecc(long *session, UINT32 key_index, ECCCipher *key, long **key_handle)
{
	return ImportKeyWithISKECC((HANDLE)session, key_index, key, (HANDLE *)key_handle);
}

RV internal_sign_ecc(long *session, UINT32 key_index, UCHAR *data, UINT32 data_len, ECCSignature *sig)
{
	return InternalSignECC((HANDLE)session, key_index, data, data_len, sig);
}

RV internal_verify_ecc(long *session, UINT32 key_index, UCHAR *data, UINT32 data_len, ECCSignature *sig)
{
	return InternalVerifyECC((HANDLE)session, key_index, data, data_len, sig);
}

RV external_verify_ecc(long *session, UINT32 alg, ECCrefPublicKey *pub, UCHAR *buf, UINT32 buf_len, ECCSignature *sig)
{
	return ExternalVerifyECC((HANDLE)session, alg, pub, buf, buf_len, sig);
}

RV external_encrypt_ecc(long *session, UINT32 alg, ECCrefPublicKey *pub, UCHAR *data, UINT32 data_len, ECCCipher *cipher)
{
	return ExternalEncryptECC((HANDLE)session, alg, pub, data, data_len, cipher);
}

long gen_key_with_kek(long *session, UINT32 key_bits, UINT32 alg_id, UINT32 kek_index, BYTE *key_buf, UINT32 *key_len, long **key_handle)
{
	return GenerateKeyWithKEK((HANDLE)session, key_bits, alg_id, kek_index, key_buf, key_len, (HANDLE *)key_handle);
}

RV import_key_with_kek(long *session, UINT32 alg_id, UINT32 kek_index, BYTE *key_buf, UINT32 key_len, long **key_handle)
{
	return ImportKeyWithKEK((HANDLE)session, alg_id, kek_index, key_buf, key_len, (HANDLE *)key_handle);
}

RV destroy_key(long *session, long *key)
{
	return DestroyKey((HANDLE)session, (HANDLE)key);
}

RV encrypt(long *session, long *key, UINT32 alg, BYTE *iv, BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	return Encrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV decrypt(long *session, long *key, UINT32 alg, BYTE *iv, BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	return Decrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV cbc_mac(long *session, long *key, UINT32 alg, BYTE *iv, BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	return CalculateMAC((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV create_file(long *session, UCHAR *name, UINT32 name_len, UINT32 size)
{
	return CreateFile((HANDLE)session, name, name_len, size);
}

RV read_file(long *session, UCHAR *name, UINT32 name_len, UINT32 offset, UINT32 *file_len, UCHAR *buf)
{
	return ReadFile((HANDLE)session, name, name_len, offset, file_len, buf);
}

RV write_file(long *session, UCHAR *name, UINT32 name_len, UINT32 offset, UINT32 file_len, UCHAR *buf)
{
	return WriteFile((HANDLE)session, name, name_len, offset, file_len, buf);
}

RV delete_file(long *session, UCHAR *name, UINT32 name_len)
{
	return DeleteFile((HANDLE)session, name, name_len);
}

RV gen_random(long *session, UINT32 len, UCHAR *buf)
{
	return GenerateRandom((HANDLE)session, len, buf);
}
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
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
func OpenSession() (HANDLE, RV) {
	var session HANDLE
	ret := C.open_session((**C.long)(unsafe.Pointer(&session)))
	return HANDLE(session), RV(ret)
}

// CloseSession:关闭会话
func CloseSession(session HANDLE) RV {
	return RV(C.close_session((*C.long)(unsafe.Pointer(session))))
}

// GetPrivateKeyAccessRight:获取私钥访问权限,内部私钥签名、解密需要此权限
func GetPrivateKeyAccessRight(session HANDLE, kekIndex uint32, passwd []byte) RV {
	return RV(C.verify_pin((*C.long)(unsafe.Pointer(session)), C.unsigned(kekIndex),
		(*C.uchar)(unsafe.Pointer(&passwd[0])), C.unsigned(len(passwd))))
}

// ReleasePrivateKeyAccessRight:释放私钥访问权限
func ReleasePrivateKeyAccessRight(session HANDLE, kekIndex uint32) RV {
	return RV(C.release_pin((*C.long)(unsafe.Pointer(session)), C.unsigned(kekIndex)))
}

// Sm3Init:sm3 init，传入打开的会话
func Sm3Init(session HANDLE) RV {
	return RV(C.hash_init((*C.long)(unsafe.Pointer(session)),
		C.unsigned(C.SGD_SM3), nil, nil, 0))
}

// Sm3InitWithPubKey:sm3 init，传入打开的会话,公钥进行预处理，用于签名验签
func Sm3InitWithPubKey(session HANDLE, pubKey ECCrefPublicKey, id []byte) RV {
	return RV(C.hash_init((*C.long)(unsafe.Pointer(session)),
		C.unsigned(C.SGD_SM3), (*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)),
		(*C.uchar)(unsafe.Pointer(&id[0])), C.unsigned(len(id))))
}

// Sm3Update:sm3 update
func Sm3Update(session HANDLE, buf []byte) RV {
	return RV(C.hash_update((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len(buf))))
}

// SdfSm3Update:sm3 final，返回32字节的hash数组
func Sm3Final(session HANDLE) ([]byte, RV) {
	var len C.unsigned = 32 // sm3 hash长度固定32字节
	hash := make([]byte, 32)

	ret := C.hash_final((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.unsigned)(unsafe.Pointer(&len)))

	return hash, RV(ret)
}

// Sm3HMACInit:hmac-sm3,此处暂时匹配sw卡,跟2023标准暂不一致
func Sm3HMACInit(session HANDLE, kekIndex uint32, key []byte) RV {
	return RV(C.hmac_init((*C.long)(unsafe.Pointer(session)),
		C.unsigned(C.SGD_SM3), C.unsigned(kekIndex),
		(*C.uchar)(unsafe.Pointer(&key[0])), C.unsigned(len(key))))
}

// Sm3HMACUpdate:hmac-sm3 update
func Sm3HMACUpdate(session HANDLE, data []byte) RV {
	return RV(C.hmac_update((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.unsigned(len(data))))
}

// Sm3HMACFinal:hmac-sm3 final,返回32字节的hash数组
func Sm3HMACFinal(session HANDLE) ([]byte, RV) {
	var len C.unsigned = 32 // sm3 hash长度固定32字节
	hash := make([]byte, 32)

	ret := C.hmac_final((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.unsigned)(unsafe.Pointer(&len)))

	return hash, RV(ret)
}

// ExportSignPublicKeyECC:导出ECC签名公钥
func ExportSignPublicKeyECC(session HANDLE, keyIndex uint32) (ECCrefPublicKey, RV) {
	var pubKey ECCrefPublicKey

	ret := C.export_sign_pubkey_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyIndex), (*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)))
	return pubKey, RV(ret)
}

// ExportEncPublicKeyECC:导出ECC加密公钥
func ExportEncPublicKeyECC(session HANDLE, keyIndex uint32) (ECCrefPublicKey, RV) {
	var pubKey ECCrefPublicKey

	ret := C.export_enc_pubkey_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyIndex), (*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)))
	return pubKey, RV(ret)
}

// GenerateKeyWithIPKECC:生成会话密钥,并用内部ECC加密公钥加密后导出
func GenerateKeyWithIPKECC(session HANDLE, keyIndex uint32, keyBits uint32) (ECCCipher, HANDLE, RV) {
	var cipher ECCCipher
	var keyHandle HANDLE

	ret := C.gen_key_with_ipk_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyIndex), C.unsigned(keyBits),
		(*C.ECCCipher)(unsafe.Pointer(&cipher)),
		(**C.long)(unsafe.Pointer(&keyHandle)))
	return cipher, keyHandle, RV(ret)
}

// GenerateKeyWithEPKECC:生成会话密钥,并用外部ECC加密公钥加密后导出
func GenerateKeyWithEPKECC(session HANDLE, keyBits uint32, pubKey ECCrefPublicKey) (ECCCipher, HANDLE, RV) {
	var cipher ECCCipher
	var keyHandle HANDLE

	ret := C.gen_key_with_epk_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyBits), C.unsigned(C.SGD_SM2_3),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)),
		(*C.ECCCipher)(unsafe.Pointer(&cipher)),
		(**C.long)(unsafe.Pointer(&keyHandle)))
	return cipher, keyHandle, RV(ret)
}

// ImportKeyWithISKECC:导入会话密钥,并用内部ECC加密私钥解密
func ImportKeyWithISKECC(session HANDLE, keyIndex uint32, cipher ECCCipher) (HANDLE, RV) {
	var keyHandle HANDLE

	ret := C.import_key_with_isk_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyIndex), (*C.ECCCipher)(unsafe.Pointer(&cipher)),
		(**C.long)(unsafe.Pointer(&keyHandle)))
	return keyHandle, RV(ret)
}

// GenerateKeyWithKEK: 生成会话密钥并导出,密钥会用PKCS7填充
func GenerateKeyWithKEK(session HANDLE, kekIndex uint32, keyBits uint32) ([]byte, HANDLE, RV) {
	buf := make([]byte, 256)
	var keyLen C.unsigned
	var keyHandle HANDLE

	ret := C.gen_key_with_kek((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyBits), C.unsigned(C.SGD_SMS4_ECB), C.unsigned(kekIndex),
		(*C.uchar)(unsafe.Pointer(&buf[0])), (*C.unsigned)(unsafe.Pointer(&keyLen)),
		(**C.long)(unsafe.Pointer(&keyHandle)))
	if ret != 0 {
		return nil, nil, RV(ret)
	}

	keyBuf := make([]byte, keyLen)
	copy(keyBuf, buf[:keyLen])
	return keyBuf, keyHandle, RV(ret)
}

// ImportKeyWithKEK: 导入并解密会话密钥
func ImportKeyWithKEK(session HANDLE, kekIndex uint32, key []byte) (HANDLE, RV) {
	var keyHandle HANDLE

	ret := C.import_key_with_kek((*C.long)(unsafe.Pointer(session)),
		C.unsigned(C.SGD_SMS4_ECB),
		C.unsigned(kekIndex), (*C.uchar)(unsafe.Pointer(&key[0])),
		C.unsigned(len(key)), (**C.long)(unsafe.Pointer(&keyHandle)))

	return keyHandle, RV(ret)
}

// DestroyKey:销毁会话密钥,释放密钥句柄
func DestroyKey(session, keyHandle HANDLE) RV {
	return RV(C.destroy_key((*C.long)(unsafe.Pointer(keyHandle)),
		(*C.long)(unsafe.Pointer(keyHandle))))
}

// 以下几个签名、验签函数,须传入经过预处理后的HASH值,不能直接传递消息原文
// ExternalKeyVerifyECC:ECC外部签名公钥验签
func ExternalKeyVerifyECC(session HANDLE, pubKey ECCrefPublicKey, buf []byte, sig ECCSignature) RV {
	return RV(C.external_verify_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(C.SGD_SM2_1),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)),
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(buf)), (*C.ECCSignature)(unsafe.Pointer(&sig))))
}

// InternalSignECC:内部ECC签名私钥签名
func InternalSignECC(session HANDLE, keyIndex uint32, hash []byte) (ECCSignature, RV) {
	var sig ECCSignature

	ret := C.internal_sign_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyIndex), (*C.uchar)(unsafe.Pointer(&hash[0])),
		C.unsigned(len(hash)), (*C.ECCSignature)(unsafe.Pointer(&sig)))
	return sig, RV(ret)
}

// InternalVerifyECC:内部ECC签名公钥验签
func InternalVerifyECC(session HANDLE, keyIndex uint32, hash []byte, sig ECCSignature) RV {
	return RV(C.internal_verify_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyIndex), (*C.uchar)(unsafe.Pointer(&hash[0])),
		C.unsigned(len(hash)), (*C.ECCSignature)(unsafe.Pointer(&sig))))
}

// ExternalEncryptECC:外部ECC加密公钥加密
func ExternalEncryptECC(session HANDLE, pubKey ECCrefPublicKey, data []byte) (ECCCipher, RV) {
	var cipher ECCCipher

	ret := C.external_encrypt_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(C.SGD_SM2_3), (*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.unsigned(len(data)),
		(*C.ECCCipher)(unsafe.Pointer(&cipher)))
	return cipher, RV(ret)
}

// SM4EncryptECB:sm4加密，ECB模式，调用者须填充
func SM4EncryptECB(session, key HANDLE, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	iv := make([]byte, 16)
	var outLen C.unsigned = 0

	ret := C.encrypt((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(C.SGD_SMS4_ECB),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, RV(ret)
}

// SM4EncryptCBC:sm4加密，CBC模式，调用者须填充
func SM4EncryptCBC(session, key HANDLE, iv, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := C.encrypt((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(C.SGD_SMS4_CBC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, RV(ret)
}

// SM4DecryptECB:sm4解密，ECB模式
func SM4DecryptECB(session, key HANDLE, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	iv := make([]byte, 16)
	var outLen C.unsigned = 0

	ret := C.decrypt((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(C.SGD_SMS4_ECB),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, RV(ret)
}

// SM4DecryptCBC:sm4解密，CBC模式
func SM4DecryptCBC(session, key HANDLE, iv, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := C.decrypt((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(C.SGD_SMS4_CBC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, RV(ret)
}

// SM4CalculateCBCMAC:计算SM4 CBC-MAC,此函数为单包计算,若要多包计算,使用IV进行控制.该函数不填充
// CBC-MAC在长度不固定时有长度扩展攻击问题.建议以下方式使用:
// 1. 使用ISO9797-1 M3填充方式(首选)
// 2. 使用SM3计算消息HASH,再对HASH进行CBC-MAC计算
// 3. 填充数据到固定长度
// 4. 使用另一个KEY加密CBC-MAC作为最终MAC
func SM4CalculateCBCMAC(session, key HANDLE, iv []byte, data []byte) ([]byte, RV) {
	outBuf := make([]byte, 16) // SM4 CBC-MAC固定16字节
	var outLen C.unsigned = 0

	ret := C.cbc_mac((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(C.SGD_SMS4_MAC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))

	return outBuf, RV(ret)
}

// CreateFile:卡中创建文件
func CreateFile(session HANDLE, fileName string, fileSize uint32) RV {
	buf := make([]byte, len(fileName))
	return RV(C.create_file((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(fileName)), C.unsigned(fileSize)))
}

// ReadFile:读取卡中文件,从offset开始读取readLen字节
func ReadFile(session HANDLE, fileName string, offSet, readLen uint32) ([]byte, RV) {
	fileBytes := make([]byte, len(fileName))
	buf := make([]byte, readLen) //读取文件buf

	ret := C.read_file((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&fileBytes[0])),
		C.unsigned(len(fileName)), C.unsigned(offSet),
		(*C.unsigned)(unsafe.Pointer(&readLen)),
		(*C.uchar)(unsafe.Pointer(&buf[0])))

	return buf, RV(ret)
}

// WriteFile:文件写入内容,从offset开始写入readLen字节
func WriteFile(session HANDLE, fileName string, offSet uint32, buf []byte) RV {
	fileBytes := make([]byte, len(fileName))
	return RV(C.write_file((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&fileBytes[0])),
		C.unsigned(len(fileName)), C.unsigned(offSet), C.unsigned(len(buf)),
		(*C.uchar)(unsafe.Pointer(&buf[0]))))
}

// DeleteFile:删除卡中文件
func DeleteFile(session HANDLE, fileName string) RV {
	buf := make([]byte, len(fileName))
	return RV(C.delete_file((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(fileName))))
}

// GenerateRandom:生成随机数
func GenerateRandom(len int) ([]byte, RV) {
	session, ret := OpenSession()
	if ret != 0 {
		return nil, ret
	}
	defer CloseSession(session)

	buf := make([]byte, len)
	ret = RV(C.gen_random((*C.long)(unsafe.Pointer(session)),
		C.unsigned(len), (*C.uchar)(unsafe.Pointer(&buf[0]))))
	return buf, ret
}

// GB/T 17964-2021 附录C.4 填充方法3, 生成块L,单位为Byte
// ISO9797M3Padding 实现M3填充, 生成块L,单位为Bit
func ISO9797M3Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("block size must be positive")
	}

	// 计算原始数据的字节长度
	ld := uint64(len(data))

	// 右填充0x00到块大小的整数倍
	dataLen := len(data)
	paddingBytes := (blockSize - (dataLen % blockSize)) % blockSize
	paddedData := append(data, bytes.Repeat([]byte{0x00}, paddingBytes)...)

	// 生成块L：将ld的二进制表示左填充到blockSize字节
	lBlock := make([]byte, blockSize)
	ldBytes := big.NewInt(0).SetUint64(ld).Bytes() // 转换为大端字节

	// 若ld的字节表示超过块大小，返回错误
	if len(ldBytes) > blockSize {
		return nil, errors.New("data length exceeds block size capacity")
	}

	// 将ldBytes左填充到blockSize长度
	padStart := blockSize - len(ldBytes)
	copy(lBlock[padStart:], ldBytes)

	// 合并块L和填充后的数据
	return append(lBlock, paddedData...), nil
}
