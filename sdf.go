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

RV plugin_init(char *path)
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
		return SDR_OPENDEVICE;
	}

	//查找符号
	for (i = 0; i < (sizeof(gs_func_name_arr) / sizeof(struct func_name_pair)); i++)
	{
		sym = (long *)dlsym(gs_lib_handle, gs_func_name_arr[i].name);
		if (sym == NULL)
		{
			goto error;
		}

		*gs_func_name_arr[i].func = sym;
	}

	//打开设备
	if (!OpenDevice(&gs_sdf_device))
	{
		return SDR_OK;
	}

error:
	dlclose(gs_lib_handle);
	return SDR_NOTSUPPORT;
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
	"unsafe"
)

// Init:模块初始化,打开device、so库,查找符号表
func Init(libPath string) RV {
	return RV(C.plugin_init(C.CString(libPath)))
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

// HashInit: HASH初始化
func HashInit(session HANDLE, alg ALGID, pubKey *ECCrefPublicKey, id []byte) RV {
	return RV(C.hash_init((*C.long)(unsafe.Pointer(session)),
		C.unsigned(alg), (*C.ECCrefPublicKey)(unsafe.Pointer(pubKey)),
		(*C.uchar)(unsafe.Pointer(&id[0])), C.unsigned(len(id))))
}

// HashUpdate:hash update
func HashUpdate(session HANDLE, buf []byte) RV {
	return RV(C.hash_update((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&buf[0])), C.unsigned(len(buf))))
}

// HashFinal:hash final
func HashFinal(session HANDLE) ([]byte, RV) {
	var len C.unsigned = 64
	hash := make([]byte, 64)

	ret := C.hash_final((*C.long)(unsafe.Pointer(session)),
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.unsigned)(unsafe.Pointer(&len)))

	return hash[:len], RV(ret)
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

// GenerateKeyWithKEK: 生成会话密钥并导出,算法选用ECB模式,密钥会用PKCS7填充
func GenerateKeyWithKEK(session HANDLE, kekIndex uint32, alg ALGID, keyBits uint32) ([]byte, HANDLE, RV) {
	buf := make([]byte, 256)
	var keyLen C.unsigned
	var keyHandle HANDLE

	ret := C.gen_key_with_kek((*C.long)(unsafe.Pointer(session)),
		C.unsigned(keyBits), C.unsigned(alg), C.unsigned(kekIndex),
		(*C.uchar)(unsafe.Pointer(&buf[0])), (*C.unsigned)(unsafe.Pointer(&keyLen)),
		(**C.long)(unsafe.Pointer(&keyHandle)))
	if ret != 0 {
		return nil, nil, RV(ret)
	}

	keyBuf := make([]byte, keyLen)
	copy(keyBuf, buf[:keyLen])
	return keyBuf, keyHandle, RV(ret)
}

// ImportKeyWithKEK: 导入并解密会话密钥,算法选用ECB模式
func ImportKeyWithKEK(session HANDLE, kekIndex uint32, alg ALGID, key []byte) (HANDLE, RV) {
	var keyHandle HANDLE

	ret := C.import_key_with_kek((*C.long)(unsafe.Pointer(session)),
		C.unsigned(alg), C.unsigned(kekIndex), (*C.uchar)(unsafe.Pointer(&key[0])),
		C.unsigned(len(key)), (**C.long)(unsafe.Pointer(&keyHandle)))

	return keyHandle, RV(ret)
}

// DestroyKey:销毁会话密钥,释放密钥句柄
func DestroyKey(session, keyHandle HANDLE) RV {
	return RV(C.destroy_key((*C.long)(unsafe.Pointer(keyHandle)),
		(*C.long)(unsafe.Pointer(keyHandle))))
}

// 以下几个签名、验签函数,须传入经过预处理后的HASH值,不能直接传递消息原文
// ExternalVerifyECC:ECC外部签名公钥验签
func ExternalVerifyECC(session HANDLE, pubKey ECCrefPublicKey, hash []byte, sig ECCSignature) RV {
	return RV(C.external_verify_ecc((*C.long)(unsafe.Pointer(session)),
		C.unsigned(C.SGD_SM2_1),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)),
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		C.unsigned(len(hash)), (*C.ECCSignature)(unsafe.Pointer(&sig))))
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

// Encrypt: 根据指定算法加密,不对数据进行填充
func Encrypt(session, key HANDLE, alg ALGID, iv []byte, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := RV(C.encrypt((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(alg),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen))))
	return outBuf, ret
}

// Decrypt: 根据指定算法解密
func Decrypt(session, key HANDLE, alg ALGID, iv []byte, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := RV(C.decrypt((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(alg),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen))))
	return outBuf, ret
}

// CalculateMAC:CBC-MAC,此函数为单包计算,若要多包计算,使用IV进行控制
// CBC-MAC在长度不固定时有长度扩展攻击问题
func CalculateMAC(session, key HANDLE, alg ALGID, iv []byte, data []byte) ([]byte, RV) {
	outBuf := make([]byte, Sm4BlockSize) // SM4 CBC-MAC固定16字节
	var outLen C.unsigned = 0

	ret := C.cbc_mac((*C.long)(unsafe.Pointer(session)),
		(*C.long)(unsafe.Pointer(key)), C.unsigned(alg),
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
	if ret != SDR_OK {
		return nil, ret
	}
	defer CloseSession(session)

	buf := make([]byte, len)
	ret = RV(C.gen_random((*C.long)(unsafe.Pointer(session)),
		C.unsigned(len), (*C.uchar)(unsafe.Pointer(&buf[0]))))
	return buf, ret
}
