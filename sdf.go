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

//杂凑运算
RV (*HashInit)(HANDLE, UINT32, ECCrefPublicKey *, unsigned char *, UINT32);
RV (*HashUpdate)(HANDLE, unsigned char *, UINT32);
RV (*HashFinal)(HANDLE, unsigned char *, UINT32 *);

//HMAC运算函数:该实现为三未信安提供,跟0018-2023不一致
RV (*HMACInit)(HANDLE, UINT32, UINT32, UCHAR*, UINT32);
RV (*HMACUpdate)(HANDLE, UCHAR*, UINT32);
RV (*HMACFinal)(HANDLE, UCHAR*, UINT32*);

//密钥管理
RV (*ExportSignPublicKeyECC)(HANDLE, UINT32, ECCrefPublicKey *);
RV (*ExportEncPublicKeyECC)(HANDLE, UINT32, ECCrefPublicKey *);
RV (*GenerateKeyPairECC)(HANDLE, UINT32, UINT32, ECCrefPublicKey *,ECCrefPrivateKey *);
RV (*GenerateKeyWithIPKECC)(HANDLE, UINT32, UINT32, ECCCipher *, HANDLE*);
RV (*GenerateKeyWithEPKECC)(HANDLE, UINT32, UINT32, ECCrefPublicKey *, ECCCipher *, HANDLE*);
RV (*ImportKeyWithISKECC)(HANDLE, UINT32, ECCCipher *, HANDLE*);
RV (*GenerateAgreementDataWithECC)(HANDLE, UINT32, UINT32, unsigned char *, UINT32, ECCrefPublicKey *, ECCrefPublicKey *, HANDLE*);
RV (*GenerateKeyWithECC)(HANDLE, unsigned char *, UINT32, ECCrefPublicKey *, ECCrefPublicKey *, HANDLE, HANDLE*);
RV (*GenerateAgreementDataAndKeyWithECC)(HANDLE, UINT32, UINT32, unsigned char *, UINT32, unsigned char *, UINT32, ECCrefPublicKey *, ECCrefPublicKey *, ECCrefPublicKey *, ECCrefPublicKey *, HANDLE, HANDLE*);
RV (*ExchangeDigitEnvelopeBaseOnECC)(HANDLE, UINT32, UINT32, ECCrefPublicKey *, ECCCipher *, ECCCipher *);
RV (*GenerateKeyWithKEK)(HANDLE, UINT32, UINT32 , UINT32, unsigned char *, UINT32 *, HANDLE*);
RV (*ImportKeyWithKEK)(HANDLE, UINT32, UINT32, unsigned char *, UINT32, HANDLE*);
RV (*DestroyKey)(HANDLE, HANDLE);

//非对称运算
RV (*ExternalVerifyECC)(HANDLE, UINT32, ECCrefPublicKey *, unsigned char *, UINT32, ECCSignature *);
RV (*InternalSignECC)(HANDLE, UINT32, unsigned char *, UINT32, ECCSignature *);
RV (*InternalVerifyECC)(HANDLE, UINT32, unsigned char *, UINT32, ECCSignature *);
RV (*ExternalEncryptECC)(HANDLE, UINT32, ECCrefPublicKey *,unsigned char *, UINT32, ECCCipher *);
RV (*ExternalDecryptECC)(HANDLE, UINT32, ECCrefPrivateKey *, ECCCipher *, unsigned char *, UINT32 *);
RV (*InternalEncryptECC)(HANDLE, UINT32, unsigned char *, UINT32, ECCCipher *);
RV (*InternalDecryptECC)(HANDLE, UINT32, ECCCipher *, unsigned char *, UINT32 *);

//对称运算
RV (*Encrypt)(HANDLE, HANDLE, UINT32, unsigned char *, unsigned char *, UINT32, unsigned char *, UINT32 *);
RV (*Decrypt)(HANDLE, HANDLE, UINT32, unsigned char *, unsigned char *, UINT32, unsigned char *, UINT32 *);
RV (*CalculateMAC)(HANDLE, HANDLE, UINT32, unsigned char *, unsigned char *, UINT32, unsigned char *, UINT32 *);

//文件管理
RV (*CreateFile)(HANDLE, unsigned char *, UINT32, UINT32);
RV (*ReadFile)(HANDLE, unsigned char *, UINT32, UINT32, UINT32 *, unsigned char *);
RV (*WriteFile)(HANDLE, unsigned char *, UINT32, UINT32, UINT32, unsigned char *);
RV (*DeleteFile)(HANDLE, unsigned char *, UINT32);

// 随机数
RV (*GenerateRandom)(HANDLE, UINT32, unsigned char *);

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

#ifdef SW_GM0018_2012
		{"SDF_HMAC_Init", (long **)&HMACInit},
		{"SDF_HMAC_Update", (long **)&HMACUpdate},
		{"SDF_HMAC_Final", (long **)&HMACFinal},
#endif

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

long open_session(RV *ret)
{
	HANDLE session = NULL;

	*ret = OpenSession(gs_sdf_device, &session);
	return (long)session;
}

RV close_session(long session)
{
	return CloseSession((HANDLE)session);
}

RV hash_init(long session, UINT32 alg, ECCrefPublicKey *pub, BYTE *id, UINT32 id_len)
{
	return HashInit((HANDLE)session, alg, pub, id, id_len);
}

RV hash_update(long session, unsigned char *buf, UINT32 buf_len)
{
	return HashUpdate((HANDLE)session, buf, buf_len);
}

RV hash_final(long session, unsigned char *hash, UINT32 *hash_len)
{
	return HashFinal((HANDLE)session, hash, hash_len);
}

RV hmac_init(long session, UINT32 alg, UINT32 kek, UCHAR* pucKey, UINT32 key_len)
{
	return HMACInit((HANDLE)session, alg, kek, pucKey, key_len);
}

RV hmac_update(long session, UCHAR* data, UINT32 data_len)
{
	return HMACUpdate((HANDLE)session, data, data_len);
}

RV hmac_final(long session, UCHAR* mac, UINT32* mac_len)
{
	return HMACFinal((HANDLE)session, mac, mac_len);
}

RV external_verify_ecc(long session, UINT32 alg, ECCrefPublicKey *key, unsigned char *buf, UINT32 buf_len, ECCSignature *sig)
{
	return ExternalVerifyECC((HANDLE)session, alg, key, buf, buf_len, sig);
}

long gen_key_with_kek(long session, UINT32 key_bits, UINT32 alg_id, UINT32 kek_index, BYTE *key_buf, UINT32 *key_len, RV *ret)
{
	HANDLE key_handle = NULL;

	*ret = GenerateKeyWithKEK((HANDLE)session, key_bits, alg_id, kek_index, key_buf, key_len, &key_handle);
	return (long)key_handle;
}

RV import_key_with_kek(long session, UINT32 alg_id, UINT32 kek_index, BYTE *key_buf, UINT32 key_len, RV *ret)
{
	HANDLE key_handle = NULL;

	*ret = ImportKeyWithKEK((HANDLE)session, alg_id, kek_index, key_buf, key_len, &key_handle);
	return (long)key_handle;
}

RV destroy_key(long session, long key)
{
	return DestroyKey((HANDLE)session, (HANDLE)key);
}

RV encrypt(long session, long key, UINT32 alg, BYTE *iv, BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	return Encrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV decrypt(long session, long key, UINT32 alg, BYTE *iv, BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	return Decrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV cbc_mac(long session, long key, UINT32 alg, BYTE *iv, BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	return CalculateMAC((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV create_file(long session, unsigned char *name, UINT32 name_len, UINT32 size)
{
	return CreateFile((HANDLE)session, name, name_len, size);
}

RV read_file(long session, unsigned char *name, UINT32 name_len, UINT32 offset, UINT32 *file_len, unsigned char *buf)
{
	return ReadFile((HANDLE)session, name, name_len, offset, file_len, buf);
}

RV write_file(long session, unsigned char *name, UINT32 name_len, UINT32 offset, UINT32 file_len, unsigned char *buf)
{
	return WriteFile((HANDLE)session, name, name_len, offset, file_len, buf);
}

RV delete_file(long session, unsigned char *name, UINT32 name_len)
{
	return DeleteFile((HANDLE)session, name, name_len);
}

RV gen_random(long session, UINT32 len, unsigned char *buf)
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
func OpenSession() (int, RV) {
	var ret C.unsigned
	session := C.open_session((*C.unsigned)(unsafe.Pointer(&ret)))
	return int(session), RV(ret)
}

// CloseSession:关闭会话
func CloseSession(session int) RV {
	return RV(C.close_session(C.long(session)))
}

// Sm3Init:sm3 init，传入打开的会话
func Sm3Init(session int) RV {
	return RV(C.hash_init(C.long(session), C.unsigned(C.SGD_SM3), nil, nil, 0))
}

// Sm3InitWithPubKey:sm3 init，传入打开的会话,公钥进行预处理，用于签名验签
func Sm3InitWithPubKey(session int, pubKey ECCrefPublicKey, id []byte) RV {
	return RV(C.hash_init(C.long(session), C.unsigned(C.SGD_SM3),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)),
		(*C.uchar)(unsafe.Pointer(&id[0])), C.unsigned(len(id))))
}

// Sm3Update:sm3 update
func Sm3Update(session int, buf []byte) RV {
	return RV(C.hash_update(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(buf))))
}

// SdfSm3Update:sm3 final，返回32字节的hash数组
func Sm3Final(session int) ([]byte, RV) {
	var len C.unsigned = 32 // sm3 hash长度固定32字节
	hash := make([]byte, 32)

	ret := C.hash_final(C.long(session), (*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.unsigned)(unsafe.Pointer(&len)))

	return hash, RV(ret)
}

// Sm3HMACInit:hmac-sm3,此处暂时匹配sw卡,跟2023标准暂不一致
func Sm3HMACInit(session int, kekIndex uint32, key []byte) RV {
	return RV(C.hmac_init(C.long(session), C.unsigned(C.SGD_SM3),
		C.unsigned(kekIndex),
		(*C.uchar)(unsafe.Pointer(&key[0])), C.unsigned(len(key))))
}

// Sm3HMACUpdate:hmac-sm3 update
func Sm3HMACUpdate(session int, data []byte) RV {
	return RV(C.hmac_update(C.long(session),
		(*C.uchar)(unsafe.Pointer(&data[0])), C.unsigned(len(data))))
}

// Sm3HMACFinal:hmac-sm3 final,返回32字节的hash数组
func Sm3HMACFinal(session int) ([]byte, RV) {
	var len C.unsigned = 32 // sm3 hash长度固定32字节
	hash := make([]byte, 32)

	ret := C.hmac_final(C.long(session), (*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.unsigned)(unsafe.Pointer(&len)))

	return hash, RV(ret)
}

// GenerateKeyWithKEK: 生成会话密钥并导出,密钥会用PKCS7填充
func GenerateKeyWithKEK(session int, kekIndex uint32, keyBits uint32) ([]byte, int, RV) {
	buf := make([]byte, 256)
	var keyLen C.unsigned
	var ret C.unsigned

	handle := C.gen_key_with_kek(C.long(session), C.unsigned(keyBits),
		C.unsigned(C.SGD_SMS4_ECB), C.unsigned(kekIndex),
		(*C.uchar)(unsafe.Pointer(&buf[0])), (*C.unsigned)(unsafe.Pointer(&keyLen)),
		(*C.unsigned)(unsafe.Pointer(&ret)))
	if ret != 0 {
		return nil, 0, RV(ret)
	}

	keyBuf := make([]byte, keyLen)
	copy(keyBuf, buf[:keyLen])
	return keyBuf, int(handle), RV(ret)
}

// ImportKeyWithKEK: 导入并解密会话密钥
func ImportKeyWithKEK(session int, kekIndex uint32, key []byte) (int, RV) {
	var ret C.unsigned

	handle := C.import_key_with_kek(C.long(session), C.unsigned(C.SGD_SMS4_ECB),
		C.unsigned(kekIndex), (*C.uchar)(unsafe.Pointer(&key[0])),
		C.unsigned(len(key)), (*C.unsigned)(unsafe.Pointer(&ret)))

	return int(handle), RV(ret)
}

// DestroyKey:销毁会话密钥,释放密钥句柄
func DestroyKey(session, keyHandle int) RV {
	return RV(C.destroy_key(C.long(session), C.long(keyHandle)))
}

// SM4EncryptECB:sm4加密，ECB模式，调用者须填充
func SM4EncryptECB(session, keyHandle int, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	iv := make([]byte, 16)
	var outLen C.unsigned = 0

	ret := C.encrypt(C.long(session), C.long(keyHandle), C.unsigned(C.SGD_SMS4_ECB),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, RV(ret)
}

// SM4EncryptCBC:sm4加密，CBC模式，调用者须填充
func SM4EncryptCBC(session, keyHandle int, iv, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := C.encrypt(C.long(session), C.long(keyHandle), C.unsigned(C.SGD_SMS4_CBC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, RV(ret)
}

// SM4DecryptECB:sm4解密，ECB模式
func SM4DecryptECB(session, keyHandle int, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	iv := make([]byte, 16)
	var outLen C.unsigned = 0

	ret := C.decrypt(C.long(session), C.long(keyHandle), C.unsigned(C.SGD_SMS4_ECB),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))
	return outBuf, RV(ret)
}

// SM4DecryptCBC:sm4解密，CBC模式
func SM4DecryptCBC(session, keyHandle int, iv, data []byte) ([]byte, RV) {
	outBuf := make([]byte, len(data))
	var outLen C.unsigned = 0

	ret := C.decrypt(C.long(session), C.long(keyHandle), C.unsigned(C.SGD_SMS4_CBC),
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
func SM4CalculateCBCMAC(session, keyHandle int, iv []byte, data []byte) ([]byte, RV) {
	outBuf := make([]byte, 16) // SM4 CBC-MAC固定16字节
	var outLen C.unsigned = 0

	ret := C.cbc_mac(C.long(session), C.long(keyHandle), C.unsigned(C.SGD_SMS4_MAC),
		(*C.uchar)(unsafe.Pointer(&iv[0])), (*C.uchar)(unsafe.Pointer(&data[0])),
		C.unsigned(len(data)), (*C.uchar)(unsafe.Pointer(&outBuf[0])),
		(*C.unsigned)(unsafe.Pointer(&outLen)))

	return outBuf, RV(ret)
}

// Sm2ExtKeyVerify:sm2外部key验签
func Sm2ExtKeyVerify(session int, pubKey ECCrefPublicKey, buf []byte, sig ECCSignature) RV {
	return RV(C.external_verify_ecc(C.long(session), C.unsigned(C.SGD_SM2_1),
		(*C.ECCrefPublicKey)(unsafe.Pointer(&pubKey)), (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(buf)), (*C.ECCSignature)(unsafe.Pointer(&sig))))
}

// CreateFile:卡中创建文件
func CreateFile(session int, fileName string, fileSize uint32) RV {
	buf := make([]byte, len(fileName))
	return RV(C.create_file(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])),
		C.unsigned(len(fileName)), C.unsigned(fileSize)))
}

// ReadFile:读取卡中文件,从offset开始读取readLen字节
func ReadFile(session int, fileName string, offSet, readLen uint32) ([]byte, RV) {
	fileBytes := make([]byte, len(fileName))
	buf := make([]byte, readLen) //读取文件buf

	ret := C.read_file(C.long(session), (*C.uchar)(unsafe.Pointer(&fileBytes[0])),
		C.unsigned(len(fileName)), C.unsigned(offSet),
		(*C.unsigned)(unsafe.Pointer(&readLen)),
		(*C.uchar)(unsafe.Pointer(&buf[0])))

	return buf, RV(ret)
}

// WriteFile:文件写入内容,从offset开始写入readLen字节
func WriteFile(session int, fileName string, offSet uint32, buf []byte) RV {
	fileBytes := make([]byte, len(fileName))
	return RV(C.write_file(C.long(session), (*C.uchar)(unsafe.Pointer(&fileBytes[0])),
		C.unsigned(len(fileName)), C.unsigned(offSet), C.unsigned(len(buf)),
		(*C.uchar)(unsafe.Pointer(&buf[0]))))
}

// DeleteFile:删除卡中文件
func DeleteFile(session int, fileName string) RV {
	buf := make([]byte, len(fileName))
	return RV(C.delete_file(C.long(session), (*C.uchar)(unsafe.Pointer(&buf[0])),
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
	ret = RV(C.gen_random(C.long(session), C.unsigned(len), (*C.uchar)(unsafe.Pointer(&buf[0]))))
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
