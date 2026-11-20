/* gosdf 测试桩设备:实现 sdf_shim 绑定的设备管理/密钥管理/非对称/对称/文件符号。
 * 默认不含 AEAD 多步符号;定义 GOSDF_STUB_STREAM_AEAD 时补 6 个流式
 * SDF_AuthEncInit/Update/Final 与 SDF_AuthDecInit/Update/Final。
 *
 * 行为(全部确定性,便于断言):
 *   - 对称加解密 = 逐字节 XOR 0x5A(自逆,往返可逆);流式 AEAD 同此变换
 *   - 杂凑/HMAC/MAC = FNV-1a 累加派生的定长输出
 *   - 会话句柄从 0x2001 递增,密钥句柄从 0x4001 递增(两者不同值)
 *   - SDF_GetPrivateKeyAccessRight(keyIndex==7) 返回 SDR_KEYNOTEXIST
 *   - DestroyKey、HMACInit 与文件操作的参数按行写入 $SDF_STUB_RECORD 指定的文件
 *   - 导出的 ECC 公钥为 sm2p256v1 生成元(通过曲线校验)
 *
 * 编译:cc -shared -fPIC -I. -o libsdf_stub.so testdata/sdf_stub.c
 * 缺符号变体:cc -shared -fPIC -I. -DGOSDF_STUB_OMIT_HMAC -o libsdf_stub_nohmac.so testdata/sdf_stub.c
 * 流式 AEAD 变体:cc -shared -fPIC -I. -DGOSDF_STUB_STREAM_AEAD -o libsdf_stub_aead.so testdata/sdf_stub.c
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdf.h"

/* ---------- 参数记录 ---------- */

static void record_line(const char *line)
{
	const char *path = getenv("SDF_STUB_RECORD");
	FILE *f;

	if (path == NULL || path[0] == '\0')
		return;
	f = fopen(path, "a");
	if (f == NULL)
		return;
	fputs(line, f);
	fputc('\n', f);
	fclose(f);
}

static void record_file(const char *op, const unsigned char *name, unsigned int len)
{
	char buf[320];
	unsigned int n = len < 160 ? len : 160;

	snprintf(buf, sizeof(buf), "file:%s:%.*s", op, (int)n, (const char *)name);
	record_line(buf);
}

static void record_destroy(void *session, void *key)
{
	char buf[96];

	snprintf(buf, sizeof(buf), "destroy:%lx:%lx",
		(unsigned long)(uintptr_t)session, (unsigned long)(uintptr_t)key);
	record_line(buf);
}

static void record_hmac_init(long *key, UINT32 alg)
{
	char buf[96];

	snprintf(buf, sizeof(buf), "hmacinit:%lx:%x",
		(unsigned long)(uintptr_t)key, (unsigned int)alg);
	record_line(buf);
}

/* ---------- 全局状态 ---------- */

static unsigned long g_session_seq = 0x2000;
static unsigned long g_key_seq = 0x4000;

static unsigned int g_hash_acc;
static int g_hash_active;

static unsigned int g_hmac_acc;
static int g_hmac_active;

static unsigned int g_mac_acc;

#define STUB_FILE_MAX 4096
static unsigned char g_file_data[STUB_FILE_MAX];
static unsigned int g_file_len;

/* sm2p256v1 生成元(与 gmsm 一致),使桩导出的公钥通过 IsOnCurve 校验 */
static const unsigned char k_sm2_gx[32] = {
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
	0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
	0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
	0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
};
static const unsigned char k_sm2_gy[32] = {
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
	0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
	0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
	0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
};

static void fill_pub(ECCrefPublicKey *pub)
{
	memset(pub, 0, sizeof(*pub));
	pub->bits = 256;
	memcpy(pub->x + 32, k_sm2_gx, 32);
	memcpy(pub->y + 32, k_sm2_gy, 32);
}

static unsigned int fnv1a(unsigned int acc, const unsigned char *data, UINT32 len)
{
	UINT32 i;

	for (i = 0; i < len; i++) {
		acc ^= data[i];
		acc *= 16777619u;
	}
	return acc;
}

static void fill_digest(unsigned int acc, unsigned char *out, UINT32 n)
{
	UINT32 i;

	for (i = 0; i < n; i++)
		out[i] = (unsigned char)((acc >> ((i % 4) * 8)) ^ (i * 0x9Eu));
}

/* ---------- 设备管理 ---------- */

RV SDF_OpenDevice(HANDLE *phDeviceHandle)
{
	if (phDeviceHandle == NULL)
		return SDR_OUTARGERR;
	*phDeviceHandle = (HANDLE)0x1001;
	return SDR_OK;
}

RV SDF_CloseDevice(HANDLE hDeviceHandle)
{
	(void)hDeviceHandle;
	return SDR_OK;
}

RV SDF_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle)
{
	(void)hDeviceHandle;
	if (phSessionHandle == NULL)
		return SDR_OPENSESSION;
	*phSessionHandle = (HANDLE)(++g_session_seq);
	return SDR_OK;
}

RV SDF_CloseSession(HANDLE hSessionHandle)
{
	(void)hSessionHandle;
	return SDR_OK;
}

RV SDF_GetDeviceInfo(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo)
{
	(void)hSessionHandle;
	if (pstDeviceInfo == NULL)
		return SDR_OUTARGERR;
	memset(pstDeviceInfo, 0, sizeof(*pstDeviceInfo));
	memcpy(pstDeviceInfo->IssuerName, "stub-issuer", 11);
	memcpy(pstDeviceInfo->DeviceName, "stub-dev", 8);
	memcpy(pstDeviceInfo->DeviceSerial, "0001", 4);
	pstDeviceInfo->DeviceVersion = 0x0100;
	pstDeviceInfo->StandardVersion = 0x0200;
	pstDeviceInfo->BufferSize = 65536;
	return SDR_OK;
}

RV SDF_GenerateRandom(HANDLE hSessionHandle, UINT32 uiLength, UCHAR *pucRandom)
{
	static UINT32 seq = 0;
	UINT32 i;

	(void)hSessionHandle;
	if (uiLength > 0 && pucRandom == NULL)
		return SDR_OUTARGERR;
	for (i = 0; i < uiLength; i++)
		pucRandom[i] = (UCHAR)((seq + i) & 0xFF);
	seq += uiLength;
	return SDR_OK;
}

RV SDF_GetPrivateKeyAccessRight(HANDLE hSessionHandle, UINT32 uiKeyIndex,
	UCHAR *pucPassword, UINT32 uiPwdLength)
{
	(void)hSessionHandle;
	(void)pucPassword;
	(void)uiPwdLength;
	if (uiKeyIndex == 7) /* 测试 TestErrorsIs */
		return SDR_KEYNOTEXIST;
	return SDR_OK;
}

RV SDF_ReleasePrivateKeyAccessRight(HANDLE hSessionHandle, UINT32 uiKeyIndex)
{
	(void)hSessionHandle;
	(void)uiKeyIndex;
	return SDR_OK;
}

/* ---------- 杂凑运算 ---------- */

RV SDF_HashInit(HANDLE hSessionHandle, UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey,
	UCHAR *pucID, UINT32 uiIDLength)
{
	(void)hSessionHandle;
	(void)uiAlgID;
	(void)pucPublicKey;
	(void)pucID;
	(void)uiIDLength;
	g_hash_acc = 2166136261u;
	g_hash_active = 1;
	return SDR_OK;
}

RV SDF_HashUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength)
{
	(void)hSessionHandle;
	if (!g_hash_active)
		return SDR_STEPERR;
	g_hash_acc = fnv1a(g_hash_acc, pucData, uiDataLength);
	return SDR_OK;
}

RV SDF_HashFinal(HANDLE hSessionHandle, UCHAR *pucHash, UINT32 *puiHashLength)
{
	(void)hSessionHandle;
	if (!g_hash_active || pucHash == NULL || puiHashLength == NULL || *puiHashLength < 32)
		return SDR_STEPERR;
	fill_digest(g_hash_acc, pucHash, 32);
	*puiHashLength = 32;
	g_hash_active = 0;
	return SDR_OK;
}

#ifndef GOSDF_STUB_OMIT_HMAC
/* ---------- 带密钥的杂凑(GM/T 0018-2023 6.6.2~6.6.4) ---------- */

RV SDF_HMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID)
{
	(void)hSessionHandle;
	if (hKeyHandle == NULL)
		return SDR_INARGERR;
	record_hmac_init((long *)hKeyHandle, uiAlgID);
	/* 密钥句柄字节充当密钥材料(确定性即可) */
	g_hmac_acc = fnv1a(2166136261u,
		(const unsigned char *)&hKeyHandle, (UINT32)sizeof(hKeyHandle));
	g_hmac_active = 1;
	return SDR_OK;
}

RV SDF_HMACUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength)
{
	(void)hSessionHandle;
	if (!g_hmac_active)
		return SDR_STEPERR;
	g_hmac_acc = fnv1a(g_hmac_acc, pucData, uiDataLength);
	return SDR_OK;
}

RV SDF_HMACFinal(HANDLE hSessionHandle, UCHAR *pucMAC, UINT32 *puiMACLength)
{
	(void)hSessionHandle;
	if (!g_hmac_active || pucMAC == NULL || puiMACLength == NULL || *puiMACLength < 32)
		return SDR_STEPERR;
	fill_digest(g_hmac_acc, pucMAC, 32);
	*puiMACLength = 32;
	g_hmac_active = 0;
	return SDR_OK;
}
#endif /* GOSDF_STUB_OMIT_HMAC */

/* ---------- 密钥管理 ---------- */

RV SDF_ExportSignPublicKey_ECC(HANDLE hSessionHandle, UINT32 uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	(void)hSessionHandle;
	(void)uiKeyIndex;
	if (pucPublicKey == NULL)
		return SDR_OUTARGERR;
	fill_pub(pucPublicKey);
	return SDR_OK;
}

RV SDF_ExportEncPublicKey_ECC(HANDLE hSessionHandle, UINT32 uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	(void)hSessionHandle;
	(void)uiKeyIndex;
	if (pucPublicKey == NULL)
		return SDR_OUTARGERR;
	fill_pub(pucPublicKey);
	return SDR_OK;
}

/* RSA 公钥导出:bits=2048,m 由 tag(密钥索引)确定性派生;e 固定 65537,
 * 保证经 crypto/rsa 语义校验的结构合法性(仅测试用,非真实参数) */
static void fill_rsa_pub(RSArefPublicKey *pub, UINT32 tag)
{
	UINT32 i;

	memset(pub, 0, sizeof(*pub));
	pub->bits = 2048;
	for (i = 0; i < RSAref_MAX_LEN; i++)
		pub->m[i] = (UCHAR)((tag * 131u + i * 3u + 7u) & 0xFF);
	pub->e[RSAref_MAX_LEN - 3] = 0x01;
	pub->e[RSAref_MAX_LEN - 1] = 0x01;
}

RV SDF_ExportSignPublicKey_RSA(HANDLE hSessionHandle, UINT32 uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	(void)hSessionHandle;
	if (pucPublicKey == NULL)
		return SDR_OUTARGERR;
	fill_rsa_pub(pucPublicKey, uiKeyIndex);
	return SDR_OK;
}

RV SDF_ExportEncPublicKey_RSA(HANDLE hSessionHandle, UINT32 uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	(void)hSessionHandle;
	if (pucPublicKey == NULL)
		return SDR_OUTARGERR;
	fill_rsa_pub(pucPublicKey, uiKeyIndex);
	return SDR_OK;
}

/* RSA 密钥对:公私钥字段由 keyBits 确定性派生,e 固定 65537;
 * 模数/私指数仅填低 keyBits/8 字节,保证位宽 ≤ keyBits(仅测试用,非真实参数) */
static void fill_rsa_keypair(RSArefPublicKey *pub, RSArefPrivateKey *priv, UINT32 key_bits)
{
	UINT32 i, w;
	UCHAR v;

	memset(pub, 0, sizeof(*pub));
	memset(priv, 0, sizeof(*priv));
	pub->bits = key_bits;
	priv->bits = key_bits;
	w = key_bits / 8;
	for (i = 0; i < w; i++) {
		v = (UCHAR)((key_bits * 131u + i * 3u + 7u) & 0xFF);
		pub->m[RSAref_MAX_LEN - w + i] = v;
		priv->m[RSAref_MAX_LEN - w + i] = v;
		priv->d[RSAref_MAX_LEN - w + i] = (UCHAR)(v ^ 0xA5);
	}
	pub->e[RSAref_MAX_LEN - 3] = 0x01;
	pub->e[RSAref_MAX_LEN - 1] = 0x01;
	priv->e[RSAref_MAX_LEN - 3] = 0x01;
	priv->e[RSAref_MAX_LEN - 1] = 0x01;
	for (i = 0; i < RSAref_MAX_PLEN; i++) {
		priv->prime[0][i] = (UCHAR)((key_bits + i * 5u + 0x11u) & 0xFF);
		priv->prime[1][i] = (UCHAR)((key_bits + i * 9u + 0x23u) & 0xFF);
		priv->pexp[0][i] = (UCHAR)((key_bits + i * 3u + 0x35u) & 0xFF);
		priv->pexp[1][i] = (UCHAR)((key_bits + i * 7u + 0x47u) & 0xFF);
		priv->coef[i] = (UCHAR)((key_bits + i * 11u + 0x59u) & 0xFF);
	}
}

RV SDF_GenerateKeyPair_RSA(HANDLE hSessionHandle, UINT32 uiKeyBits,
	RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey)
{
	(void)hSessionHandle;
	if (pucPublicKey == NULL || pucPrivateKey == NULL)
		return SDR_OUTARGERR;
	if (uiKeyBits == 0 || uiKeyBits > RSAref_MAX_BITS || uiKeyBits % 8 != 0)
		return SDR_KEYERR;
	fill_rsa_keypair(pucPublicKey, pucPrivateKey, uiKeyBits);
	return SDR_OK;
}

RV SDF_GenerateKeyPair_ECC(HANDLE hSessionHandle, UINT32 uiAlgID, UINT32 uiKeyBits,
	ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
	UINT32 i;

	(void)hSessionHandle;
	(void)uiAlgID;
	if (pucPublicKey == NULL || pucPrivateKey == NULL)
		return SDR_OUTARGERR;
	fill_pub(pucPublicKey);
	memset(pucPrivateKey, 0, sizeof(*pucPrivateKey));
	pucPrivateKey->bits = uiKeyBits == 0 ? 256 : uiKeyBits;
	/* 确定性私钥,布局与公钥 x/y 一致:高 32 字节留零,数据置于低 32 字节 */
	for (i = 0; i < 32; i++)
		pucPrivateKey->K[32 + i] = (UCHAR)((i * 7u + 1u) & 0xFF);
	return SDR_OK;
}

/* ECCCipher 输出填充:X/Y = 生成元,M = 0xA5,C = 16 字节 0x5A */
static void fill_cipher(ECCCipher *cipher, const UCHAR *data, UINT32 len)
{
	memset(cipher->x, 0, sizeof(cipher->x));
	memset(cipher->y, 0, sizeof(cipher->y));
	memcpy(cipher->x + 32, k_sm2_gx, 32);
	memcpy(cipher->y + 32, k_sm2_gy, 32);
	memset(cipher->M, 0xA5, sizeof(cipher->M));
	cipher->L = len;
	if (len > 0)
		memcpy(cipher->C, data, len);
}

RV SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, UINT32 uiIPKIndex, UINT32 uiKeyBits,
	ECCCipher *pucKey, HANDLE *phKeyHandle)
{
	unsigned char tag[16];

	(void)hSessionHandle;
	(void)uiIPKIndex;
	(void)uiKeyBits;
	if (pucKey == NULL || phKeyHandle == NULL)
		return SDR_OUTARGERR;
	memset(tag, 0x5A, sizeof(tag));
	fill_cipher(pucKey, tag, sizeof(tag));
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

RV SDF_GenerateKeyWithEPK_ECC(HANDLE hSessionHandle, UINT32 uiKeyBits, UINT32 uiAlgID,
	ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, HANDLE *phKeyHandle)
{
	unsigned char tag[16];

	(void)hSessionHandle;
	(void)uiKeyBits;
	(void)uiAlgID;
	(void)pucPublicKey;
	if (pucKey == NULL || phKeyHandle == NULL)
		return SDR_OUTARGERR;
	memset(tag, 0x5A, sizeof(tag));
	fill_cipher(pucKey, tag, sizeof(tag));
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

RV SDF_ImportKeyWithISK_ECC(HANDLE hSessionHandle, UINT32 uiISKIndex, ECCCipher *pucKey,
	HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)uiISKIndex;
	(void)pucKey;
	if (phKeyHandle == NULL)
		return SDR_OUTARGERR;
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

/* RSA 族包装密钥:16 字节确定性 blob(同 ECC 变体的 0x5A 标签)+ 新密钥句柄 */
#define STUB_RSA_WRAP_LEN 16

static RV stub_rsa_wrap(UCHAR *pucKey, UINT32 *puiKeyLength, HANDLE *phKeyHandle)
{
	if (pucKey == NULL || puiKeyLength == NULL || phKeyHandle == NULL)
		return SDR_OUTARGERR;
	if (*puiKeyLength < STUB_RSA_WRAP_LEN) /* *puiKeyLength 为入参容量 */
		return SDR_KEYERR;
	memset(pucKey, 0x5A, STUB_RSA_WRAP_LEN);
	*puiKeyLength = STUB_RSA_WRAP_LEN;
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

RV SDF_GenerateKeyWithIPK_RSA(HANDLE hSessionHandle, UINT32 uiIPKIndex, UINT32 uiKeyBits,
	UCHAR *pucKey, UINT32 *puiKeyLength, HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)uiIPKIndex;
	(void)uiKeyBits;
	return stub_rsa_wrap(pucKey, puiKeyLength, phKeyHandle);
}

RV SDF_GenerateKeyWithEPK_RSA(HANDLE hSessionHandle, UINT32 uiKeyBits,
	RSArefPublicKey *pucPublicKey, UCHAR *pucKey, UINT32 *puiKeyLength, HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)uiKeyBits;
	if (pucPublicKey == NULL)
		return SDR_OUTARGERR;
	return stub_rsa_wrap(pucKey, puiKeyLength, phKeyHandle);
}

RV SDF_ImportKeyWithISK_RSA(HANDLE hSessionHandle, UINT32 uiISKIndex, UCHAR *pucKey,
	UINT32 uiKeyLength, HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)uiISKIndex;
	(void)pucKey;
	if (phKeyHandle == NULL)
		return SDR_OUTARGERR;
	if (uiKeyLength == 0)
		return SDR_KEYERR;
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

RV SDF_GenerateKeyWithKEK(HANDLE hSessionHandle, UINT32 uiKeyBits, UINT32 uiAlgID,
	UINT32 uiKEKIndex, UCHAR *pucKey, UINT32 *puiKeyLength, HANDLE *phKeyHandle)
{
	UINT32 n, i;

	(void)hSessionHandle;
	(void)uiAlgID;
	(void)uiKEKIndex;
	if (pucKey == NULL || puiKeyLength == NULL || phKeyHandle == NULL)
		return SDR_OUTARGERR;
	n = uiKeyBits / 8;
	if (n == 0 || n > *puiKeyLength) /* *puiKeyLength 为入参容量 */
		return SDR_KEYERR;
	for (i = 0; i < n; i++)
		pucKey[i] = (UCHAR)(i + 1);
	*puiKeyLength = n;
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

RV SDF_ImportKeyWithKEK(HANDLE hSessionHandle, UINT32 uiAlgID, UINT32 uiKEKIndex,
	UCHAR *pucKey, UINT32 uiKeyLength, HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)uiAlgID;
	(void)uiKEKIndex;
	(void)pucKey;
	if (phKeyHandle == NULL)
		return SDR_OUTARGERR;
	if (uiKeyLength == 0)
		return SDR_KEYERR;
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

/* 记录两个句柄,回归旧实现把 key 同时当 session 和 key 传入的缺陷 */
RV SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle)
{
	record_destroy(hSessionHandle, hKeyHandle);
	return SDR_OK;
}

/* 数字信封交换(RSA):逐字节 XOR 0x5A,与对称运算同一确定性变换,可往返断言 */
RV SDF_ExchangeDigitEnvelopeBaseOnRSA(HANDLE hSessionHandle, UINT32 uiKeyIndex,
	RSArefPublicKey *pucPublicKey, UCHAR *pucDEInput, UINT32 uiDELength,
	UCHAR *pucDEOutput, UINT32 *puiDELength)
{
	UINT32 i;

	(void)hSessionHandle;
	(void)uiKeyIndex;
	if (pucPublicKey == NULL || pucDEInput == NULL || uiDELength == 0 ||
		pucDEOutput == NULL || puiDELength == NULL)
		return SDR_OUTARGERR;
	if (*puiDELength < uiDELength) /* *puiDELength 为出参容量 */
		return SDR_NOBUFFER;
	for (i = 0; i < uiDELength; i++)
		pucDEOutput[i] = pucDEInput[i] ^ 0x5A;
	*puiDELength = uiDELength;
	return SDR_OK;
}

/* 数字信封交换(ECC):输出结构同 fill_cipher(生成元 + M=0xA5),L 取输入 L,
 * C 逐字节 XOR 0x5A;调用方按 L 分配输出缓冲 */
RV SDF_ExchangeDigitEnvelopeBaseOnECC(HANDLE hSessionHandle, UINT32 uiKeyIndex,
	UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut)
{
	UINT32 i, n;

	(void)hSessionHandle;
	(void)uiKeyIndex;
	(void)uiAlgID;
	(void)pucPublicKey;
	if (pucEncDataIn == NULL || pucEncDataOut == NULL)
		return SDR_OUTARGERR;
	n = pucEncDataIn->L;
	memset(pucEncDataOut, 0, sizeof(*pucEncDataOut));
	memcpy(pucEncDataOut->x + 32, k_sm2_gx, 32);
	memcpy(pucEncDataOut->y + 32, k_sm2_gy, 32);
	memset(pucEncDataOut->M, 0xA5, sizeof(pucEncDataOut->M));
	pucEncDataOut->L = n;
	for (i = 0; i < n; i++)
		pucEncDataOut->C[i] = pucEncDataIn->C[i] ^ 0x5A;
	return SDR_OK;
}

/* 明文密钥导入:同 ImportKeyWithKEK */
RV SDF_ImportKey(HANDLE hSessionHandle, UCHAR *pucKey, UINT32 uiKeyLength,
	HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)pucKey;
	if (phKeyHandle == NULL)
		return SDR_OUTARGERR;
	if (uiKeyLength == 0)
		return SDR_KEYERR;
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

/* ---------- SM2 密钥协商 ---------- */

RV SDF_GenerateAgreementDataWithECC(HANDLE hSessionHandle, UINT32 uiISKIndex,
	UINT32 uiKeyBits, UCHAR *pucSponsorID, UINT32 uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
	HANDLE *phAgreementHandle)
{
	(void)hSessionHandle;
	(void)uiISKIndex;
	(void)uiKeyBits;
	(void)pucSponsorID;
	(void)uiSponsorIDLength;
	if (pucSponsorPublicKey == NULL || pucSponsorTmpPublicKey == NULL ||
		phAgreementHandle == NULL)
		return SDR_OUTARGERR;
	fill_pub(pucSponsorPublicKey);
	fill_pub(pucSponsorTmpPublicKey);
	*phAgreementHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

RV SDF_GenerateKeyWithECC(HANDLE hSessionHandle, UCHAR *pucResponseID,
	UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey, HANDLE hAgreementHandle,
	HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)pucResponseID;
	(void)uiResponseIDLength;
	(void)pucResponsePublicKey;
	(void)pucResponseTmpPublicKey;
	(void)hAgreementHandle;
	if (phKeyHandle == NULL)
		return SDR_OUTARGERR;
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

RV SDF_GenerateAgreementDataAndKeyWithECC(HANDLE hSessionHandle, UINT32 uiISKIndex,
	UINT32 uiKeyBits, UCHAR *pucResponseID, UINT32 uiResponseIDLength,
	UCHAR *pucSponsorID, UINT32 uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey,
	ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey,
	HANDLE *phKeyHandle)
{
	(void)hSessionHandle;
	(void)uiISKIndex;
	(void)uiKeyBits;
	(void)pucResponseID;
	(void)uiResponseIDLength;
	(void)pucSponsorID;
	(void)uiSponsorIDLength;
	(void)pucSponsorPublicKey;
	(void)pucSponsorTmpPublicKey;
	/* GM/T 0018 §6.3.16:sponsor 侧参数为 [in],响应方长期/临时公钥为 [out]。
	 * 与 sdf_shim.c gen_agreement_data_and_key_with_ecc 一致,设备侧保持标准符合。 */
	if (pucResponsePublicKey == NULL || pucResponseTmpPublicKey == NULL ||
		phKeyHandle == NULL)
		return SDR_OUTARGERR;
	fill_pub(pucResponsePublicKey);
	fill_pub(pucResponseTmpPublicKey);
	*phKeyHandle = (HANDLE)(++g_key_seq);
	return SDR_OK;
}

/* ---------- 非对称运算 ---------- */

RV SDF_ExternalVerify_ECC(HANDLE hSessionHandle, UINT32 uiAlgID,
	ECCrefPublicKey *pucPublicKey, UCHAR *pucDataInput, UINT32 uiInputLength,
	ECCSignature *pucSignature)
{
	/* 与 SDF_InternalSign_ECC 同一确定性派生规则:期望签名逐字节比对,
	 * 不匹配返回 SDR_VERIFYERR(恒 SDR_OK 会让验签接线回归检测不到)。 */
	UINT32 i, n;
	unsigned char r[64];
	unsigned char s[64];

	(void)hSessionHandle;
	(void)uiAlgID;
	(void)pucPublicKey;
	if (pucSignature == NULL || pucDataInput == NULL || uiInputLength == 0)
		return SDR_VERIFYERR;
	memset(r, 0, sizeof(r));
	n = uiInputLength > 64 ? 64 : uiInputLength;
	memcpy(r + (64 - n), pucDataInput + (uiInputLength - n), n);
	for (i = 0; i < 64; i++) /* S = 按位取反 */
		s[i] = (unsigned char)~r[i];
	s[63] |= 1; /* 与 InternalSign 同:最低字节置 1 */
	if (memcmp(pucSignature->r, r, 64) != 0 ||
		memcmp(pucSignature->s, s, 64) != 0)
		return SDR_VERIFYERR;
	return SDR_OK;
}

RV SDF_InternalSign_ECC(HANDLE hSessionHandle, UINT32 uiISKIndex, UCHAR *pucData,
	UINT32 uiDataLength, ECCSignature *pucSignature)
{
	UINT32 i, n;

	(void)hSessionHandle;
	(void)uiISKIndex;
	if (pucSignature == NULL || pucData == NULL || uiDataLength == 0)
		return SDR_SIGNERR;
	memset(pucSignature, 0, sizeof(*pucSignature));
	n = uiDataLength > 64 ? 64 : uiDataLength;
	memcpy(pucSignature->r + (64 - n), pucData + (uiDataLength - n), n);
	for (i = 0; i < 64; i++) /* S = 按位取反 */
		pucSignature->s[i] = (unsigned char)~pucSignature->r[i];
	pucSignature->s[63] |= 1; /* 最低字节置 1:全 0xFF 输入取反为 0,保证非零 */
	return SDR_OK;
}

RV SDF_InternalVerify_ECC(HANDLE hSessionHandle, UINT32 uiISKIndex, UCHAR *pucData,
	UINT32 uiDataLength, ECCSignature *pucSignature)
{
	(void)hSessionHandle;
	(void)uiISKIndex;
	(void)pucData;
	(void)uiDataLength;
	(void)pucSignature;
	return SDR_OK;
}

RV SDF_ExternalEncrypt_ECC(HANDLE hSessionHandle, UINT32 uiAlgID,
	ECCrefPublicKey *pucPublicKey, UCHAR *pucData, UINT32 uiDataLength,
	ECCCipher *pucEncData)
{
	(void)hSessionHandle;
	(void)uiAlgID;
	(void)pucPublicKey;
	if (pucEncData == NULL || (uiDataLength > 0 && pucData == NULL))
		return SDR_OUTARGERR;
	fill_cipher(pucEncData, pucData, uiDataLength);
	return SDR_OK;
}

/* ---------- 对称运算(单包) ---------- */

static RV xor_crypt(UCHAR *data, UINT32 len, UCHAR *out, UINT32 *outLen)
{
	UINT32 i;

	if (outLen == NULL || (len > 0 && (data == NULL || out == NULL)))
		return SDR_OUTARGERR;
	if (*outLen < len)
		return SDR_NOBUFFER;
	for (i = 0; i < len; i++)
		out[i] = data[i] ^ 0x5A;
	*outLen = len;
	return SDR_OK;
}

RV SDF_Encrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV,
	UCHAR *pucData, UINT32 uiDataLength, UCHAR *pucEncData, UINT32 *puiEncDataLength)
{
	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucIV;
	return xor_crypt(pucData, uiDataLength, pucEncData, puiEncDataLength);
}

RV SDF_Decrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV,
	UCHAR *pucEncData, UINT32 uiEncDataLength, UCHAR *pucData, UINT32 *puiDataLength)
{
	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucIV;
	return xor_crypt(pucEncData, uiEncDataLength, pucData, puiDataLength);
}

RV SDF_CalculateMAC(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID, UCHAR *pucIV,
	UCHAR *pucData, UINT32 uiDataLength, UCHAR *pucMAC, UINT32 *puiMACLength)
{
	unsigned int acc;

	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucIV;
	if (pucMAC == NULL || puiMACLength == NULL || *puiMACLength < 16)
		return SDR_OUTARGERR;
	acc = fnv1a(2166136261u, pucData, uiDataLength);
	fill_digest(acc, pucMAC, 16);
	*puiMACLength = 16;
	return SDR_OK;
}

/* ---------- 对称运算(多包,2023 6.5 原型) ---------- */

#ifdef GOSDF_STUB_BUFFERED_SYM
/* Final 才输出全部密文的缓冲变体,用于验证 Crypter.Final 的缓冲分配 */
static UCHAR g_sym_buf[4096];
static UINT32 g_sym_len;
#endif

RV SDF_EncryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID,
	UCHAR *pucIV, UINT32 uiIVLength)
{
	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucIV;
	(void)uiIVLength;
#ifdef GOSDF_STUB_BUFFERED_SYM
	g_sym_len = 0;
#endif
	return SDR_OK;
}

RV SDF_EncryptUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength,
	UCHAR *pucEncData, UINT32 *puiEncDataLength)
{
	(void)hSessionHandle;
#ifdef GOSDF_STUB_BUFFERED_SYM
	(void)pucEncData;
	if (puiEncDataLength == NULL || (pucData == NULL && uiDataLength > 0))
		return SDR_INARGERR;
	if (g_sym_len + uiDataLength > sizeof(g_sym_buf))
		return SDR_NOBUFFER;
	if (uiDataLength > 0)
		memcpy(g_sym_buf + g_sym_len, pucData, uiDataLength);
	g_sym_len += uiDataLength;
	*puiEncDataLength = 0; /* 缓冲模型:Final 才输出 */
	return SDR_OK;
#else
	return xor_crypt(pucData, uiDataLength, pucEncData, puiEncDataLength);
#endif
}

RV SDF_EncryptFinal(HANDLE hSessionHandle, UCHAR *pucEncData, UINT32 *puiEncDataLength)
{
	UINT32 i;
	(void)hSessionHandle;
#ifdef GOSDF_STUB_BUFFERED_SYM
	if (puiEncDataLength == NULL || pucEncData == NULL)
		return SDR_OUTARGERR;
	if (*puiEncDataLength < g_sym_len)
		return SDR_NOBUFFER;
	for (i = 0; i < g_sym_len; i++)
		pucEncData[i] = g_sym_buf[i] ^ 0x5A;
	*puiEncDataLength = g_sym_len;
	g_sym_len = 0;
	return SDR_OK;
#else
	(void)pucEncData;
	(void)i;
	if (puiEncDataLength == NULL)
		return SDR_OUTARGERR;
	*puiEncDataLength = 0; /* XOR 分组无尾块 */
	return SDR_OK;
#endif
}

RV SDF_DecryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID,
	UCHAR *pucIV, UINT32 uiIVLength)
{
	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucIV;
	(void)uiIVLength;
	return SDR_OK;
}

RV SDF_DecryptUpdate(HANDLE hSessionHandle, UCHAR *pucEncData, UINT32 uiEncDataLength,
	UCHAR *pucData, UINT32 *puiDataLength)
{
	(void)hSessionHandle;
	return xor_crypt(pucEncData, uiEncDataLength, pucData, puiDataLength);
}

RV SDF_DecryptFinal(HANDLE hSessionHandle, UCHAR *pucData, UINT32 *puiDataLength)
{
	(void)hSessionHandle;
	(void)pucData;
	if (puiDataLength == NULL)
		return SDR_OUTARGERR;
	*puiDataLength = 0;
	return SDR_OK;
}

RV SDF_CalculateMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID,
	UCHAR *pucIV, UINT32 uiIVLength)
{
	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucIV;
	(void)uiIVLength;
	g_mac_acc = 2166136261u;
	return SDR_OK;
}

RV SDF_CalculateMACUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength)
{
	(void)hSessionHandle;
	g_mac_acc = fnv1a(g_mac_acc, pucData, uiDataLength);
	return SDR_OK;
}

RV SDF_CalculateMACFinal(HANDLE hSessionHandle, UCHAR *pucMAC, UINT32 *puiMACLength)
{
	(void)hSessionHandle;
	if (pucMAC == NULL || puiMACLength == NULL || *puiMACLength < 16)
		return SDR_OUTARGERR;
	fill_digest(g_mac_acc, pucMAC, 16);
	*puiMACLength = 16;
	return SDR_OK;
}

#ifdef GOSDF_STUB_STREAM_AEAD
/* ---------- 多步 AEAD(流式;仅用于验证 Update 输出不被丢弃) ---------- */

static int g_aead_active;
static int g_aead_role; /* 1=enc, 2=dec */

RV SDF_AuthEncInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID,
	UCHAR *pucStartVar, UINT32 uiStartVarLength, UCHAR *pucAad,
	UINT32 uiAadLength, UINT32 uiDataLength)
{
	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucAad;
	(void)uiAadLength;
	(void)uiDataLength;
	if (pucStartVar == NULL || uiStartVarLength == 0)
		return SDR_INARGERR;
	g_aead_active = 1;
	g_aead_role = 1;
	return SDR_OK;
}

RV SDF_AuthEncUpdate(HANDLE hSessionHandle, UCHAR *pucData, UINT32 uiDataLength,
	UCHAR *pucEncData, UINT32 *puiEncDataLength)
{
	UINT32 i;

	(void)hSessionHandle;
	if (!g_aead_active || g_aead_role != 1)
		return SDR_STEPERR;
	if (puiEncDataLength == NULL ||
		(pucData == NULL && uiDataLength > 0) ||
		(pucEncData == NULL && uiDataLength > 0))
		return SDR_INARGERR;
	if (*puiEncDataLength < uiDataLength)
		return SDR_NOBUFFER;
	for (i = 0; i < uiDataLength; i++)
		pucEncData[i] = pucData[i] ^ 0x5A;
	*puiEncDataLength = uiDataLength;
	return SDR_OK;
}

RV SDF_AuthEncFinal(HANDLE hSessionHandle, UCHAR *pucLastEncData,
	UINT32 *puiLastEncDataLength, UCHAR *pucAuthData, UINT32 *puiAuthDataLength)
{
	(void)hSessionHandle;
	(void)pucLastEncData;
	if (!g_aead_active || g_aead_role != 1)
		return SDR_STEPERR;
	if (puiLastEncDataLength == NULL || pucAuthData == NULL ||
		puiAuthDataLength == NULL || *puiAuthDataLength < 16)
		return SDR_OUTARGERR;
	*puiLastEncDataLength = 0;
	memset(pucAuthData, 0xA5, 16);
	*puiAuthDataLength = 16;
	g_aead_active = 0;
	return SDR_OK;
}

RV SDF_AuthDecInit(HANDLE hSessionHandle, HANDLE hKeyHandle, UINT32 uiAlgID,
	UCHAR *pucStartVar, UINT32 uiStartVarLength, UCHAR *pucAad,
	UINT32 uiAadLength, UCHAR *pucAuthData, UINT32 uiAuthDataLength,
	UINT32 uiDataLength)
{
	(void)hSessionHandle;
	(void)hKeyHandle;
	(void)uiAlgID;
	(void)pucAad;
	(void)uiAadLength;
	(void)uiDataLength;
	if (pucStartVar == NULL || uiStartVarLength == 0 ||
		pucAuthData == NULL || uiAuthDataLength != 16)
		return SDR_INARGERR;
	g_aead_active = 1;
	g_aead_role = 2;
	return SDR_OK;
}

RV SDF_AuthDecUpdate(HANDLE hSessionHandle, UCHAR *pucEncData,
	UINT32 uiEncDataLength, UCHAR *pucData, UINT32 *puiDataLength)
{
	UINT32 i;

	(void)hSessionHandle;
	if (!g_aead_active || g_aead_role != 2)
		return SDR_STEPERR;
	if (puiDataLength == NULL ||
		(pucEncData == NULL && uiEncDataLength > 0) ||
		(pucData == NULL && uiEncDataLength > 0))
		return SDR_INARGERR;
	if (*puiDataLength < uiEncDataLength)
		return SDR_NOBUFFER;
	for (i = 0; i < uiEncDataLength; i++)
		pucData[i] = pucEncData[i] ^ 0x5A;
	*puiDataLength = uiEncDataLength;
	return SDR_OK;
}

RV SDF_AuthDecFinal(HANDLE hSessionHandle, UCHAR *pucLastData,
	UINT32 *puiLastDataLength)
{
	(void)hSessionHandle;
	(void)pucLastData;
	if (!g_aead_active || g_aead_role != 2)
		return SDR_STEPERR;
	if (puiLastDataLength == NULL)
		return SDR_OUTARGERR;
	*puiLastDataLength = 0;
	g_aead_active = 0;
	return SDR_OK;
}
#endif /* GOSDF_STUB_STREAM_AEAD */

/* ---------- 文件操作 ---------- */

RV SDF_CreateFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen,
	UINT32 uiFileSize)
{
	(void)hSessionHandle;
	(void)uiFileSize;
	if (pucFileName == NULL || uiNameLen == 0)
		return SDR_INARGERR;
	record_file("create", pucFileName, uiNameLen);
	g_file_len = 0;
	return SDR_OK;
}

RV SDF_WriteFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen,
	UINT32 uiOffset, UINT32 uiWriteLength, UCHAR *pucBuffer)
{
	(void)hSessionHandle;
	if (pucFileName == NULL || uiNameLen == 0)
		return SDR_INARGERR;
	record_file("write", pucFileName, uiNameLen);
	if (uiWriteLength > 0 && pucBuffer == NULL)
		return SDR_FILEWERR;
	if ((uint64_t)uiOffset + uiWriteLength > STUB_FILE_MAX)
		return SDR_FILESIZEERR;
	memcpy(g_file_data + uiOffset, pucBuffer, uiWriteLength);
	if (uiOffset + uiWriteLength > g_file_len)
		g_file_len = uiOffset + uiWriteLength;
	return SDR_OK;
}

RV SDF_ReadFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen,
	UINT32 uiOffset, UINT32 *puiReadLength, UCHAR *pucBuffer)
{
	UINT32 req, n;

	(void)hSessionHandle;
	if (pucFileName == NULL || uiNameLen == 0 || puiReadLength == NULL)
		return SDR_INARGERR;
	record_file("read", pucFileName, uiNameLen);
	if (*puiReadLength > 0 && pucBuffer == NULL)
		return SDR_OUTARGERR;
	if (uiOffset >= g_file_len) {
		*puiReadLength = 0;
		return SDR_OK;
	}
	req = *puiReadLength;
	n = g_file_len - uiOffset;
	if (n > req)
		n = req;
	memcpy(pucBuffer, g_file_data + uiOffset, n);
	*puiReadLength = n;
	return SDR_OK;
}

RV SDF_DeleteFile(HANDLE hSessionHandle, UCHAR *pucFileName, UINT32 uiNameLen)
{
	(void)hSessionHandle;
	if (pucFileName == NULL || uiNameLen == 0)
		return SDR_INARGERR;
	record_file("delete", pucFileName, uiNameLen);
	g_file_len = 0;
	return SDR_OK;
}
