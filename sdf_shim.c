#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sdf.h"

/* 全部 SDF_* 绑定函数指针,沿用 sdf.h 原型 */
struct sdf_ctx {
	void *lib;	/* dlopen 句柄 */
	HANDLE dev;	/* 加密设备句柄 */

	RV (*OpenDevice)(HANDLE *);
	RV (*CloseDevice)(HANDLE);
	RV (*OpenSession)(HANDLE, HANDLE *);
	RV (*CloseSession)(HANDLE);
	RV (*GetDeviceInfo)(HANDLE, DEVICEINFO *);
	RV (*GenerateRandom)(HANDLE, UINT32, UCHAR *);
	RV (*GetPrivateKeyAccessRight)(HANDLE, UINT32, UCHAR *, UINT32);
	RV (*ReleasePrivateKeyAccessRight)(HANDLE, UINT32);

	RV (*HashInit)(HANDLE, UINT32, ECCrefPublicKey *, UCHAR *, UINT32);
	RV (*HashUpdate)(HANDLE, UCHAR *, UINT32);
	RV (*HashFinal)(HANDLE, UCHAR *, UINT32 *);

	RV (*HMACInit)(HANDLE, HANDLE, UINT32);
	RV (*HMACUpdate)(HANDLE, UCHAR *, UINT32);
	RV (*HMACFinal)(HANDLE, UCHAR *, UINT32 *);

	RV (*ExportSignPublicKey_ECC)(HANDLE, UINT32, ECCrefPublicKey *);
	RV (*ExportEncPublicKey_ECC)(HANDLE, UINT32, ECCrefPublicKey *);
	RV (*GenerateKeyWithIPK_ECC)(HANDLE, UINT32, UINT32, ECCCipher *, HANDLE *);
	RV (*GenerateKeyWithEPK_ECC)(HANDLE, UINT32, UINT32, ECCrefPublicKey *, ECCCipher *, HANDLE *);
	RV (*ImportKeyWithISK_ECC)(HANDLE, UINT32, ECCCipher *, HANDLE *);
	RV (*GenerateKeyWithKEK)(HANDLE, UINT32, UINT32, UINT32, UCHAR *, UINT32 *, HANDLE *);
	RV (*ImportKeyWithKEK)(HANDLE, UINT32, UINT32, UCHAR *, UINT32, HANDLE *);
	RV (*DestroyKey)(HANDLE, HANDLE);

	/* RSA/通用密钥管理(2012 6.3.1~6.3.7、6.3.10、6.3.17、6.3.20;GenerateKeyPair 亦见 2023 表16) */
	RV (*ExportSignPublicKey_RSA)(HANDLE, UINT32, RSArefPublicKey *);
	RV (*ExportEncPublicKey_RSA)(HANDLE, UINT32, RSArefPublicKey *);
	RV (*GenerateKeyPair_RSA)(HANDLE, UINT32, RSArefPublicKey *, RSArefPrivateKey *);
	RV (*GenerateKeyPair_ECC)(HANDLE, UINT32, UINT32, ECCrefPublicKey *, ECCrefPrivateKey *);
	RV (*GenerateKeyWithIPK_RSA)(HANDLE, UINT32, UINT32, UCHAR *, UINT32 *, HANDLE *);
	RV (*GenerateKeyWithEPK_RSA)(HANDLE, UINT32, RSArefPublicKey *, UCHAR *, UINT32 *, HANDLE *);
	RV (*ImportKeyWithISK_RSA)(HANDLE, UINT32, UCHAR *, UINT32, HANDLE *);
	RV (*ExchangeDigitEnvelopeBaseOnRSA)(HANDLE, UINT32, RSArefPublicKey *,
		UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*ExchangeDigitEnvelopeBaseOnECC)(HANDLE, UINT32, UINT32, ECCrefPublicKey *,
		ECCCipher *, ECCCipher *);
	RV (*ImportKey)(HANDLE, UCHAR *, UINT32, HANDLE *);

	RV (*GenerateAgreementDataWithECC)(HANDLE, UINT32, UINT32, UCHAR *, UINT32,
		ECCrefPublicKey *, ECCrefPublicKey *, HANDLE *);
	RV (*GenerateKeyWithECC)(HANDLE, UCHAR *, UINT32, ECCrefPublicKey *,
		ECCrefPublicKey *, HANDLE, HANDLE *);
	RV (*GenerateAgreementDataAndKeyWithECC)(HANDLE, UINT32, UINT32, UCHAR *, UINT32,
		UCHAR *, UINT32, ECCrefPublicKey *, ECCrefPublicKey *,
		ECCrefPublicKey *, ECCrefPublicKey *, HANDLE *);

	RV (*ExternalVerify_ECC)(HANDLE, UINT32, ECCrefPublicKey *, UCHAR *, UINT32, ECCSignature *);
	RV (*InternalSign_ECC)(HANDLE, UINT32, UCHAR *, UINT32, ECCSignature *);
	RV (*InternalVerify_ECC)(HANDLE, UINT32, UCHAR *, UINT32, ECCSignature *);
	RV (*ExternalEncrypt_ECC)(HANDLE, UINT32, ECCrefPublicKey *, UCHAR *, UINT32, ECCCipher *);

	RV (*Encrypt)(HANDLE, HANDLE, UINT32, UCHAR *, UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*Decrypt)(HANDLE, HANDLE, UINT32, UCHAR *, UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*CalculateMAC)(HANDLE, HANDLE, UINT32, UCHAR *, UCHAR *, UINT32, UCHAR *, UINT32 *);

	/* 2023 6.5 多包原型,按名 dlsym */
	RV (*EncryptInit)(HANDLE, HANDLE, UINT32, UCHAR *, UINT32);
	RV (*EncryptUpdate)(HANDLE, UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*EncryptFinal)(HANDLE, UCHAR *, UINT32 *);
	RV (*DecryptInit)(HANDLE, HANDLE, UINT32, UCHAR *, UINT32);
	RV (*DecryptUpdate)(HANDLE, UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*DecryptFinal)(HANDLE, UCHAR *, UINT32 *);
	RV (*CalculateMACInit)(HANDLE, HANDLE, UINT32, UCHAR *, UINT32);
	RV (*CalculateMACUpdate)(HANDLE, UCHAR *, UINT32);
	RV (*CalculateMACFinal)(HANDLE, UCHAR *, UINT32 *);

	/* 可鉴别加解密(2023 表13),按名 dlsym,可选 */
	RV (*AuthEnc)(HANDLE, HANDLE, UINT32, UCHAR *, UINT32, UCHAR *, UINT32,
		UCHAR *, UINT32, UCHAR *, UINT32 *, UCHAR *, UINT32 *);
	RV (*AuthDec)(HANDLE, HANDLE, UINT32, UCHAR *, UINT32, UCHAR *, UINT32,
		UCHAR *, UINT32, UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*AuthEncInit)(HANDLE, HANDLE, UINT32, UCHAR *, UINT32, UCHAR *, UINT32,
		UINT32);
	RV (*AuthEncUpdate)(HANDLE, UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*AuthEncFinal)(HANDLE, UCHAR *, UINT32 *, UCHAR *, UINT32 *);
	RV (*AuthDecInit)(HANDLE, HANDLE, UINT32, UCHAR *, UINT32, UCHAR *, UINT32,
		UCHAR *, UINT32, UINT32);
	RV (*AuthDecUpdate)(HANDLE, UCHAR *, UINT32, UCHAR *, UINT32 *);
	RV (*AuthDecFinal)(HANDLE, UCHAR *, UINT32 *);

	RV (*CreateFile)(HANDLE, UCHAR *, UINT32, UINT32);
	RV (*ReadFile)(HANDLE, UCHAR *, UINT32, UINT32, UINT32 *, UCHAR *);
	RV (*WriteFile)(HANDLE, UCHAR *, UINT32, UINT32, UINT32, UCHAR *);
	RV (*DeleteFile)(HANDLE, UCHAR *, UINT32);
};

struct func_name_pair {
	const char *name;	/* SDF_* 符号名 */
	size_t offset;		/* 函数指针在 sdf_ctx 中的偏移 */
	int required;		/* 是否必需(缺失即整体失败) */
};

#define BIND(field, sym, req) { sym, offsetof(struct sdf_ctx, field), req }

static const struct func_name_pair gs_func_name_arr[] = {
	BIND(OpenDevice, "SDF_OpenDevice", 1),
	BIND(CloseDevice, "SDF_CloseDevice", 1),
	BIND(OpenSession, "SDF_OpenSession", 1),
	BIND(CloseSession, "SDF_CloseSession", 1),
	BIND(GetDeviceInfo, "SDF_GetDeviceInfo", 0),
	BIND(GenerateRandom, "SDF_GenerateRandom", 0),
	BIND(GetPrivateKeyAccessRight, "SDF_GetPrivateKeyAccessRight", 0),
	BIND(ReleasePrivateKeyAccessRight, "SDF_ReleasePrivateKeyAccessRight", 0),

	BIND(HashInit, "SDF_HashInit", 0),
	BIND(HashUpdate, "SDF_HashUpdate", 0),
	BIND(HashFinal, "SDF_HashFinal", 0),

	BIND(HMACInit, "SDF_HMACInit", 0),
	BIND(HMACUpdate, "SDF_HMACUpdate", 0),
	BIND(HMACFinal, "SDF_HMACFinal", 0),

	BIND(ExportSignPublicKey_ECC, "SDF_ExportSignPublicKey_ECC", 0),
	BIND(ExportEncPublicKey_ECC, "SDF_ExportEncPublicKey_ECC", 0),
	BIND(GenerateKeyWithIPK_ECC, "SDF_GenerateKeyWithIPK_ECC", 0),
	BIND(GenerateKeyWithEPK_ECC, "SDF_GenerateKeyWithEPK_ECC", 0),
	BIND(ImportKeyWithISK_ECC, "SDF_ImportKeyWithISK_ECC", 0),
	BIND(GenerateKeyWithKEK, "SDF_GenerateKeyWithKEK", 0),
	BIND(ImportKeyWithKEK, "SDF_ImportKeyWithKEK", 0),
	BIND(DestroyKey, "SDF_DestroyKey", 0),

	BIND(ExportSignPublicKey_RSA, "SDF_ExportSignPublicKey_RSA", 0),
	BIND(ExportEncPublicKey_RSA, "SDF_ExportEncPublicKey_RSA", 0),
	BIND(GenerateKeyPair_RSA, "SDF_GenerateKeyPair_RSA", 0),
	BIND(GenerateKeyPair_ECC, "SDF_GenerateKeyPair_ECC", 0),
	BIND(GenerateKeyWithIPK_RSA, "SDF_GenerateKeyWithIPK_RSA", 0),
	BIND(GenerateKeyWithEPK_RSA, "SDF_GenerateKeyWithEPK_RSA", 0),
	BIND(ImportKeyWithISK_RSA, "SDF_ImportKeyWithISK_RSA", 0),
	BIND(ExchangeDigitEnvelopeBaseOnRSA, "SDF_ExchangeDigitEnvelopeBaseOnRSA", 0),
	BIND(ExchangeDigitEnvelopeBaseOnECC, "SDF_ExchangeDigitEnvelopeBaseOnECC", 0),
	BIND(ImportKey, "SDF_ImportKey", 0),

	BIND(GenerateAgreementDataWithECC, "SDF_GenerateAgreementDataWithECC", 0),
	BIND(GenerateKeyWithECC, "SDF_GenerateKeyWithECC", 0),
	BIND(GenerateAgreementDataAndKeyWithECC, "SDF_GenerateAgreementDataAndKeyWithECC", 0),

	BIND(ExternalVerify_ECC, "SDF_ExternalVerify_ECC", 0),
	BIND(InternalSign_ECC, "SDF_InternalSign_ECC", 0),
	BIND(InternalVerify_ECC, "SDF_InternalVerify_ECC", 0),
	BIND(ExternalEncrypt_ECC, "SDF_ExternalEncrypt_ECC", 0),

	BIND(Encrypt, "SDF_Encrypt", 0),
	BIND(Decrypt, "SDF_Decrypt", 0),
	BIND(CalculateMAC, "SDF_CalculateMAC", 0),

	BIND(EncryptInit, "SDF_EncryptInit", 0),
	BIND(EncryptUpdate, "SDF_EncryptUpdate", 0),
	BIND(EncryptFinal, "SDF_EncryptFinal", 0),
	BIND(DecryptInit, "SDF_DecryptInit", 0),
	BIND(DecryptUpdate, "SDF_DecryptUpdate", 0),
	BIND(DecryptFinal, "SDF_DecryptFinal", 0),
	BIND(CalculateMACInit, "SDF_CalculateMACInit", 0),
	BIND(CalculateMACUpdate, "SDF_CalculateMACUpdate", 0),
	BIND(CalculateMACFinal, "SDF_CalculateMACFinal", 0),

	BIND(AuthEnc, "SDF_AuthEnc", 0),
	BIND(AuthDec, "SDF_AuthDec", 0),
	BIND(AuthEncInit, "SDF_AuthEncInit", 0),
	BIND(AuthEncUpdate, "SDF_AuthEncUpdate", 0),
	BIND(AuthEncFinal, "SDF_AuthEncFinal", 0),
	BIND(AuthDecInit, "SDF_AuthDecInit", 0),
	BIND(AuthDecUpdate, "SDF_AuthDecUpdate", 0),
	BIND(AuthDecFinal, "SDF_AuthDecFinal", 0),

	BIND(CreateFile, "SDF_CreateFile", 0),
	BIND(ReadFile, "SDF_ReadFile", 0),
	BIND(WriteFile, "SDF_WriteFile", 0),
	BIND(DeleteFile, "SDF_DeleteFile", 0),
};

#define BIND_COUNT ((int)(sizeof(gs_func_name_arr) / sizeof(gs_func_name_arr[0])))

/* 绑定函数缺失时 wrapper 一律返回 SDR_NOTSUPPORT 而非崩溃 */
#define REQUIRE(field) do { \
	if (c == NULL || c->field == NULL) \
		return SDR_NOTSUPPORT; \
} while (0)

/* 按 SDF_* 符号名探测绑定函数是否存在(1/0) */
int sdf_has(sdf_ctx *c, const char *sdf_symbol)
{
	int i;
	if (c == NULL || sdf_symbol == NULL)
		return 0;
	for (i = 0; i < BIND_COUNT; i++) {
		if (strcmp(gs_func_name_arr[i].name, sdf_symbol) == 0) {
			void *fn = *(void **)((char *)c + gs_func_name_arr[i].offset);
			return fn != NULL;
		}
	}
	return 0;
}

sdf_ctx *sdf_open(const char *path, RV *err)
{
	sdf_ctx *c;
	void *lib;
	int i;
	RV rv;

	if (path == NULL || path[0] == '\0' || err == NULL) {
		if (err != NULL)
			*err = SDR_INARGERR;
		return NULL;
	}

	lib = dlopen(path, RTLD_LAZY);
	if (lib == NULL) {
		*err = SDR_OPENDEVICE;
		return NULL;
	}

	c = (sdf_ctx *)calloc(1, sizeof(*c));
	if (c == NULL) {
		dlclose(lib);
		*err = SDR_UNKNOWERR;
		return NULL;
	}
	c->lib = lib;

	/* 必需符号缺失 → SDR_NOTSUPPORT;其余符号可选,缺失置 NULL */
	for (i = 0; i < BIND_COUNT; i++) {
		void *sym = dlsym(lib, gs_func_name_arr[i].name);
		if (sym == NULL && gs_func_name_arr[i].required) {
			free(c);
			dlclose(lib);
			*err = SDR_NOTSUPPORT;
			return NULL;
		}
		*(void **)((char *)c + gs_func_name_arr[i].offset) = sym;
	}

	rv = c->OpenDevice(&c->dev);
	if (rv != SDR_OK) {
		free(c);
		dlclose(lib);
		*err = rv;
		return NULL;
	}

	*err = SDR_OK;
	return c;
}

void sdf_close(sdf_ctx *c)
{
	if (c == NULL)
		return;
	if (c->CloseDevice != NULL && c->dev != NULL)
		c->CloseDevice(c->dev);
	if (c->lib != NULL)
		dlclose(c->lib);
	free(c);
}

/* 设备管理 */
RV open_session(sdf_ctx *c, long **session)
{
	REQUIRE(OpenSession);
	return c->OpenSession(c->dev, (HANDLE *)session);
}

RV close_session(sdf_ctx *c, long *session)
{
	REQUIRE(CloseSession);
	return c->CloseSession((HANDLE)session);
}

RV get_device_info(sdf_ctx *c, long *session, DEVICEINFO *info)
{
	REQUIRE(GetDeviceInfo);
	return c->GetDeviceInfo((HANDLE)session, info);
}

RV gen_random(sdf_ctx *c, long *session, UINT32 len, UCHAR *buf)
{
	REQUIRE(GenerateRandom);
	return c->GenerateRandom((HANDLE)session, len, buf);
}

RV verify_pin(sdf_ctx *c, long *session, UINT32 key_index, UCHAR *pin, UINT32 pin_len)
{
	REQUIRE(GetPrivateKeyAccessRight);
	return c->GetPrivateKeyAccessRight((HANDLE)session, key_index, pin, pin_len);
}

RV release_pin(sdf_ctx *c, long *session, UINT32 key_index)
{
	REQUIRE(ReleasePrivateKeyAccessRight);
	return c->ReleasePrivateKeyAccessRight((HANDLE)session, key_index);
}

/* 杂凑运算 */
RV hash_init(sdf_ctx *c, long *session, UINT32 alg, ECCrefPublicKey *pub, BYTE *id, UINT32 id_len)
{
	REQUIRE(HashInit);
	return c->HashInit((HANDLE)session, alg, pub, id, id_len);
}

RV hash_update(sdf_ctx *c, long *session, UCHAR *buf, UINT32 buf_len)
{
	REQUIRE(HashUpdate);
	return c->HashUpdate((HANDLE)session, buf, buf_len);
}

RV hash_final(sdf_ctx *c, long *session, UCHAR *hash, UINT32 *hash_len)
{
	REQUIRE(HashFinal);
	return c->HashFinal((HANDLE)session, hash, hash_len);
}

/* 带密钥的杂凑(GM/T 0018-2023 6.6.2~6.6.4,GB/T 15852.2) */
RV hmac_init(sdf_ctx *c, long *session, long *key, UINT32 alg)
{
	REQUIRE(HMACInit);
	return c->HMACInit((HANDLE)session, (HANDLE)key, alg);
}

RV hmac_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len)
{
	REQUIRE(HMACUpdate);
	return c->HMACUpdate((HANDLE)session, data, data_len);
}

RV hmac_final(sdf_ctx *c, long *session, UCHAR *mac, UINT32 *mac_len)
{
	REQUIRE(HMACFinal);
	return c->HMACFinal((HANDLE)session, mac, mac_len);
}

/* 密钥管理 */
RV export_sign_pubkey_ecc(sdf_ctx *c, long *session, UINT32 key_index, ECCrefPublicKey *pub)
{
	REQUIRE(ExportSignPublicKey_ECC);
	return c->ExportSignPublicKey_ECC((HANDLE)session, key_index, pub);
}

RV export_enc_pubkey_ecc(sdf_ctx *c, long *session, UINT32 key_index, ECCrefPublicKey *pub)
{
	REQUIRE(ExportEncPublicKey_ECC);
	return c->ExportEncPublicKey_ECC((HANDLE)session, key_index, pub);
}

/* RSA/通用密钥管理(2012 6.3.1~6.3.7、6.3.10、6.3.17、6.3.20;GenerateKeyPair 亦见 2023 表16) */
RV export_sign_pubkey_rsa(sdf_ctx *c, long *session, UINT32 key_index, RSArefPublicKey *pub)
{
	REQUIRE(ExportSignPublicKey_RSA);
	if (pub == NULL)
		return SDR_INARGERR;
	return c->ExportSignPublicKey_RSA((HANDLE)session, key_index, pub);
}

RV export_enc_pubkey_rsa(sdf_ctx *c, long *session, UINT32 key_index, RSArefPublicKey *pub)
{
	REQUIRE(ExportEncPublicKey_RSA);
	if (pub == NULL)
		return SDR_INARGERR;
	return c->ExportEncPublicKey_RSA((HANDLE)session, key_index, pub);
}

RV gen_keypair_rsa(sdf_ctx *c, long *session, UINT32 key_bits,
	RSArefPublicKey *pub, RSArefPrivateKey *priv)
{
	REQUIRE(GenerateKeyPair_RSA);
	if (pub == NULL || priv == NULL)
		return SDR_INARGERR;
	return c->GenerateKeyPair_RSA((HANDLE)session, key_bits, pub, priv);
}

RV gen_keypair_ecc(sdf_ctx *c, long *session, UINT32 alg, UINT32 key_bits,
	ECCrefPublicKey *pub, ECCrefPrivateKey *priv)
{
	REQUIRE(GenerateKeyPair_ECC);
	if (pub == NULL || priv == NULL)
		return SDR_INARGERR;
	return c->GenerateKeyPair_ECC((HANDLE)session, alg, key_bits, pub, priv);
}

RV gen_key_with_ipk_rsa(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	BYTE *key_buf, UINT32 *key_len, long **key_handle)
{
	REQUIRE(GenerateKeyWithIPK_RSA);
	if (key_buf == NULL || key_len == NULL || key_handle == NULL)
		return SDR_INARGERR;
	return c->GenerateKeyWithIPK_RSA((HANDLE)session, key_index, key_bits,
		key_buf, key_len, (HANDLE *)key_handle);
}

RV gen_key_with_epk_rsa(sdf_ctx *c, long *session, UINT32 key_bits, RSArefPublicKey *pub,
	BYTE *key_buf, UINT32 *key_len, long **key_handle)
{
	REQUIRE(GenerateKeyWithEPK_RSA);
	if (pub == NULL || key_buf == NULL || key_len == NULL || key_handle == NULL)
		return SDR_INARGERR;
	return c->GenerateKeyWithEPK_RSA((HANDLE)session, key_bits, pub,
		key_buf, key_len, (HANDLE *)key_handle);
}

RV import_key_with_isk_rsa(sdf_ctx *c, long *session, UINT32 key_index,
	BYTE *key_buf, UINT32 key_len, long **key_handle)
{
	REQUIRE(ImportKeyWithISK_RSA);
	if (key_buf == NULL || key_len == 0 || key_handle == NULL)
		return SDR_INARGERR;
	return c->ImportKeyWithISK_RSA((HANDLE)session, key_index, key_buf, key_len,
		(HANDLE *)key_handle);
}

RV exchange_envelope_rsa(sdf_ctx *c, long *session, UINT32 key_index, RSArefPublicKey *pub,
	UCHAR *de_in, UINT32 de_in_len, UCHAR *de_out, UINT32 *de_out_len)
{
	REQUIRE(ExchangeDigitEnvelopeBaseOnRSA);
	if (pub == NULL || de_in == NULL || de_in_len == 0 ||
		de_out == NULL || de_out_len == NULL)
		return SDR_INARGERR;
	return c->ExchangeDigitEnvelopeBaseOnRSA((HANDLE)session, key_index, pub,
		de_in, de_in_len, de_out, de_out_len);
}

RV exchange_envelope_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 alg,
	ECCrefPublicKey *pub, void *in_cipher, UINT32 in_cap,
	void *out_cipher, UINT32 out_cap)
{
	REQUIRE(ExchangeDigitEnvelopeBaseOnECC);
	if (pub == NULL || in_cipher == NULL || in_cap < (UINT32)sizeof(ECCCipher) ||
		out_cipher == NULL || out_cap < (UINT32)sizeof(ECCCipher))
		return SDR_INARGERR;
	return c->ExchangeDigitEnvelopeBaseOnECC((HANDLE)session, key_index, alg, pub,
		(ECCCipher *)in_cipher, (ECCCipher *)out_cipher);
}

RV import_key(sdf_ctx *c, long *session, BYTE *key_buf, UINT32 key_len, long **key_handle)
{
	REQUIRE(ImportKey);
	if (key_buf == NULL || key_len == 0 || key_handle == NULL)
		return SDR_INARGERR;
	return c->ImportKey((HANDLE)session, key_buf, key_len, (HANDLE *)key_handle);
}

RV gen_key_with_ipk_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	void *cipher_buf, UINT32 cipher_cap, long **key_handle)
{
	REQUIRE(GenerateKeyWithIPK_ECC);
	if (cipher_buf == NULL || cipher_cap < (UINT32)sizeof(ECCCipher))
		return SDR_INARGERR;
	return c->GenerateKeyWithIPK_ECC((HANDLE)session, key_index, key_bits,
		(ECCCipher *)cipher_buf, (HANDLE *)key_handle);
}

RV gen_key_with_epk_ecc(sdf_ctx *c, long *session, UINT32 key_bits, UINT32 alg, ECCrefPublicKey *pub,
	void *cipher_buf, UINT32 cipher_cap, long **key_handle)
{
	REQUIRE(GenerateKeyWithEPK_ECC);
	if (cipher_buf == NULL || cipher_cap < (UINT32)sizeof(ECCCipher) || pub == NULL)
		return SDR_INARGERR;
	return c->GenerateKeyWithEPK_ECC((HANDLE)session, key_bits, alg, pub,
		(ECCCipher *)cipher_buf, (HANDLE *)key_handle);
}

RV import_key_with_isk_ecc(sdf_ctx *c, long *session, UINT32 key_index,
	void *cipher_buf, UINT32 cipher_cap, long **key_handle)
{
	REQUIRE(ImportKeyWithISK_ECC);
	if (cipher_buf == NULL || cipher_cap < (UINT32)sizeof(ECCCipher))
		return SDR_INARGERR;
	return c->ImportKeyWithISK_ECC((HANDLE)session, key_index,
		(ECCCipher *)cipher_buf, (HANDLE *)key_handle);
}

RV gen_key_with_kek(sdf_ctx *c, long *session, UINT32 key_bits, UINT32 alg_id, UINT32 kek_index,
	BYTE *key_buf, UINT32 *key_len, long **key_handle)
{
	REQUIRE(GenerateKeyWithKEK);
	return c->GenerateKeyWithKEK((HANDLE)session, key_bits, alg_id, kek_index,
		key_buf, key_len, (HANDLE *)key_handle);
}

RV import_key_with_kek(sdf_ctx *c, long *session, UINT32 alg_id, UINT32 kek_index,
	BYTE *key_buf, UINT32 key_len, long **key_handle)
{
	REQUIRE(ImportKeyWithKEK);
	return c->ImportKeyWithKEK((HANDLE)session, alg_id, kek_index,
		key_buf, key_len, (HANDLE *)key_handle);
}

/* 修复:session 与 key 分别透传(旧实现两个参数都传了 key) */
RV destroy_key(sdf_ctx *c, long *session, long *key)
{
	REQUIRE(DestroyKey);
	return c->DestroyKey((HANDLE)session, (HANDLE)key);
}

/* SM2 密钥协商 */
RV gen_agreement_data_with_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	UCHAR *sponsor_id, UINT32 sponsor_id_len,
	ECCrefPublicKey *sponsor_pub, ECCrefPublicKey *sponsor_tmp_pub, long **handle)
{
	REQUIRE(GenerateAgreementDataWithECC);
	return c->GenerateAgreementDataWithECC((HANDLE)session, key_index, key_bits,
		sponsor_id, sponsor_id_len, sponsor_pub, sponsor_tmp_pub, (HANDLE *)handle);
}

RV gen_key_with_ecc(sdf_ctx *c, long *session,
	UCHAR *response_id, UINT32 response_id_len,
	ECCrefPublicKey *response_pub, ECCrefPublicKey *response_tmp_pub,
	long *handle, long **key_handle)
{
	REQUIRE(GenerateKeyWithECC);
	return c->GenerateKeyWithECC((HANDLE)session, response_id, response_id_len,
		response_pub, response_tmp_pub, (HANDLE)handle, (HANDLE *)key_handle);
}

RV gen_agreement_data_and_key_with_ecc(sdf_ctx *c, long *session, UINT32 key_index, UINT32 key_bits,
	UCHAR *response_id, UINT32 response_id_len, UCHAR *sponsor_id, UINT32 sponsor_id_len,
	ECCrefPublicKey *sponsor_pub, ECCrefPublicKey *sponsor_tmp_pub,
	ECCrefPublicKey *response_pub, ECCrefPublicKey *response_tmp_pub, long **key_handle)
{
	REQUIRE(GenerateAgreementDataAndKeyWithECC);
	/* GM/T 0018-2023 6.3.14:pucSponsorPublicKey[响应方调用时为外部输入的
	 * 发起方公钥]、pucResponsePublicKey[返回的响应方公钥]。Go 层把调用方传入的
	 * 对端公钥放在 response_* 参数、把返回的本端公钥放在 sponsor_* 参数,这里按
	 * 标准的 in/out 方向把两组槽位对调。 */
	return c->GenerateAgreementDataAndKeyWithECC((HANDLE)session, key_index, key_bits,
		response_id, response_id_len, sponsor_id, sponsor_id_len,
		response_pub, response_tmp_pub, sponsor_pub, sponsor_tmp_pub, (HANDLE *)key_handle);
}

/* 非对称运算 */
RV external_verify_ecc(sdf_ctx *c, long *session, UINT32 alg, ECCrefPublicKey *pub,
	UCHAR *buf, UINT32 buf_len, ECCSignature *sig)
{
	REQUIRE(ExternalVerify_ECC);
	return c->ExternalVerify_ECC((HANDLE)session, alg, pub, buf, buf_len, sig);
}

RV internal_sign_ecc(sdf_ctx *c, long *session, UINT32 key_index,
	UCHAR *data, UINT32 data_len, ECCSignature *sig)
{
	REQUIRE(InternalSign_ECC);
	return c->InternalSign_ECC((HANDLE)session, key_index, data, data_len, sig);
}

RV internal_verify_ecc(sdf_ctx *c, long *session, UINT32 key_index,
	UCHAR *data, UINT32 data_len, ECCSignature *sig)
{
	REQUIRE(InternalVerify_ECC);
	return c->InternalVerify_ECC((HANDLE)session, key_index, data, data_len, sig);
}

RV external_encrypt_ecc(sdf_ctx *c, long *session, UINT32 alg, ECCrefPublicKey *pub,
	UCHAR *data, UINT32 data_len, void *cipher_buf, UINT32 cipher_cap)
{
	REQUIRE(ExternalEncrypt_ECC);
	if (cipher_buf == NULL || cipher_cap < (UINT32)sizeof(ECCCipher) || pub == NULL)
		return SDR_INARGERR;
	return c->ExternalEncrypt_ECC((HANDLE)session, alg, pub, data, data_len,
		(ECCCipher *)cipher_buf);
}

/* 对称运算(单包) */
RV encrypt(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv,
	BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	REQUIRE(Encrypt);
	return c->Encrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV decrypt(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv,
	BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	REQUIRE(Decrypt);
	return c->Decrypt((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

RV cbc_mac(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv,
	BYTE *data, UINT32 data_len, BYTE *out_buf, UINT32 *out_len)
{
	REQUIRE(CalculateMAC);
	return c->CalculateMAC((HANDLE)session, (HANDLE)key, alg, iv, data, data_len, out_buf, out_len);
}

/* 对称运算(多包) */
RV enc_init(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv, UINT32 iv_len)
{
	REQUIRE(EncryptInit);
	return c->EncryptInit((HANDLE)session, (HANDLE)key, alg, iv, iv_len);
}

RV enc_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len, UCHAR *out, UINT32 *out_len)
{
	REQUIRE(EncryptUpdate);
	return c->EncryptUpdate((HANDLE)session, data, data_len, out, out_len);
}

RV enc_final(sdf_ctx *c, long *session, UCHAR *out, UINT32 *out_len)
{
	REQUIRE(EncryptFinal);
	return c->EncryptFinal((HANDLE)session, out, out_len);
}

RV dec_init(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv, UINT32 iv_len)
{
	REQUIRE(DecryptInit);
	return c->DecryptInit((HANDLE)session, (HANDLE)key, alg, iv, iv_len);
}

RV dec_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len, UCHAR *out, UINT32 *out_len)
{
	REQUIRE(DecryptUpdate);
	return c->DecryptUpdate((HANDLE)session, data, data_len, out, out_len);
}

RV dec_final(sdf_ctx *c, long *session, UCHAR *out, UINT32 *out_len)
{
	REQUIRE(DecryptFinal);
	return c->DecryptFinal((HANDLE)session, out, out_len);
}

RV mac_init(sdf_ctx *c, long *session, long *key, UINT32 alg, BYTE *iv, UINT32 iv_len)
{
	REQUIRE(CalculateMACInit);
	return c->CalculateMACInit((HANDLE)session, (HANDLE)key, alg, iv, iv_len);
}

RV mac_update(sdf_ctx *c, long *session, UCHAR *data, UINT32 data_len)
{
	REQUIRE(CalculateMACUpdate);
	return c->CalculateMACUpdate((HANDLE)session, data, data_len);
}

RV mac_final(sdf_ctx *c, long *session, UCHAR *out, UINT32 *out_len)
{
	REQUIRE(CalculateMACFinal);
	return c->CalculateMACFinal((HANDLE)session, out, out_len);
}

/* 可鉴别加解密(GM/T 0018-2023 表13;厂商 .so 可能缺失) */
RV auth_enc(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len,
	BYTE *data, UINT32 data_len,
	BYTE *enc_buf, UINT32 *enc_len,
	BYTE *auth_buf, UINT32 *auth_len)
{
	REQUIRE(AuthEnc);
	if (start_var == NULL || (aad == NULL && aad_len) ||
		(data == NULL && data_len) || enc_buf == NULL || enc_len == NULL ||
		auth_buf == NULL || auth_len == NULL)
		return SDR_INARGERR;
	return c->AuthEnc((HANDLE)session, (HANDLE)key, alg, start_var, start_var_len,
		aad, aad_len, data, data_len, enc_buf, enc_len, auth_buf, auth_len);
}

RV auth_dec(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len,
	BYTE *auth, UINT32 auth_len,
	BYTE *enc, UINT32 enc_len,
	BYTE *data_buf, UINT32 *data_len)
{
	REQUIRE(AuthDec);
	if (start_var == NULL || (aad == NULL && aad_len) || auth == NULL ||
		(enc == NULL && enc_len) || data_buf == NULL || data_len == NULL)
		return SDR_INARGERR;
	return c->AuthDec((HANDLE)session, (HANDLE)key, alg, start_var, start_var_len,
		aad, aad_len, auth, auth_len, enc, enc_len, data_buf, data_len);
}

RV auth_enc_init(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len, UINT32 data_len)
{
	REQUIRE(AuthEncInit);
	if (start_var == NULL || (aad == NULL && aad_len))
		return SDR_INARGERR;
	return c->AuthEncInit((HANDLE)session, (HANDLE)key, alg, start_var,
		start_var_len, aad, aad_len, data_len);
}

RV auth_enc_update(sdf_ctx *c, long *session, BYTE *data, UINT32 data_len,
	BYTE *enc_buf, UINT32 *enc_len)
{
	REQUIRE(AuthEncUpdate);
	if ((data == NULL && data_len) || enc_buf == NULL || enc_len == NULL)
		return SDR_INARGERR;
	return c->AuthEncUpdate((HANDLE)session, data, data_len, enc_buf, enc_len);
}

RV auth_enc_final(sdf_ctx *c, long *session, BYTE *enc_buf, UINT32 *enc_len,
	BYTE *auth_buf, UINT32 *auth_len)
{
	REQUIRE(AuthEncFinal);
	if (enc_buf == NULL || enc_len == NULL || auth_buf == NULL ||
		auth_len == NULL)
		return SDR_INARGERR;
	return c->AuthEncFinal((HANDLE)session, enc_buf, enc_len, auth_buf, auth_len);
}

RV auth_dec_init(sdf_ctx *c, long *session, long *key, UINT32 alg,
	BYTE *start_var, UINT32 start_var_len,
	BYTE *aad, UINT32 aad_len,
	BYTE *auth, UINT32 auth_len, UINT32 data_len)
{
	REQUIRE(AuthDecInit);
	if (start_var == NULL || (aad == NULL && aad_len) || auth == NULL)
		return SDR_INARGERR;
	return c->AuthDecInit((HANDLE)session, (HANDLE)key, alg, start_var,
		start_var_len, aad, aad_len, auth, auth_len, data_len);
}

RV auth_dec_update(sdf_ctx *c, long *session, BYTE *enc, UINT32 enc_len,
	BYTE *data_buf, UINT32 *data_len)
{
	REQUIRE(AuthDecUpdate);
	if ((enc == NULL && enc_len) || data_buf == NULL || data_len == NULL)
		return SDR_INARGERR;
	return c->AuthDecUpdate((HANDLE)session, enc, enc_len, data_buf, data_len);
}

RV auth_dec_final(sdf_ctx *c, long *session, BYTE *data_buf, UINT32 *data_len)
{
	REQUIRE(AuthDecFinal);
	if (data_buf == NULL || data_len == NULL)
		return SDR_INARGERR;
	return c->AuthDecFinal((HANDLE)session, data_buf, data_len);
}

/* 文件操作(文件名字节由调用方直接传入,不再复制) */
RV create_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len, UINT32 size)
{
	REQUIRE(CreateFile);
	return c->CreateFile((HANDLE)session, name, name_len, size);
}

RV read_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len,
	UINT32 offset, UINT32 *length, UCHAR *buf)
{
	REQUIRE(ReadFile);
	return c->ReadFile((HANDLE)session, name, name_len, offset, length, buf);
}

RV write_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len,
	UINT32 offset, UINT32 length, UCHAR *buf)
{
	REQUIRE(WriteFile);
	return c->WriteFile((HANDLE)session, name, name_len, offset, length, buf);
}

RV delete_file(sdf_ctx *c, long *session, UCHAR *name, UINT32 name_len)
{
	REQUIRE(DeleteFile);
	return c->DeleteFile((HANDLE)session, name, name_len);
}
