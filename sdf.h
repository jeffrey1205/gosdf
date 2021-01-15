#ifndef __SDF_FUNC_H__
#define __SDF_FUNC_H__

#include "base_type.h"
#include "sdf_type.h"

#ifdef __cplusplus
extern "C"
{
#endif
	/*device manage*/
	int SDF_OpenDevice(void **phDeviceHandle);
	int SDF_CloseDevice(void *hDeviceHandle);
	int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
	int SDF_CloseSession(void *hSessionHandle);
	//int SDF_SecLock(void *hSessionHandle, unsigned int time);
	//int SDF_SecUnlock(void *hSessionHandle);
	int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);
	int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom);
	int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength);
	int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int uiKeyIndex);

	/*key manage*/
	int SDF_ExportSignPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
	int SDF_ExportEncPublicKey_RSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
	int SDF_GenerateKeyPair_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
	int SDF_GenerateKeyWithIPK_RSA(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
								   unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
	int SDF_GenerateKeyWithEPK_RSA(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey,
								   unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
	int SDF_ImportKeyWithISK_RSA(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey,
								 unsigned int puiKeyLength, void **phKeyHandle);
	int SDF_ExchangeDigitEnvelopeBaseOnRSA(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey,
										   unsigned char *pucDEInput, unsigned int uiDELength, unsigned char *pucDEOutput, unsigned int *puiDELength);
	int SDF_ExportSignPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
	int SDF_ExportEncPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
	int SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits,
								ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
	int SDF_GenerateKeyWithIPK_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits,
								   ECCCipher *pucKey, void **phKeyHandle);
	int SDF_GenerateKeyWithEPK_ECC(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID,
								   ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle);
	int SDF_ImportKeyWithISK_ECC(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle);
	int EVDF_ExportKeyWithEPK_ECC(void *hSessionHandle, void *hKeyHandle, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey);
	int SDF_GenerateAgreementDataWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,
										 unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void **phAgreementHandle);
	int SDF_GenerateKeyWithECC(void *hSessionHandle, unsigned char *pucResponseID, unsigned int uiResponseIDLength,
							   ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle, void **phKeyHandle);
	int SDF_GenerateAgreementDataAndKeyWithECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucResponseID,
											   unsigned int uiResponseIDLength, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
											   ECCrefPublicKey *pucSponsorTmpPublicKey, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void **phKeyHandle);
	int SDF_ExchangeDigitEnvelopeBaseOnECC(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiAlgID,
										   ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, ECCCipher *pucEncDataOut);
	int SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
							   unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
	int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int puiKeyLength, void **phKeyHandle);
	int EVDF_ImportKeyWithSessionKey(void *hSessionHandle, unsigned int uiAlgID, void *hSessionKeyHandle, unsigned char *pucKey, unsigned int puiKeyLength, void **phKeyHandle);
	int EVDF_SetKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
	int SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
	int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle);

	/*asym*/
	int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle, RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,
										   unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle, RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
											unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput,
										   unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput,
											unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
	int SDF_ExternalSign_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
							 unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
	int SDF_ExternalVerify_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
							   unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
	int SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData,
							 unsigned int uiDataLength, ECCSignature *pucSignature);
	int SDF_InternalVerify_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned char *pucData,
							   unsigned int uiDataLength, ECCSignature *pucSignature);
	int SDF_ExternalEncrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
								unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData);
	int SDF_ExternalDecrypt_ECC(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey,
								ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength);
	int SDF_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiIPKIndex, unsigned char *pucData,
								unsigned int uiDataLength, ECCCipher *pucEncData);
	int SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucEncData,
								unsigned char *pucData, unsigned int *puiDataLength);

	/*symm*/
	int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
					unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
	int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
					unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
	int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
						 unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucMAC, unsigned int *puiMACLength);

	/* hash */
	int SDF_HashInit(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey,
					 unsigned char *pucID, unsigned int uiIDLength);
	int SDF_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
	int EVDF_HashUpdateWithKey(void *hSessionHandle, void *hKeyHandle, unsigned int uiKeyFormat);
	int SDF_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength);
	int EVDF_HMACInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength);
	int EVDF_HMACUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
	int EVDF_HMACFinal(void *hSessionHandle, unsigned char *pucHMAC, unsigned int *puiHMACLength);

	/* file */
	int SDF_CreateFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);
	int SDF_ReadFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
					 unsigned int uiOffset, unsigned int *puiFileLength, unsigned char *pucBuffer);
	int SDF_WriteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen,
					  unsigned int uiOffset, unsigned int uiFileLength, unsigned char *pucBuffer);
	int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen);
	int EVDF_EnumFiles(void *hSessionHandle, char *szFileList, unsigned int *puiSize);

#define SDF_ExportKeyWithEPK_ECC EVDF_ExportKeyWithEPK_ECC
#define SDF_ImportKeyWithSessionKey EVDF_ImportKeyWithSessionKey
#define SDF_SetKey EVDF_SetKey
#define SDF_HashUpdateWithKey EVDF_HashUpdateWithKey
#ifdef __cplusplus
};
#endif

#endif /*__SDF_FUNC_H__*/