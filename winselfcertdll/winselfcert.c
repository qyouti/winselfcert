/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <stdio.h>
#include <jni.h>

#include <Windows.h>
#include <WinCrypt.h>
#include <tchar.h>

#include "org_qyouti_winselfcert_WindowsCertificateGenerator.h"


jbyteArray convertSerialNumber( JNIEnv *env, CRYPT_INTEGER_BLOB *pBlob )
{
    DWORD i, j;
    BYTE b;
    jbyteArray serial = (*env)->NewByteArray( env, pBlob->cbData );
    // convert little endian to big endian
    for ( i = 0, j=pBlob->cbData-1; i<(pBlob->cbData/2); i++, j-- )
    {
        b                = pBlob->pbData[i];
        pBlob->pbData[i] = pBlob->pbData[j];
        pBlob->pbData[j] = b;
    }
    (*env)->SetByteArrayRegion(env,serial,0,pBlob->cbData,pBlob->pbData);
    return serial;
}



void throwException(JNIEnv *env, const char *message)
{
    char szBuffer[1024];
    snprintf( szBuffer, sizeof(szBuffer), "%s (Windows Error Code 0x%x)", message, (int)GetLastError() );
    
    jclass e = (*env)->FindClass(env, "org/qyouti/winselfcert/WindowsCertificateException");
    if ( e == NULL )
        return;
    (*env)->ThrowNew(env, e, message);
}


// from https://stackoverflow.com/questions/48673289/how-to-calculate-subject-key-identifier-in-cng

HRESULT capiCreateKeyIdentifierFromPublicKey(
        JNIEnv *env, 
        const char* pszKeyContainerName, 
        const char* pszKeyProviderName, 
        DWORD dwProviderType,         
        DWORD dwKeySpec,
        CRYPT_DATA_BLOB *extdata) 
{
    HRESULT hr = S_OK;
    BOOL bResult = FALSE;
    PCERT_PUBLIC_KEY_INFO pCertInfo = NULL;
    DWORD cbCertInfo = 0;
    HCRYPTPROV hCryptProv = (HCRYPTPROV) NULL;
    CRYPT_DATA_BLOB outHash;

    outHash.pbData = NULL;
    outHash.cbData = 0;

    // Acquire key container
    // Try to create a new key container
    if (!CryptAcquireContextA(&hCryptProv, pszKeyContainerName, pszKeyProviderName, dwProviderType, 0 )) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to acquire context.");
        goto Cleanup;
    }


    /* STEP1: Extract public key. */
    bResult = CryptExportPublicKeyInfo(hCryptProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &cbCertInfo);
    if (!bResult) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to get the public key length.");
        goto Cleanup;
    }
    
    pCertInfo = (PCERT_PUBLIC_KEY_INFO) HeapAlloc(GetProcessHeap(), 0, cbCertInfo);
    if (NULL == pCertInfo) {
        hr = HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
        throwException(env,"Out of memory getting public key.");
        goto Cleanup;
    }
    
    bResult = CryptExportPublicKeyInfo(hCryptProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertInfo, &cbCertInfo);
    if (!bResult) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to get the public key.");
        goto Cleanup;
    }

    /* STEP2: Make hash. */
    bResult = CryptHashPublicKeyInfo((HCRYPTPROV_LEGACY) NULL, CALG_SHA1, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertInfo, NULL, &outHash.cbData);
    if (!bResult) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to get hash length.");
        goto Cleanup;
    }
    outHash.pbData = (BYTE*) HeapAlloc(GetProcessHeap(), 0, outHash.cbData);
    bResult = CryptHashPublicKeyInfo((HCRYPTPROV_LEGACY) NULL, CALG_SHA1, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertInfo, outHash.pbData, &outHash.cbData);
    if (!bResult) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to get hash.");
        goto Cleanup;
    }

    /*
    printf("\nHashed public key length %d\n", (int) outHash.cbData);
    for (DWORD i = 0; i < outHash.cbData; i++)
        printf("%2.2x ", (int) outHash.pbData[i]);
    printf("\n\n");
    */
    
    //encode subject key identifier extension
    if (!CryptEncodeObject(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            szOID_SUBJECT_KEY_IDENTIFIER,
            (void*) &outHash,
            NULL,
            &extdata->cbData
            )) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to get encoded hash length.");
        goto Cleanup;
    }
    extdata->pbData = (LPBYTE) LocalAlloc(0, extdata->cbData);
    if (!CryptEncodeObject(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            szOID_SUBJECT_KEY_IDENTIFIER,
            (void*) &outHash,
            extdata->pbData,
            &extdata->cbData
            )) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to get encoded hash.");
        goto Cleanup;
    }

Cleanup:
    if (!SUCCEEDED(hr) && NULL != extdata->pbData) {
        HeapFree(GetProcessHeap(), 0, extdata->pbData);
        extdata->pbData = NULL;
        extdata->cbData = 0;
    }
    if (NULL != outHash.pbData) {
        HeapFree(GetProcessHeap(), 0, outHash.pbData);
    }
    if (NULL != pCertInfo) {
        HeapFree(GetProcessHeap(), 0, pCertInfo);
        pCertInfo = 0;
    }
    if (hCryptProv) {
        CryptReleaseContext(hCryptProv, 0);
    }

    return hr;
}

HRESULT capiCreateKeyUsageExtension(JNIEnv *env, CRYPT_DATA_BLOB *extdata) {
    HRESULT hr = S_OK;
    BOOL bResult = FALSE;
    CRYPT_BIT_BLOB keyuse;
    BYTE keyusebits;
    keyusebits = CERT_KEY_ENCIPHERMENT_KEY_USAGE;
    keyuse.cbData = 1;
    keyuse.pbData = &keyusebits;
    keyuse.cUnusedBits = 0;

    //encode subject key identifier extension
    if (!CryptEncodeObject(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            szOID_KEY_USAGE,
            (void*) &keyuse,
            NULL,
            &extdata->cbData
            )) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to find length of encoded key usage blob.");
        goto Cleanup;
    }

    extdata->pbData = (LPBYTE) LocalAlloc(0, extdata->cbData);
    if (!CryptEncodeObject(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            szOID_KEY_USAGE,
            (void*) &keyuse,
            extdata->pbData,
            &extdata->cbData
            )) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        throwException(env,"Unable to encode key usage blob.");
        goto Cleanup;
    }

Cleanup:
    if (!SUCCEEDED(hr) && NULL != extdata->pbData) {
        HeapFree(GetProcessHeap(), 0, extdata->pbData);
        extdata->pbData = NULL;
        extdata->cbData = 0;
    }

    return hr;
}

jbyteArray MakeSelfSignedCertificate(
        JNIEnv *env, 
        const char* pszKeyCommonName, 
        const char* pszKeyContainerName,
        const char* pszKeyProviderName,
        DWORD dwProviderType,
        DWORD dwKeySpec,
        DWORD dwKeySize,
        DWORD dwKeyFlags
    ) 
{
    HCRYPTPROV hCryptProv = (HCRYPTPROV) NULL;
    HCRYPTKEY hKey = (HCRYPTKEY) NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BYTE *pbEncoded = NULL;
    HCERTSTORE hStore = NULL;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE) NULL;
    BOOL fCallerFreeProvOrNCryptKey = FALSE;
    LPCTSTR pszX500 = _T(pszKeyCommonName);
    DWORD cbEncoded = 0;
    CERT_NAME_BLOB SubjectIssuerBlob;
    CRYPT_KEY_PROV_INFO KeyProvInfo;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    SYSTEMTIME EndTime;
    BYTE propertybuffer[1024];
    DWORD propertylength;
    int r = 0;
    WCHAR * pwszContainerName = NULL;
    WCHAR * pwszProviderName = NULL;
    DWORD len;
    CERT_EXTENSION extensionarray[2];
    CERT_EXTENSIONS extensions;
    BYTE keyuse[] = {0x03, 0x02, 0x05, 0x20};
    jbyteArray serialNumber = NULL;

    // Try to create a new key container
    if (!CryptAcquireContextA(&hCryptProv, pszKeyContainerName, pszKeyProviderName, dwProviderType, CRYPT_NEWKEYSET /*| CRYPT_MACHINE_KEYSET*/)) {
        throwException(env,"Unable to acquire cryptographic provider context.");
        goto cleanupa;
    }


    // Generate new key pair
    //_tprintf(_T("CryptGenKey... "));
    if (!CryptGenKey(hCryptProv, dwKeySpec, (dwKeySize << 16) | dwKeyFlags, &hKey))
    {
        throwException(env,"Unable to generate key(s).");
        goto cleanupa;
    }

    r = 1;

    // Clean up  
cleanupa:
    {
        if (hKey) {
            CryptDestroyKey(hKey);
        }
        if (hCryptProv) {
            CryptReleaseContext(hCryptProv, 0);
        }
    }
    if (r == 0) return NULL;
    r = 0;



    extensions.cExtension = 2;
    extensions.rgExtension = extensionarray;
    extensionarray[0].pszObjId = szOID_SUBJECT_KEY_IDENTIFIER;
    extensionarray[0].fCritical = FALSE;
    if (capiCreateKeyIdentifierFromPublicKey(env,pszKeyContainerName, pszKeyProviderName, dwProviderType, dwKeySpec, &extensionarray[0].Value)) {
        throwException(env,"Unable to create key identifier\n");
        goto cleanupb;
    }
    extensionarray[1].pszObjId = szOID_KEY_USAGE;
    extensionarray[1].fCritical = TRUE;
    extensionarray[1].Value.cbData = sizeof (keyuse);
    extensionarray[1].Value.pbData = (BYTE*) & keyuse;




    // CREATE SELF-SIGNED CERTIFICATE AND ADD IT TO 'MY' STORE IN MACHINE PROFILE

    // Encode certificate Subject
    if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL)) {
        throwException(env,"Unable to find length of encoded certificate subject");
        goto cleanupb;
    }
    if (!(pbEncoded = (BYTE *) malloc(cbEncoded))) {
        throwException(env,"Out of memory for encoded certificate subject");
        goto cleanupb;
    }
    if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL)) {
        throwException(env,"Unable to encode certificate subject");
        goto cleanupb;
    }

    // Prepare certificate Subject for self-signed certificate
    memset(&SubjectIssuerBlob, 0, sizeof (SubjectIssuerBlob));
    SubjectIssuerBlob.cbData = cbEncoded;
    SubjectIssuerBlob.pbData = pbEncoded;

    // Convert to a wide char string
    len = strlen(pszKeyContainerName) + 1;
    pwszContainerName = malloc(len * sizeof (WCHAR));
    if (pwszContainerName == NULL) {
        throwException(env,"Out of memory for 16 bit encoded container name");
        goto cleanupb;
    }
    if (mbstowcs(pwszContainerName, pszKeyContainerName, len) == 0) {
        printf("Unable to convert container name to wide characters.");
        goto cleanupb;
    }
    pwszProviderName = NULL;
    if ( pszKeyProviderName != NULL )
    {
        len = strlen(pszKeyProviderName) + 1;
        pwszProviderName = malloc(len * sizeof (WCHAR));
        if (pwszProviderName == NULL) {
        throwException(env,"Out of memory for 16 bit encoded provider name");
            goto cleanupb;
        }
        if (mbstowcs(pwszProviderName, pszKeyProviderName, len) == 0) {
            printf("Unable to convert provider name to wide characters.");
            goto cleanupb;
        }
    }

    // Prepare key provider structure for self-signed certificate
    memset(&KeyProvInfo, 0, sizeof (KeyProvInfo));
    KeyProvInfo.pwszContainerName = pwszContainerName;
    KeyProvInfo.pwszProvName = pwszProviderName;
    KeyProvInfo.dwProvType = dwProviderType;
    KeyProvInfo.dwFlags = 0;
    KeyProvInfo.cProvParam = 0;
    KeyProvInfo.rgProvParam = NULL;
    KeyProvInfo.dwKeySpec = dwKeySpec;

    // Prepare algorithm structure for self-signed certificate
    memset(&SignatureAlgorithm, 0, sizeof (SignatureAlgorithm));
    SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
    // Prepare Expiration date for self-signed certificate
    GetSystemTime(&EndTime);
    EndTime.wYear += 5;


    // Create self-signed certificate
    pCertContext = CertCreateSelfSignCertificate((HCRYPTPROV_OR_NCRYPT_KEY_HANDLE) NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, 0, &EndTime, &extensions);
    if (!pCertContext) {
        // Error
        printf("Unable to create self signed certificate.");
        goto cleanupb;
    }

    // Open "My" cert store in machine profile
    hStore = CertOpenSystemStore(0, "My");
    if (!hStore) {
        printf("Unable to open certificate store.");
        goto cleanupb;
    }

    // Add self-signed cert to the store
    if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0)) {
        printf("Unable to add certficiate to store.");
        goto cleanupb;
    }

    serialNumber = convertSerialNumber( env, &pCertContext->pCertInfo->SerialNumber );
    
    // Clean up
cleanupb:
    {
        if (pwszContainerName)
            free(pwszContainerName);
        if (pwszProviderName)
            free(pwszProviderName);
        if (!pbEncoded)
            free(pbEncoded);
        if (hCryptProvOrNCryptKey)
            CryptReleaseContext(hCryptProvOrNCryptKey, 0);
        if (pCertContext)
            CertFreeCertificateContext(pCertContext);
        if (hStore)
            CertCloseStore(hStore, 0);
    }

    return serialNumber;
}

JNIEXPORT jbyteArray JNICALL Java_org_qyouti_winselfcert_WindowsCertificateGenerator_requestCAPISelfSignedCertificate(
        JNIEnv *env,
        jobject obj,
        jstring commonname,
        jstring containername,
        jstring providername,
        jint providertype,
        jboolean keyexchange,
        jint keybitsize,
        jint keyflags) {

    jbyteArray serialNumber = NULL;
    
    const char* pszKeyCommonName = NULL;
    const char* pszKeyContainerName = NULL; // UUID
    const char* pszProviderName = NULL; // UUID

    if (commonname == NULL) {
        throwException(env, "Common name cannot be null.");
        return NULL;
    }

    if (containername == NULL) {
        throwException(env, "Container name cannot be null.");
        return NULL;
    }

    if ((pszKeyCommonName = (*env)->GetStringUTFChars(env, commonname, NULL)) == NULL) {
        throwException(env, "Cannot convert string.");
        goto complete;
    }

    if ((pszKeyContainerName = (*env)->GetStringUTFChars(env, containername, NULL)) == NULL) {
        throwException(env, "Cannot convert string.");
        goto complete;
    }
    if (providername != NULL)
        if ((pszProviderName = (*env)->GetStringUTFChars(env, providername, NULL)) == NULL) {
            throwException(env, "Cannot convert string.");
            goto complete;
        }

    if (pszKeyContainerName && pszKeyCommonName) {
        serialNumber = MakeSelfSignedCertificate(
                            env,
                            pszKeyCommonName, 
                            pszKeyContainerName,
                            pszProviderName,
                            (DWORD)providertype,
                            (keyexchange == JNI_TRUE)?AT_KEYEXCHANGE:AT_SIGNATURE,
                            (DWORD)keybitsize,
                            (DWORD)keyflags
                );
    }

complete:
    if (pszKeyCommonName)
        (*env)->ReleaseStringUTFChars(env, commonname, pszKeyCommonName);
    if (pszKeyContainerName)
        (*env)->ReleaseStringUTFChars(env, containername, pszKeyContainerName);

return serialNumber;
}


