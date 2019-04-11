#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

void keychainGenerate(bool useSecureEnclave, SecKeyRef *publicKey, SecKeyRef *privateKey) {
	OSStatus rc;
	CFErrorRef err = NULL;
	SecAccessControlRef access = NULL;
	CFMutableDictionaryRef params = NULL;
	CFNumberRef number;
	int keySize = 256;
	CFMutableDictionaryRef privateKeyAttrs = NULL;

	// Initial output with NULL values to indicate error if we exit early.
	*publicKey = NULL;
	*privateKey = NULL;

	access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		kSecAttrAccessibleAlwaysThisDeviceOnly,
		kSecAccessControlPrivateKeyUsage,
		&err);
	if (err != NULL) {
		return;
	}

	params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keySize);
	CFDictionarySetValue(params, kSecAttrKeySizeInBits, number);
	CFRelease(number);
	if (useSecureEnclave) {
	    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    }

	privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(privateKeyAttrs, kSecAttrIsPermanent, kCFBooleanFalse);
	CFDictionarySetValue(privateKeyAttrs, kSecAttrAccessControl, access);
	CFDictionarySetValue(params, kSecPrivateKeyAttrs, privateKeyAttrs);
	CFRelease(privateKeyAttrs);

	rc = SecKeyGeneratePair(params, publicKey, privateKey);
	if (rc != errSecSuccess) {
	    *publicKey = NULL;
	    *privateKey = NULL;
	}

	CFRelease(access);
	CFRelease(params);
}

void keychainExportPublicKey(SecKeyRef publicKey, uint8_t** outPublicKey, size_t* outLength) {
    CFDataRef exportedPublicKey;
    OSStatus rc;

    rc = SecItemExport((CFTypeRef)publicKey, kSecFormatOpenSSL, 0, NULL, &exportedPublicKey);
    if (rc != errSecSuccess) {
        *outPublicKey = NULL;
        return;
    }

	*outLength = CFDataGetLength(exportedPublicKey);
	*outPublicKey = (uint8_t*)malloc(*outLength);
	if (*outPublicKey != NULL) {
	    memcpy(*outPublicKey, CFDataGetBytePtr(exportedPublicKey), *outLength);
	}
	CFRelease(exportedPublicKey);
}

void keychainSign(uint8_t* digest, size_t digestLength, SecKeyRef privateKey, uint8_t** outSignature, size_t* outLength) {

    CFErrorRef err;
    CFDataRef signature;
    CFDataRef cfDigest;

    cfDigest = CFDataCreate(kCFAllocatorDefault, digest, digestLength);
    if (cfDigest == NULL) {
        *outSignature = NULL;
        return;
    }

	signature = SecKeyCreateSignature(privateKey, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, cfDigest, &err);
	CFRelease(cfDigest);
	if (signature == NULL) {
	    *outSignature = NULL;
		return;
	}

    *outLength = CFDataGetLength(signature);
    *outSignature = (uint8_t*)malloc(*outLength);
    if (*outSignature != NULL) {
        memcpy(*outSignature, CFDataGetBytePtr(signature), *outLength);
    }
	CFRelease(signature);
}
