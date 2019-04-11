#ifndef TEST_ADDONS_NAPI_6_OBJECT_WRAP_KEYCHAIN_H_
#define TEST_ADDONS_NAPI_6_OBJECT_WRAP_KEYCHAIN_H_

#include <Security/Security.h>

void keychainGenerate(bool useSecureEnclave, SecKeyRef *publicKey, SecKeyRef *privateKey);
void keychainExportPublicKey(SecKeyRef publicKey, uint8_t** outPublicKey, size_t* outLength);
void keychainSign(uint8_t* digest, size_t digestLength, SecKeyRef privateKey, uint8_t** outSignature, size_t* outLength);

#endif // TEST_ADDONS_NAPI_6_OBJECT_WRAP_KEYCHAIN_H_
