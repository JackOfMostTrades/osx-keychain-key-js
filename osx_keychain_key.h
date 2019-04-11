#ifndef TEST_ADDONS_NAPI_6_OBJECT_WRAP_MYOBJECT_H_
#define TEST_ADDONS_NAPI_6_OBJECT_WRAP_MYOBJECT_H_

#include <node_api.h>
#include <Security/Security.h>

class OsxKeychainKey {
 public:
  static napi_value Init(napi_env env, napi_value exports);
  static void Destructor(napi_env env, void* nativeObject, void* finalize_hint);

 private:
  explicit OsxKeychainKey(bool useSecureEnclave);
  ~OsxKeychainKey();

  static napi_value New(napi_env env, napi_callback_info info);
  static napi_value Generate(napi_env env, napi_callback_info info);
  static napi_value GetPublicKey(napi_env env, napi_callback_info info);
  static napi_value Sign(napi_env env, napi_callback_info info);

  static napi_ref constructor;

  bool useSecureEnclave;
  SecKeyRef publicKey;
  SecKeyRef privateKey;
  napi_env env_;
  napi_ref wrapper_;
};

#endif  // TEST_ADDONS_NAPI_6_OBJECT_WRAP_MYOBJECT_H_
