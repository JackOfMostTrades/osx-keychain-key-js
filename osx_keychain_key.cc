#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "osx_keychain_key.h"
#include "keychain.h"

napi_ref OsxKeychainKey::constructor;

OsxKeychainKey::OsxKeychainKey(bool useSecureEnclave) {
    this->useSecureEnclave = useSecureEnclave;
    this->publicKey = nullptr;
    this->privateKey = nullptr;
    this->env_ = nullptr;
    this->wrapper_ = nullptr;
}

OsxKeychainKey::~OsxKeychainKey() {
    if (this->publicKey != nullptr) {
        CFRelease(this->publicKey);
    }
    if (this->privateKey != nullptr) {
        CFRelease(this->privateKey);
    }

    napi_delete_reference(env_, wrapper_);
}

void OsxKeychainKey::Destructor(napi_env env, void* nativeObject, void* /*finalize_hint*/) {
  reinterpret_cast<OsxKeychainKey*>(nativeObject)->~OsxKeychainKey();
}

#define DECLARE_NAPI_METHOD(name, func)                          \
  { name, 0, func, 0, 0, 0, napi_default, 0 }

napi_value OsxKeychainKey::Init(napi_env env, napi_value exports) {
  napi_status status;
  napi_property_descriptor properties[] = {
      DECLARE_NAPI_METHOD("generate", Generate),
      DECLARE_NAPI_METHOD("getPublicKey", GetPublicKey),
      DECLARE_NAPI_METHOD("sign", Sign),
  };

  napi_value cons;
  status = napi_define_class(env, "OsxKeychainKey", NAPI_AUTO_LENGTH, New, nullptr, 3, properties, &cons);
  assert(status == napi_ok);

  status = napi_create_reference(env, cons, 1, &constructor);
  assert(status == napi_ok);

  status = napi_set_named_property(env, exports, "OsxKeychainKey", cons);
  assert(status == napi_ok);
  return exports;
}

napi_value OsxKeychainKey::New(napi_env env, napi_callback_info info) {
  napi_status status;

  napi_value target;
  status = napi_get_new_target(env, info, &target);
  assert(status == napi_ok);
  bool is_constructor = target != nullptr;

  if (is_constructor) {
    // Invoked as constructor: `new OsxKeychainKey(...)`
    size_t argc = 1;
    napi_value args[1];
    napi_value jsthis;
    status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
    assert(status == napi_ok);

    bool useSecureEnclave = false;
    if (argc >= 1) {
        napi_valuetype valuetype;
        status = napi_typeof(env, args[0], &valuetype);
        assert(status == napi_ok);

        if (valuetype != napi_undefined && valuetype != napi_boolean) {
          napi_throw_error(env, nullptr, "First argument to constructor must be undefined or a boolean.");
          return jsthis;
        }
        if (valuetype == napi_boolean) {
          status = napi_get_value_bool(env, args[0], &useSecureEnclave);
          assert(status == napi_ok);
        }
    }

    OsxKeychainKey* obj = new OsxKeychainKey(useSecureEnclave);

    obj->env_ = env;
    status = napi_wrap(env,
                       jsthis,
                       reinterpret_cast<void*>(obj),
                       OsxKeychainKey::Destructor,
                       nullptr,  // finalize_hint
                       &obj->wrapper_);
    assert(status == napi_ok);

    return jsthis;
  } else {
    // Invoked as plain function `OsxKeychainKey(...)`, turn into construct call.
    size_t argc_ = 1;
    napi_value args[1];
    status = napi_get_cb_info(env, info, &argc_, args, nullptr, nullptr);
    assert(status == napi_ok);

    const size_t argc = 1;
    napi_value argv[argc] = {args[0]};

    napi_value cons;
    status = napi_get_reference_value(env, constructor, &cons);
    assert(status == napi_ok);

    napi_value instance;
    status = napi_new_instance(env, cons, argc, argv, &instance);
    assert(status == napi_ok);

    return instance;
  }
}

napi_value OsxKeychainKey::GetPublicKey(napi_env env, napi_callback_info info) {
  napi_status status;

  napi_value jsthis;
  status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
  assert(status == napi_ok);

  OsxKeychainKey* obj;
  status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&obj));
  assert(status == napi_ok);

  if (obj->publicKey == nullptr) {
    napi_value result;
    napi_get_undefined(env, &result);
    assert(status == napi_ok);
    return result;
  }

  uint8_t* exportedKey;
  size_t exportedKeyLength;
  keychainExportPublicKey(obj->publicKey, &exportedKey, &exportedKeyLength);
  if (exportedKey == nullptr) {
    napi_throw_error(env, nullptr, "Underlying keychain error when trying to export public key.");
    napi_value result;
    napi_get_undefined(env, &result);
    assert(status == napi_ok);
    return result;
  }

  void* arraybuffer_data;
  napi_value arraybuffer_result;
  status = napi_create_arraybuffer(env, exportedKeyLength, &arraybuffer_data, &arraybuffer_result);
  assert(status == napi_ok);

  memcpy(arraybuffer_data, exportedKey, exportedKeyLength);
  free(exportedKey);

  napi_value typedarray_result;
  status = napi_create_typedarray(env, napi_uint8_array, exportedKeyLength,
    arraybuffer_result, 0, &typedarray_result);
  assert(status == napi_ok);

  return typedarray_result;
}

napi_value OsxKeychainKey::Generate(napi_env env, napi_callback_info info) {
  napi_status status;

  napi_value jsthis;
  status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
  assert(status == napi_ok);

  OsxKeychainKey* obj;
  status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&obj));
  assert(status == napi_ok);

  if (obj->publicKey != nullptr) {
    CFRelease(obj->publicKey);
  }
  if (obj->privateKey != nullptr) {
    CFRelease(obj->privateKey);
  }
  keychainGenerate(obj->useSecureEnclave, &obj->publicKey, &obj->privateKey);
  if (obj->privateKey == nullptr || obj->publicKey == nullptr) {
    napi_throw_error(env, nullptr, "Unable to generate keychain key.");
  }

  napi_value result;
  napi_get_undefined(env, &result);
  assert(status == napi_ok);
  return result;
}

napi_value OsxKeychainKey::Sign(napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 1;
  napi_value args[1];
  napi_value jsthis;
  status = napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);
  assert(status == napi_ok);

  OsxKeychainKey* obj;
  status = napi_unwrap(env, jsthis, reinterpret_cast<void**>(&obj));
  assert(status == napi_ok);

  if (obj->privateKey == nullptr || obj->publicKey == nullptr) {
      napi_throw_error(env, nullptr, "Key must have been generated before signature can be called.");

      napi_value result;
      napi_get_undefined(env, &result);
      assert(status == napi_ok);
      return result;
  }

  bool is_typedarray;
  status = napi_is_typedarray(env, args[0], &is_typedarray);
  assert(status == napi_ok);

  if (!is_typedarray) {
    napi_throw_error(env, nullptr, "Digest must be provided to sign() method.");

    napi_value result;
    napi_get_undefined(env, &result);
    assert(status == napi_ok);
    return result;
  }

  size_t digestLength;
  void* digestData;
  status = napi_get_typedarray_info(env, args[0], nullptr, &digestLength,
    &digestData, nullptr, nullptr);
  assert(status == napi_ok);

  uint8_t* signature;
  size_t signatureLength;
  keychainSign((uint8_t*)digestData, digestLength, obj->privateKey, &signature, &signatureLength);
  if (signature == nullptr) {
    napi_throw_error(env, nullptr, "Underlying signature call failed.");

    napi_value result;
    napi_get_undefined(env, &result);
    assert(status == napi_ok);
    return result;
  }

  void* result;
  napi_value arraybuffer_result;
  status = napi_create_arraybuffer(env, signatureLength, &result, &arraybuffer_result);
  assert(status == napi_ok);

  memcpy(result, signature, signatureLength);
  free(signature);

  napi_value typedarray_result;
  status = napi_create_typedarray(env, napi_uint8_array, signatureLength,
    arraybuffer_result, 0, &typedarray_result);
  assert(status == napi_ok);

  return typedarray_result;
}
