{
  "targets": [
    {
      "target_name": "osxkeychainkey",
      "sources": [ "module.cc", "osx_keychain_key.cc", "keychain.cc" ],
      "cflags": ["-Wall"],
      "libraries": ["-framework CoreFoundation", "-framework Security"]
    }
  ]
}
