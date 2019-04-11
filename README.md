OSX Keychain Keys
=================

This NPM module provides access to ephemeral OSX keychain keys. In particular this allows you to create keys inside the secure enclave of newer macbooks and mac minis.

This library does not currently support persistent keys or any other keychain features. I made it to do just enough for my purposes. Feel free to submit PRs, though!

Installation
============

```bash
npm install osx-keychain-key
```

Usage
=====

```typescript
import {OsxKeychainKey} from 'osx-keychain-key';
import {createHash} from 'crypto';

// Create a key object backed by the secure enclave
let key = new OsxKeychainKey(true);
// Actually generate the underlying key material
key.generate();
// Get the public key in PKIX/DER format
console.log(Buffer.from(key.getPublicKey()).toString('base64'));

// Sign a digest
let sig = key.sign(createHash('sha256').update("Hello, World!").digest());
console.log(Buffer.from(sig).toString('base64'));

const verify = createVerify('SHA256');
verify.write(payload);
let result = verify.verify(keyToPem(key.getPublicKey()), sig);
console.log("Verification result: " + result);
```

