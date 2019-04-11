import {OsxKeychainKey} from './index';
import * as assert from 'assert';
import {createHash, createVerify} from 'crypto';
import {describe, it} from 'mocha';

function keyToPem(publicKey) {
    return "-----BEGIN PUBLIC KEY-----\n" + Buffer.from(publicKey).toString('base64') + "\n-----END PUBLIC KEY-----\n";
}

const payload = Buffer.from('Hello, World!', 'utf8');
let digest = createHash('sha256').update(payload).digest();

describe('OsxKeychainKey Class', () => {

    it('Invalid states should throw appropriately', () => {
        let key = new OsxKeychainKey();
        key.generate();
        assert.throws(() => {
            // @ts-ignore: Intentionally call with the wrong number of arguments to verify behavior
            key.sign()
        });
        assert.throws(() => {
            // @ts-ignore: Intentionally call with wrong type of argument to verify behavior
            key.sign("foo");
        });

        // A call to sign before generating should throw.
        assert.throws(() => new OsxKeychainKey().sign(digest));
    });

    it('getPublicKey before generating returns undefined', () => {
        let key = new OsxKeychainKey();
        assert.ok(!key.getPublicKey());
        key.generate();
        assert.ok(key.getPublicKey());
    });

    it('Sign then verify should work', () => {
        let key = new OsxKeychainKey();
        key.generate();
        let sig = key.sign(digest);
        assert.ok(sig);

        const verify = createVerify('SHA256');
        verify.write(payload);
        assert.ok(verify.verify(keyToPem(key.getPublicKey()), sig));
    });

    it('Sign then verify with secure enclave should work', () => {
        let key = new OsxKeychainKey(true);
        key.generate();
        let sig = key.sign(digest);
        assert.ok(sig);

        const verify = createVerify('SHA256');
        verify.write(payload);
        assert.ok(verify.verify(keyToPem(key.getPublicKey()), sig));
    });

    it('Invalid constructor calls should throw', () => {
        // @ts-ignore Intentionally invalid constructor args
        assert.throws(() => new OsxKeychainKey(1));
    });

});
