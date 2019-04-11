export class OsxKeychainKey {
    constructor(useSecureEnclave?: boolean)
    generate(): void;
    getPublicKey(): Buffer;
    sign(digest: Buffer): Buffer;
}
