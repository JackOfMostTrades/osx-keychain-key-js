export class OsxKeychainKey {
    constructor(useSecureEnclave?: boolean)
    generate(): void;
    getPublicKey(): Uint8Array;
    sign(digest: Uint8Array): Uint8Array;
}
