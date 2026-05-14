import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import * as Did from '../src/pages/.well-known/did.json.ts';

function b64(u8: Uint8Array): string {
  let s = '';
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s);
}

describe('did.json exposes publicKeyMultibase when REPO_SIGNING_KEY is provided', () => {
  it('includes multibase key', async () => {
    // 32-byte secp256k1 private key (hex, not a real key)
    const privHex = '8b5e3d226b44c4c88fbd3d4529f6283fb2b20f6deee8a0b34e7f0a9b12d3e4f1';
    const env: any = {
      PDS_DID: 'did:web:example.com',
      PDS_HANDLE: 'user.example.com',
      REPO_SIGNING_KEY: privHex,
    };
    const req = new Request('http://localhost/.well-known/did.json');
    const res = await (Did as any).GET({ locals: { runtime: { env } }, request: req });
    expect(res.status).toBe(200);
    const json = await res.json();
    const vm = (json.verificationMethod || [])[0];
    expect(vm).toBeTruthy();
    expect(typeof vm.publicKeyMultibase).toBe('string');
    expect(vm.publicKeyMultibase.length).toBeGreaterThan(10);
  });
});
