#!/usr/bin/env -S npx tsx
/**
 * Diagnostic script to verify that the REPO_SIGNING_KEY matches the DID document's atproto key.
 * 
 * Usage:
 *   REPO_SIGNING_KEY=<your-key> npx tsx scripts/verify-signing-key.ts
 *   
 * Or with wrangler secrets:
 *   npx wrangler secret list  # to see available secrets
 */

import { Secp256k1Keypair } from '@atproto/crypto';

const DID = process.env.PDS_DID || 'did:plc:35bdlgus7hihmup66o265nuy';
const PLC_DIRECTORY = 'https://plc.directory';

async function main() {
  console.log('=== Signing Key Verification Tool ===\n');

  // 1. Fetch DID document
  console.log(`Fetching DID document for: ${DID}`);
  const didDocResponse = await fetch(`${PLC_DIRECTORY}/${DID}`);
  if (!didDocResponse.ok) {
    console.error(`Failed to fetch DID document: ${didDocResponse.status}`);
    process.exit(1);
  }
  const didDoc = await didDocResponse.json() as any;

  // 2. Extract atproto verification method
  const atprotoMethod = didDoc.verificationMethod?.find(
    (vm: any) => vm.id?.endsWith('#atproto')
  );

  if (!atprotoMethod) {
    console.error('No #atproto verification method found in DID document');
    process.exit(1);
  }

  const plcPublicKey = atprotoMethod.publicKeyMultibase;
  console.log(`PLC atproto public key: ${plcPublicKey}`);

  // 3. Get local signing key
  const signingKey = process.env.REPO_SIGNING_KEY?.trim();
  if (!signingKey) {
    console.error('\nREPO_SIGNING_KEY environment variable not set.');
    console.log('\nTo test, run with:');
    console.log('  REPO_SIGNING_KEY=<your-64-char-hex-key> npx tsx scripts/verify-signing-key.ts');
    console.log('\nOr check your Cloudflare wrangler secrets.');
    process.exit(1);
  }

  // 4. Import the private key and derive public key
  let keypair: Secp256k1Keypair;
  try {
    if (/^[0-9a-fA-F]{64}$/.test(signingKey)) {
      console.log('Importing signing key from hex format...');
      keypair = await Secp256k1Keypair.import(signingKey);
    } else {
      console.log('Importing signing key from base64 format...');
      const bin = Buffer.from(signingKey, 'base64');
      keypair = await Secp256k1Keypair.import(bin);
    }
  } catch (error) {
    console.error('Failed to import signing key:', error);
    process.exit(1);
  }

  // 5. Get the did:key representation (multibase encoded public key)
  const didKey = keypair.did();
  // Extract the multibase part from did:key:z...
  const localPublicKey = didKey.replace('did:key:', '');
  
  console.log(`Local derived public key: ${localPublicKey}`);

  // 6. Compare
  console.log('\n=== Comparison ===');
  console.log(`PLC Document:  ${plcPublicKey}`);
  console.log(`Local Key:     ${localPublicKey}`);

  if (plcPublicKey === localPublicKey) {
    console.log('\n✅ SUCCESS: Keys match! Your REPO_SIGNING_KEY is correctly configured.');
    console.log('Service auth tokens signed by your PDS will be valid.');
  } else {
    console.log('\n❌ MISMATCH: Keys do not match!');
    console.log('\nThis means service auth tokens from your PDS will be rejected by external services');
    console.log('like video.bsky.app because the signature cannot be verified against your DID document.\n');
    console.log('Options to fix:');
    console.log('  1. Update REPO_SIGNING_KEY to match the key in your DID document');
    console.log('  2. Update your DID document with a new atproto key (requires PLC rotation)');
    console.log('  3. If you have the original private key from migration, use that');
    process.exit(1);
  }

  // 7. Additional info
  console.log('\n=== DID Document Summary ===');
  console.log(`DID: ${didDoc.id}`);
  console.log(`Handle: ${didDoc.alsoKnownAs?.[0] || 'not set'}`);
  console.log(`PDS Endpoint: ${didDoc.service?.find((s: any) => s.id === '#atproto_pds')?.serviceEndpoint || 'not set'}`);
}

main().catch(console.error);
