#!/usr/bin/env -S deno run -A
/**
 * Derive did:key and PLC publicKeyMultibase (Multikey) from a secp256k1 private key (hex).
 * Usage:
 *   bun scripts/derive-public-key.ts <hex-private-key>
 */
import { Secp256k1Keypair } from '@atproto/crypto'

function hexToU8(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]{64}$/.test(clean)) throw new Error('Expected 32-byte hex private key')
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

const hex = process.argv[2] || ''
if (!hex) {
  console.error('Usage: bun scripts/derive-public-key.ts <hex-private-key>')
  process.exit(1)
}

const priv = hexToU8(hex)
const kp = await Secp256k1Keypair.import(priv)
const didKey = kp.did() // did:key:z...
// PLC "publicKeyMultibase" is the multibase portion of did:key (strip the did:key: prefix)
const publicKeyMultibase = didKey.startsWith('did:key:') ? didKey.slice('did:key:'.length) : didKey

console.log(JSON.stringify({ didKey, publicKeyMultibase }, null, 2))
