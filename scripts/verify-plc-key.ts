#!/usr/bin/env -S deno run -A
/**
 * Verify that a secp256k1 private key corresponds to the current PLC atproto key.
 * Usage:
 *   bun scripts/verify-plc-key.ts <did:plc:...> <hex-private-key>
 */
import { Secp256k1Keypair } from '@atproto/crypto'

function hexToU8(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]{64}$/.test(clean)) throw new Error('Expected 32-byte hex private key')
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

const did = process.argv[2]
const hex = process.argv[3]
if (!did || !hex) {
  console.error('Usage: bun scripts/verify-plc-key.ts <did:plc:...> <hex-private-key>')
  process.exit(1)
}

const priv = hexToU8(hex)
const kp = await Secp256k1Keypair.import(priv)
const didKey = kp.did() // did:key:z...
const multibase = didKey.startsWith('did:key:') ? didKey.slice('did:key:'.length) : didKey

const res = await fetch(`https://plc.directory/${encodeURIComponent(did)}`)
if (!res.ok) {
  console.error('Failed to fetch PLC doc:', res.status, res.statusText)
  process.exit(2)
}
const doc: any = await res.json()
const vm = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []
const plcKeys = vm
  .filter((v: any) => typeof v?.publicKeyMultibase === 'string')
  .map((v: any) => v.publicKeyMultibase)

const matches = plcKeys.includes(multibase)
console.log(JSON.stringify({ did, didKey, publicKeyMultibase: multibase, plcKeys, matches }, null, 2))

process.exit(matches ? 0 : 3)
