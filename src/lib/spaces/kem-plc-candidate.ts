import * as dagCbor from '@ipld/dag-cbor';
import type { PlcOperation } from './kem-plc-operation';

// Conservative incoming constraints from the current PLC server source.
const MAX_SIGNED_BYTES = 4_000;

export function incomingCandidateError(operation: PlcOperation): 'serverLimit' | 'tooLarge' | null {
  const methods = Object.entries(operation.verificationMethods);
  const services = Object.entries(operation.services);
  const aliases = operation.alsoKnownAs;
  if (methods.length > 10 || methods.some(([id, key]) => id.length > 32 || key.length > 256) ||
    services.length > 10 || services.some(([id, service]) =>
      id.length > 32 || service.type.length > 256 || service.endpoint.length > 512) ||
    aliases.length > 10 || new Set(aliases).size !== aliases.length || aliases.some((alias) => alias.length > 258) ||
    operation.rotationKeys.length > 10 || operation.rotationKeys.some((key) => key.length > 256)) {
    return 'serverLimit';
  }
  // A compact 64-byte signature is always 86 unpadded base64url characters.
  const signedBytes = dagCbor.encode({ ...operation, sig: 'A'.repeat(86) });
  return signedBytes.byteLength > MAX_SIGNED_BYTES ? 'tooLarge' : null;
}
