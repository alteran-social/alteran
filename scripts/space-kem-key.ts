#!/usr/bin/env -S deno run --allow-read --allow-write --allow-sys=uid
import { createSpaceKemFile, readSpaceKemPublicKey } from './space-kem-files';

if (import.meta.main) {
  const [action, destination, ...extra] = Deno.args;
  if ((action !== 'create' && action !== 'public') || !destination || extra.length) {
    console.error('Usage: deno run --allow-read --allow-write --allow-sys=uid scripts/space-kem-key.ts <create|public> <private-file>');
    Deno.exit(1);
  }
  try {
    const publicKey = action === 'create'
      ? await createSpaceKemFile(destination)
      : await readSpaceKemPublicKey(destination);
    console.log(publicKey);
  } catch {
    console.error('Key operation failed. Inspect any existing file; do not overwrite or regenerate it automatically.');
    Deno.exit(1);
  }
}
