import { expect } from '@std/expect';
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto-spaces';
import { createOp, createUpdateOp } from '@did-plc/lib';
import { planKemPlcUpdate } from '../src/lib/spaces/kem-plc-plan';
import { planKemPlcFromLineage } from '../src/lib/spaces/kem-plc-lineage';

const configuredOrigin = Deno.env.get('ALTERAN_REFERENCE_PLC_ORIGIN');

Deno.test({
  name: 'unsigned KEM planning retains a stale head across local PLC recovery',
  ignore: !configuredOrigin,
  sanitizeOps: false,
  sanitizeResources: false,
  async fn() {
    try {
      if (!configuredOrigin) throw new Error();
      const origin = loopbackOrigin(configuredOrigin);
      const signing = await Secp256k1Keypair.create();
      const recovery = await Secp256k1Keypair.create();
      const kem = await P256Keypair.create();
      const genesis = await createOp({ signingKey: signing.did(), rotationKeys: [recovery.did(), signing.did()],
        handle: 'local-planner.test', pds: 'https://pds.example', signer: signing });
      const post = async (operation: unknown) => {
        const response = await fetch(`${origin}/${genesis.did}`, {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(operation),
          redirect: 'manual', signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw new Error();
        await response.body?.cancel();
      };
      const audit = async () => {
        const response = await fetch(`${origin}/${genesis.did}/log/audit`, {
          redirect: 'manual', signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw new Error();
        const entries: unknown = await response.json();
        if (!Array.isArray(entries)) throw new Error();
        return entries as { operation?: unknown; cid?: unknown; nullified?: unknown }[];
      };
      const plan = (head: unknown) => planKemPlcUpdate(JSON.stringify(head), genesis.did,
        '1234567890abcdef1234567890abcdef', true, 'https://pds.example', signing.did(), signing.did(), kem.did());
      const linked = (...operations: unknown[]) => planKemPlcFromLineage(operations.map((op) => JSON.stringify(op)),
        genesis.did, '1234567890abcdef1234567890abcdef', true, 'https://pds.example',
        signing.did(), signing.did(), kem.did());
      await post(genesis.op);
      const initial = await audit();
      if (initial.length !== 1 || JSON.stringify(initial[0].operation) !== JSON.stringify(genesis.op)) throw new Error();
      const initialPlan = plan(initial[0].operation);
      if (initialPlan.tag !== 'proposed') throw new Error();
      expect(initialPlan.context.headCid === initial[0].cid).toBe(true);

      const update = await createUpdateOp(genesis.op, signing, (current) => ({
        ...current, alsoKnownAs: ['at://updated.local-planner.test'],
      }));
      await post(update);
      const afterUpdate = await audit();
      if (afterUpdate.length !== 2 || afterUpdate[1].nullified !== false) throw new Error();
      const updatePlan = plan(afterUpdate[1].operation);
      if (updatePlan.tag !== 'proposed') throw new Error();
      expect(updatePlan.context.headCid === afterUpdate[1].cid).toBe(true);
      expect(initialPlan.context.headCid === updatePlan.context.headCid).toBe(false);
      expect(plan(initial[0].operation)).toEqual(initialPlan);

      const fork = await createUpdateOp(genesis.op, recovery, (current) => ({
        ...current, alsoKnownAs: ['at://recovered.local-planner.test'],
      }));
      await post(fork);
      const afterRecovery = await audit();
      if (afterRecovery.length !== 3 || afterRecovery[1].nullified !== true || afterRecovery[2].nullified !== false) {
        throw new Error();
      }
      const recovered = plan(afterRecovery[2].operation);
      if (recovered.tag !== 'proposed') throw new Error();
      expect(recovered.context.headCid === afterRecovery[2].cid).toBe(true);
      expect(updatePlan.context.headCid === recovered.context.headCid).toBe(false);
      expect(plan(afterUpdate[1].operation)).toEqual(updatePlan);
      const staleLink = await linked(initial[0].operation, afterUpdate[1].operation);
      const recoveredLink = await linked(initial[0].operation, afterRecovery[2].operation);
      expect(staleLink.tag).toBe('signatureLinked');
      expect(recoveredLink.tag).toBe('signatureLinked');
      if (staleLink.tag !== 'signatureLinked' || recoveredLink.tag !== 'signatureLinked') throw new Error();
      expect(staleLink.plan).toEqual(updatePlan);
      expect(recoveredLink.plan).toEqual(recovered);
    } catch {
      throw new Error('Disposable PLC planner comparison failed');
    }
  },
});

function loopbackOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error();
  return url.origin;
}
