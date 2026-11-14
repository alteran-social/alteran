import { expect } from '@std/expect';
import { afterEach, describe, it } from './helpers/bdd';
import { applyPrivateBlobMigrations, disposePrivateBlobEnv, makePrivateBlobEnv } from './helpers/private-blob-env';

const DID = 'did:example:test';
const TYPE = 'com.example.notes';
const SPACE = `at://${DID}/space/${TYPE}/old`;

async function rejected(operation: () => Promise<unknown>) {
  let failed = false;
  try { await operation(); } catch { failed = true; }
  expect(failed).toBe(true);
}

describe('Space owner listing migration', () => {
  afterEach(disposePrivateBlobEnv);

  it('backfills known policy identities and quarantines ambiguous and malformed rows', async () => {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    await database.prepare('INSERT INTO account (did, handle, created_at, updated_at) VALUES (?, ?, 1, 1)')
      .bind(DID, 'test.example').run();
    await database.prepare('INSERT INTO account_state (did, active, created_at) VALUES (?, 1, 1)').bind(DID).run();
    const account = await database.prepare('SELECT space_incarnation FROM account WHERE did = ?')
      .bind(DID).first<{ space_incarnation: string }>();
    if (!account) throw new Error('Missing account');
    const nonce = crypto.randomUUID();
    await database.batch([
      database.prepare(`INSERT INTO space_personal_creation_attempt
        (nonce,space_ref,authority_did,space_type,skey,created_at,authority_incarnation) VALUES (?, ?, ?, ?, ?, 1, ?)`)
        .bind(nonce, SPACE, DID, TYPE, 'old', account.space_incarnation),
      database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
        .bind(SPACE, DID, TYPE, 'old'),
      database.prepare(`INSERT INTO space_personal_policy
        (space_ref,authority_did,authority_incarnation,policy_type,creation_nonce,notification_state,created_at)
        VALUES (?,?,?,'com.atproto.personalspace.policy',?,'none',1)`).bind(SPACE, DID, account.space_incarnation, nonce),
      database.prepare('DELETE FROM space_personal_creation_attempt WHERE nonce = ?').bind(nonce),
      database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
        .bind(`at://${DID}/space/${TYPE}/legacy`, DID, TYPE, 'legacy'),
      database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
        .bind('malformed-space-ref', 'invalid authority', TYPE, 'x'),
    ]);
    await applyPrivateBlobMigrations(database, 44, 44);
    const listing = await database.prepare('SELECT space_ref, authority_did, authority_incarnation, space_type FROM space_owner_listing').all();
    expect(listing.results).toEqual([{ space_ref: SPACE, authority_did: DID,
      authority_incarnation: account.space_incarnation, space_type: TYPE }]);
    const markers = await database.prepare('SELECT authority_did, space_type FROM space_owner_unclassified ORDER BY authority_did').all();
    expect(markers.results).toEqual([{ authority_did: DID, space_type: TYPE }]);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_quarantine_global').first())?.n).toBe(1);
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_classification').first())?.n).toBe(3);
  });

  it('rolls back catalog installation if an unexpected trigger conflicts', async () => {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    await database.exec('CREATE TRIGGER space_owner_listing_insert BEFORE INSERT ON space BEGIN SELECT 1; END');
    await rejected(() => applyPrivateBlobMigrations(database, 44, 44));
    expect((await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'space_owner_listing'").first())?.n).toBe(0);
    expect((await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'space_owner_classification'").first())?.n).toBe(0);
  });

  it('refuses orphan policies and malformed tombstones before installing a catalog', async () => {
    const orphan = await makePrivateBlobEnv(43), database = orphan.ALTERAN_DB;
    await database.exec('DROP TRIGGER space_personal_policy_insert');
    await database.exec('DROP TRIGGER space_personal_policy_owner_insert');
    await database.prepare(`INSERT INTO space_personal_policy
      (space_ref,authority_did,policy_type,creation_nonce,notification_state,created_at)
      VALUES (?, ?, 'com.atproto.personalspace.policy', ?, 'none', 1)`)
      .bind(SPACE, DID, crypto.randomUUID()).run();
    await rejected(() => applyPrivateBlobMigrations(database, 44, 44));
    expect((await database.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'space_owner_listing'").first())?.n).toBe(0);
    const malformed = await makePrivateBlobEnv(43), second = malformed.ALTERAN_DB;
    await second.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at,deleted_at) VALUES (?, ?, ?, ?, 1, ?)')
      .bind(SPACE, DID, TYPE, 'old', 'not-a-time').run();
    await rejected(() => applyPrivateBlobMigrations(second, 44, 44));
    expect((await second.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'space_owner_listing'").first())?.n).toBe(0);
  });

  it('quarantines a valid reference with a conflicting policy authority globally', async () => {
    const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
    await database.exec('DROP TRIGGER space_personal_policy_insert');
    await database.exec('DROP TRIGGER space_personal_policy_owner_insert');
    await database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
      .bind(SPACE, DID, TYPE, 'old').run();
    await database.prepare(`INSERT INTO space_personal_policy
      (space_ref,authority_did,authority_incarnation,policy_type,creation_nonce,notification_state,created_at)
      VALUES (?,? ,?,'com.atproto.personalspace.policy',?,'none',1)`)
      .bind(SPACE, 'did:example:other', 'a'.repeat(32), crypto.randomUUID()).run();
    await applyPrivateBlobMigrations(database, 44, 44);
    expect(await database.prepare('SELECT space_ref, authority_did, space_type FROM space_owner_unclassified').first())
      .toEqual({ space_ref: SPACE, authority_did: '', space_type: TYPE });
    expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_listing').first())?.n).toBe(0);
  });

  it('classifies old direct insertions on either side of the migration', async () => {
    for (const insertion of ['before', 'after'] as const) {
      const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
      await database.prepare('INSERT INTO account (did, handle, created_at, updated_at) VALUES (?, ?, 1, 1)')
        .bind(DID, `${insertion}.example`).run();
      await database.prepare('INSERT INTO account_state (did, active, created_at) VALUES (?, 1, 1)').bind(DID).run();
      const account = await database.prepare('SELECT space_incarnation FROM account WHERE did = ?')
        .bind(DID).first<{ space_incarnation: string }>();
      if (!account) throw new Error('Missing account');
      const legacy = `at://${DID}/space/${TYPE}/${insertion}-legacy`;
      const personal = `at://${DID}/space/${TYPE}/${insertion}-personal`;
      const insertLegacy = () => database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
        .bind(legacy, DID, TYPE, `${insertion}-legacy`).run();
      const insertPersonal = async () => {
        const nonce = crypto.randomUUID();
        await database.batch([
          database.prepare(`INSERT INTO space_personal_creation_attempt
            (nonce,space_ref,authority_did,space_type,skey,created_at,authority_incarnation) VALUES (?,?,?,?,?,1,?)`)
            .bind(nonce, personal, DID, TYPE, `${insertion}-personal`, account.space_incarnation),
          database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
            .bind(personal, DID, TYPE, `${insertion}-personal`),
          database.prepare(`INSERT INTO space_personal_policy
            (space_ref,authority_did,authority_incarnation,policy_type,creation_nonce,notification_state,created_at)
            VALUES (?,?,?,'com.atproto.personalspace.policy',?,'none',1)`).bind(personal, DID, account.space_incarnation, nonce),
          database.prepare('DELETE FROM space_personal_creation_attempt WHERE nonce = ?').bind(nonce),
        ]);
      };
      if (insertion === 'before') { await insertLegacy(); await insertPersonal(); }
      await applyPrivateBlobMigrations(database, 44, 44);
      if (insertion === 'after') { await insertLegacy(); await insertPersonal(); }
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified WHERE space_ref = ?').bind(legacy).first())?.n).toBe(1);
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_listing WHERE space_ref = ?').bind(personal).first())?.n).toBe(1);
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified WHERE space_ref = ?').bind(personal).first())?.n).toBe(0);
    }
  });

  it('serializes an old direct insertion with the migration batch', async () => {
    for (let iteration = 0; iteration < 3; iteration++) {
      const env = await makePrivateBlobEnv(43), database = env.ALTERAN_DB;
      const legacy = `at://${DID}/space/${TYPE}/concurrent-${iteration}`;
      await Promise.all([
        applyPrivateBlobMigrations(database, 44, 44),
        database.prepare('INSERT INTO space (space_ref,authority_did,space_type,skey,created_at) VALUES (?,?,?,?,1)')
          .bind(legacy, DID, TYPE, `concurrent-${iteration}`).run(),
      ]);
      expect((await database.prepare('SELECT COUNT(*) AS n FROM space_owner_unclassified WHERE space_ref = ?')
        .bind(legacy).first())?.n).toBe(1);
    }
  });
});
