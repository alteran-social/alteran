import type { D1Database } from '@cloudflare/workers-types';

/** Build a previously bound quarantined epoch in a disposable verifier fixture. */
export async function bindQuarantineFixtureOwners(database: D1Database): Promise<void> {
  const names = ['space_epoch_owner_immutable', 'space_personal_policy_insert', 'space_personal_policy_owner_insert'];
  const triggers: string[] = [];
  for (const name of names) {
    const row = await database.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?")
      .bind(name).first<{ sql: string }>();
    if (!row?.sql) throw new Error(`Missing fixture trigger: ${name}`);
    triggers.push(row.sql);
    await database.exec(`DROP TRIGGER ${name}`);
  }
  try {
    const epochs = await database.prepare(`SELECT e.id, e.space_ref, e.repo_did, s.authority_did, s.created_at
      FROM space_epoch e JOIN space s ON s.space_ref = e.space_ref`).all<{
        id: string; space_ref: string; repo_did: string; authority_did: string; created_at: number;
      }>();
    const accounts = new Map<string, string>();
    for (const epoch of epochs.results) {
      let owner = accounts.get(epoch.repo_did);
      if (!owner) {
        await database.prepare('INSERT INTO account (did, handle, created_at, updated_at) VALUES (?, ?, 0, 0)')
          .bind(epoch.repo_did, `${crypto.randomUUID()}.example`).run();
        await database.prepare('INSERT INTO account_state (did, active, created_at) VALUES (?, 1, 0)').bind(epoch.repo_did).run();
        const row = await database.prepare('SELECT space_incarnation FROM account WHERE did = ?')
          .bind(epoch.repo_did).first<{ space_incarnation: string }>();
        if (!row?.space_incarnation) throw new Error('Missing fixture incarnation');
        owner = row.space_incarnation;
        accounts.set(epoch.repo_did, owner);
      }
      await database.prepare('UPDATE space_epoch SET owner_incarnation = ? WHERE id = ?').bind(owner, epoch.id).run();
      if (epoch.authority_did === epoch.repo_did) {
        await database.prepare(`INSERT INTO space_personal_policy
          (space_ref, authority_did, policy_type, creation_nonce, notification_state, created_at, authority_incarnation)
          VALUES (?, ?, 'com.atproto.personalspace.policy', ?, 'none', ?, ?)`)
          .bind(epoch.space_ref, epoch.repo_did, crypto.randomUUID(), epoch.created_at, owner).run();
      }
    }
  } finally {
    for (const trigger of triggers) await database.exec(trigger.replace(/\n/g, ' '));
  }
}
