import type { Env } from "../../env";
import type { CodeRecord, ConsentRecord, ParSnapshot } from "./store";

/** Issue at most one code for the exact PAR displayed by a consumed consent. */
export async function issueAuthorizationCode(
  env: Env,
  id: string,
  snapshot: ParSnapshot,
  consent: ConsentRecord,
  did: string,
): Promise<string | null> {
  if (
    consent.id !== id || consent.parValue !== snapshot.value || !did ||
    JSON.stringify(snapshot.record) !== snapshot.value
  ) return null;

  const code = crypto.randomUUID().replace(/-/g, "");
  const marker = JSON.stringify({ consumedBy: crypto.randomUUID() });
  const now = Math.floor(Date.now() / 1000);
  const par = snapshot.record;
  const record: CodeRecord = {
    code,
    client_id: par.client_id,
    redirect_uri: par.redirect_uri,
    code_challenge: par.code_challenge,
    scope: par.scope,
    dpopJkt: par.dpopJkt,
    clientAuthMethod: par.clientAuthMethod,
    clientAuthKeyId: par.clientAuthKeyId ?? null,
    did,
    createdAt: now,
    expiresAt: now + 300,
  };
  const parKey = `oauth:par:${id}`;
  const codeKey = `oauth:code:${code}`;
  const codeValue = JSON.stringify(record);
  try {
    const result = await env.ALTERAN_DB.batch([
      env.ALTERAN_DB.prepare(`
      INSERT INTO secret (key, value, updated_at)
      SELECT ?, ?, ?
      WHERE EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
        AND ? >= unixepoch() AND ? >= unixepoch()
    `).bind(
          codeKey,
          codeValue,
          Date.now(),
          parKey,
          snapshot.value,
          par.expiresAt,
          consent.expiresAt,
        ),
      env.ALTERAN_DB.prepare(`
      UPDATE secret SET value = ?, updated_at = ?
      WHERE key = ? AND value = ?
        AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
    `).bind(marker, Date.now(), parKey, snapshot.value, codeKey, codeValue),
      // All other outcomes roll back, including trigger-modified rows. SQLite
      // raises an error for malformed JSON when the postcondition is not met.
      env.ALTERAN_DB.prepare(`
      SELECT CASE
        WHEN EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) THEN 1
        ELSE json_extract('invalid JSON', '$') END AS issued
    `).bind(codeKey, codeValue, parKey, marker),
    ]);
    const postcondition = result[2]?.results?.[0] as
      | { issued?: unknown }
      | undefined;
    if (postcondition?.issued !== 1) {
      throw new Error("Authorization code postcondition unavailable");
    }
    return code;
  } catch (error) {
    // A lost response can follow a committed transaction. The unique marker
    // distinguishes that outcome from a concurrent winner or expiry.
    const state = await env.ALTERAN_DB.prepare(`
      SELECT
        EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS code_present,
        EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS marked,
        EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS unchanged,
        (? >= unixepoch() AND ? >= unixepoch()) AS live
    `).bind(
      codeKey,
      codeValue,
      parKey,
      marker,
      parKey,
      snapshot.value,
      par.expiresAt,
      consent.expiresAt,
    ).first<
      { code_present: number; marked: number; unchanged: number; live: number }
    >();
    if (state?.code_present === 1 && state.marked === 1) return code;
    if (state && (state.unchanged !== 1 || state.live !== 1)) return null;
    throw error;
  }
}
