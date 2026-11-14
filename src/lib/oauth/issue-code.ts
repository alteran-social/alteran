import type { Env } from "../../env";
import { MAX_CODE_BYTES, type CodeRecord, type ConsentRecord, type ParSnapshot } from "./store";
import { hasSpaceScope, restoreParSpaceConsent } from "./space-consent";

const ACTIVE_ACCOUNT = `EXISTS (SELECT 1 FROM account a JOIN account_state state ON state.did = a.did
  WHERE a.did = ? AND a.space_incarnation = ? AND state.active = 1 AND state.status IS NULL AND state.suspended_until IS NULL)`;
const VALID_CLOCK = `EXISTS (SELECT 1 FROM oauth_replay_clock clock WHERE clock.id = 1
  AND typeof(clock.seconds) = 'integer' AND clock.seconds BETWEEN 0 AND 9007199254740991)`;
const LIVE_CLOCK = `EXISTS (SELECT 1 FROM oauth_replay_clock clock WHERE clock.id = 1
  AND typeof(clock.seconds) = 'integer' AND clock.seconds < ? AND ? < ?)`;

function workerSecond(): number {
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid OAuth Worker clock");
  return now;
}

/** Persist a time sample before any transaction that uses it for issuance. */
async function advanceConsentClock(env: Env, observedAt: number): Promise<void> {
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const row = await env.ALTERAN_DB.prepare(`UPDATE oauth_replay_clock
    SET seconds = MAX(seconds, unixepoch(), ?), nonce = ?
    WHERE id = 1 AND typeof(seconds) = 'integer' AND seconds BETWEEN 0 AND 9007199254740991
    RETURNING seconds`).bind(observedAt, nonce).first<{ seconds: number }>();
  if (!row || !Number.isSafeInteger(row.seconds) || row.seconds < observedAt) {
    throw new Error("Invalid OAuth consent clock");
  }
}

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
  const par = snapshot.record;
  const hasSpace = hasSpaceScope(par.scope);
  if (hasSpace !== !!consent.spaceConsent ||
    (consent.spaceConsent && !(await restoreParSpaceConsent(par, did, consent.spaceConsent)))) return null;

  const now = workerSecond();
  const code = crypto.randomUUID().replace(/-/g, "");
  const marker = JSON.stringify({ consumedBy: crypto.randomUUID() });
  const attempt = crypto.randomUUID().replace(/-/g, "");
  const record: CodeRecord = {
    code,
    client_id: par.client_id,
    redirect_uri: par.redirect_uri,
    code_challenge: par.code_challenge,
    scope: consent.spaceConsent?.tokenScope ?? par.scope,
    dpopJkt: par.dpopJkt,
    clientAuthMethod: par.clientAuthMethod,
    clientAuthKeyId: par.clientAuthKeyId ?? null,
    clientAuthKeyBinding: par.clientAuthKeyBinding ?? null,
    did,
    createdAt: now,
    expiresAt: now + 300,
    ...(consent.spaceConsent && { spaceConsent: consent.spaceConsent }),
  };
  const deadline = Math.min(par.expiresAt, consent.expiresAt, record.expiresAt);
  if (!Number.isSafeInteger(deadline) || deadline < 0 || !Number.isSafeInteger(record.expiresAt)) return null;
  const parKey = `oauth:par:${id}`;
  const codeKey = `oauth:code:${code}`;
  const receiptKey = `oauth:dpop:jti:consent:${attempt}`;
  const receipt = (state: string) => JSON.stringify({ iat: now, exp: now + 300, attempt, state });
  const eligible = receipt("eligible");
  const blocked = receipt("blocked");
  const changed = receipt("changed");
  const codeValue = JSON.stringify(record);
  if (codeValue.length > MAX_CODE_BYTES || new TextEncoder().encode(codeValue).byteLength > MAX_CODE_BYTES) return null;

  await advanceConsentClock(env, now);
  const observedAt = workerSecond();
  if (observedAt >= deadline) {
    await advanceConsentClock(env, observedAt);
    return null;
  }
  const db = env.ALTERAN_DB;
  const active = `(? = 0 OR ${ACTIVE_ACCOUNT})`;
  const liveArgs = [deadline, observedAt, deadline] as const;
  const activeArgs = [hasSpace ? 1 : 0, did, consent.spaceConsent?.accountIncarnation ?? ""] as const;
  let issued: unknown;
  let transactionError: unknown;
  try {
    const result = await db.batch([
      db.prepare(`INSERT INTO secret (key, value, updated_at) SELECT ?, CASE
        WHEN NOT EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) THEN ?
        WHEN NOT (${LIVE_CLOCK}) OR NOT (${active}) THEN ? ELSE ? END, ?`)
        .bind(receiptKey, parKey, snapshot.value, changed, ...liveArgs, ...activeArgs, blocked, eligible, now * 1000),
      db.prepare(`INSERT INTO secret (key, value, updated_at) SELECT ?, ?, ?
        WHERE EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND ${LIVE_CLOCK} AND ${active}`)
        .bind(codeKey, codeValue, now * 1000, receiptKey, eligible, parKey, snapshot.value, ...liveArgs, ...activeArgs),
      db.prepare(`UPDATE secret SET value = ?, updated_at = ? WHERE key = ? AND value = ?
        AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
        AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
        AND ${LIVE_CLOCK} AND ${active}`)
        .bind(marker, now * 1000, parKey, snapshot.value, receiptKey, eligible, codeKey, codeValue,
          ...liveArgs, ...activeArgs),
      db.prepare(`SELECT CASE WHEN NOT (${VALID_CLOCK}) THEN json('{')
        WHEN EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND ${LIVE_CLOCK} AND ${active} THEN 1
        WHEN EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND NOT EXISTS (SELECT 1 FROM secret WHERE key = ?)
          AND EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND (NOT (${LIVE_CLOCK}) OR NOT (${active})) THEN 0
        WHEN EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?)
          AND NOT EXISTS (SELECT 1 FROM secret WHERE key = ?)
          AND NOT EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) THEN 0
        ELSE json('{') END AS issued`)
        .bind(receiptKey, eligible, codeKey, codeValue, parKey, marker, ...liveArgs, ...activeArgs,
          receiptKey, blocked, codeKey, parKey, snapshot.value, ...liveArgs, ...activeArgs,
          receiptKey, changed, codeKey, parKey, snapshot.value),
    ]);
    issued = (result[3]?.results?.[0] as { issued?: unknown } | undefined)?.issued;
    if (issued !== 0 && issued !== 1) throw new Error("Authorization code postcondition unavailable");
  } catch (error) {
    transactionError = error;
  }
  if (issued === 0) return null;

  // A committed code stays private until a separate durable time sample and readback.
  const recoveredAt = workerSecond();
  await advanceConsentClock(env, recoveredAt);
  const state = await db.prepare(`SELECT
    EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS code_present,
    EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS marked,
    EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS receipt_present,
    EXISTS (SELECT 1 FROM secret WHERE key = ? AND value = ?) AS unchanged,
    ${LIVE_CLOCK} AS live, ${active} AS active`)
    .bind(codeKey, codeValue, parKey, marker, receiptKey, eligible, parKey, snapshot.value,
      deadline, recoveredAt, deadline, ...activeArgs)
    .first<{ code_present: number; marked: number; receipt_present: number; unchanged: number; live: number; active: number }>();
  if (state?.code_present === 1 && state.marked === 1 && state.receipt_present === 1) {
    if (state.live !== 1 || state.active !== 1) return null;
    const completedAt = workerSecond();
    if (completedAt >= deadline) {
      await advanceConsentClock(env, completedAt);
      return null;
    }
    return code;
  }
  if (state && (state.unchanged !== 1 || state.live !== 1 || state.active !== 1)) return null;
  if (transactionError !== undefined) throw transactionError;
  throw new Error("Authorization code changed before response");
}
