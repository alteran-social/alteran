import type { Env } from "../env";

const MAX_ATTEMPTS = 5;
const LOCK_SECONDS = 15 * 60;
const MAX_IP_BYTES = 256;

export type LoginAttemptReservation = {
  readonly ip: string;
  readonly nonce: string;
  readonly attempts: number;
  readonly lockedUntil: number | null;
};

export type LoginAttemptResult =
  | { readonly tag: "reserved"; readonly reservation: LoginAttemptReservation }
  | { readonly tag: "locked"; readonly retryAfter: number };

function clientKey(request: Request): string {
  const value = request.headers.get("cf-connecting-ip");
  if (!value || value.length > MAX_IP_BYTES || !/^[0-9a-fA-F:.]+$/.test(value)) return "unknown";
  return new TextEncoder().encode(value).byteLength <= MAX_IP_BYTES ? value : "unknown";
}

/** Reserve capacity before password verification, including cancelled requests. */
export async function reserveLoginAttempt(env: Env, request: Request): Promise<LoginAttemptResult> {
  const ip = clientKey(request);
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const result = await env.ALTERAN_DB.batch([
    env.ALTERAN_DB.prepare(`INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt, reservation_nonce)
      VALUES (?, 1, NULL, unixepoch(), ?)
      ON CONFLICT(ip) DO UPDATE SET
        attempts = CASE WHEN locked_until IS NOT NULL AND locked_until <= unixepoch() THEN 1 ELSE attempts + 1 END,
        locked_until = CASE WHEN locked_until IS NOT NULL AND locked_until <= unixepoch() THEN NULL
          WHEN attempts + 1 >= ? THEN unixepoch() + ? ELSE NULL END,
        last_attempt = unixepoch(), reservation_nonce = excluded.reservation_nonce
      WHERE typeof(attempts) = 'integer' AND typeof(last_attempt) = 'integer'
        AND ((locked_until IS NULL AND attempts BETWEEN 0 AND ?)
          OR (typeof(locked_until) = 'integer' AND locked_until <= unixepoch()))
      RETURNING attempts, locked_until, last_attempt, reservation_nonce`)
      .bind(ip, nonce, MAX_ATTEMPTS, LOCK_SECONDS, MAX_ATTEMPTS - 1),
    env.ALTERAN_DB.prepare(`SELECT CASE
        WHEN changes() = 1 AND EXISTS (SELECT 1 FROM login_attempts WHERE ip = ? AND reservation_nonce = ?
          AND typeof(attempts) = 'integer' AND attempts BETWEEN 1 AND ?
          AND (locked_until IS NULL OR typeof(locked_until) = 'integer')) THEN 1
        WHEN changes() = 0 AND EXISTS (SELECT 1 FROM login_attempts WHERE ip = ?) THEN 0
        ELSE json('{') END AS reserved,
      COALESCE((SELECT CASE WHEN typeof(locked_until) = 'integer' AND locked_until > unixepoch()
        THEN MIN(?, locked_until - unixepoch()) ELSE ? END FROM login_attempts WHERE ip = ?), ?) AS retry_after`)
      .bind(ip, nonce, MAX_ATTEMPTS, ip, LOCK_SECONDS, LOCK_SECONDS, ip, LOCK_SECONDS),
  ]);
  const verdict = result[1]?.results?.[0] as { reserved?: unknown; retry_after?: unknown } | undefined;
  if (verdict?.reserved === 0) {
    const seconds = verdict.retry_after;
    if (typeof seconds !== "number" || !Number.isSafeInteger(seconds) || seconds < 1 || seconds > LOCK_SECONDS) {
      throw new Error("Invalid login lockout state");
    }
    return { tag: "locked", retryAfter: seconds };
  }
  const row = result[0]?.results?.[0] as {
    attempts?: unknown; locked_until?: unknown; last_attempt?: unknown; reservation_nonce?: unknown;
  } | undefined;
  if (verdict?.reserved !== 1 || !row || row.reservation_nonce !== nonce ||
    typeof row.attempts !== "number" || !Number.isSafeInteger(row.attempts) || row.attempts < 1 || row.attempts > MAX_ATTEMPTS ||
    typeof row.last_attempt !== "number" || !Number.isSafeInteger(row.last_attempt) || row.last_attempt < 0 ||
    (row.locked_until !== null && (typeof row.locked_until !== "number" || !Number.isSafeInteger(row.locked_until)))) {
    throw new Error("Invalid login attempt reservation");
  }
  return { tag: "reserved", reservation: {
    ip, nonce, attempts: row.attempts, lockedUntil: row.locked_until as number | null,
  } };
}

/** Clear only the latest reservation, leaving newer concurrent attempts intact. */
export async function clearLoginAttempt(env: Env, reservation: LoginAttemptReservation): Promise<void> {
  await env.ALTERAN_DB.prepare("DELETE FROM login_attempts WHERE ip = ? AND reservation_nonce = ?")
    .bind(reservation.ip, reservation.nonce).run();
}

export function loginLockoutResponse(retryAfter = LOCK_SECONDS, newlyLocked = false): Response {
  const minutes = Math.max(1, Math.ceil(retryAfter / 60));
  return new Response(JSON.stringify({
    error: "RateLimitExceeded",
    message: newlyLocked ? "Too many failed login attempts. Account locked for 15 minutes."
      : `Account locked due to too many failed attempts. Try again in ${minutes} minutes.`,
  }), { status: 429, headers: { "Content-Type": "application/json" } });
}
