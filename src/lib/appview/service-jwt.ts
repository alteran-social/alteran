import type { Env } from '../../env';
import { getRuntimeString } from '../secrets';
import { getAppViewConfig } from './service-config';

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeJson(obj: Record<string, unknown>): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(obj)));
}

function randomHex(bytes = 16): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function es256kSign(privateKey: string, data: string): Promise<Uint8Array> {
  const cleaned = privateKey.trim();
  const { Secp256k1Keypair } = await import('@atproto/crypto');
  const keypair = /^[0-9a-fA-F]{64}$/.test(cleaned)
    ? await Secp256k1Keypair.import(cleaned)
    : await Secp256k1Keypair.import(base64ToBytes(cleaned));
  return keypair.sign(new TextEncoder().encode(data));
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value.replace(/\s+/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function createServiceJwt(
  env: Env,
  issuerDid: string,
  audienceDid: string,
  lexiconMethod: string | null,
  expiresInSeconds = 60,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.max(1, expiresInSeconds);
  const payload: Record<string, unknown> = {
    iss: issuerDid,
    aud: audienceDid,
    iat: now,
    exp,
    jti: randomHex(),
  };
  if (lexiconMethod) payload.lxm = lexiconMethod;

  const privateKey = ((await getRuntimeString(env, 'REPO_SIGNING_KEY', '')) ?? '').trim();
  if (!privateKey) {
    throw new Error('REPO_SIGNING_KEY not configured for ES256K service-auth');
  }

  const header = { typ: 'JWT', alg: 'ES256K' };
  const encodedHeader = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const toSign = `${encodedHeader}.${encodedPayload}`;
  const signature = await es256kSign(privateKey, toSign);
  return `${toSign}.${encodeBase64Url(signature)}`;
}

export async function getAppViewServiceToken(
  env: Env,
  did: string,
  aud?: string,
  lxm?: string | null,
  expiresInSeconds = 60,
): Promise<string> {
  const config = getAppViewConfig(env);
  if (!config) {
    throw new Error('AppView not configured');
  }
  return createServiceJwt(env, did, aud ?? config.did, lxm ?? null, expiresInSeconds);
}

export async function createServiceAuthToken(
  env: Env,
  issuerDid: string,
  audienceDid: string,
  lexiconMethod: string | null,
  expiresInSeconds = 60,
): Promise<string> {
  return createServiceJwt(env, issuerDid, audienceDid, lexiconMethod, expiresInSeconds);
}
