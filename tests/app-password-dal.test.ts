import { describe, it, beforeEach } from './helpers/bdd.ts';
import { expect } from '@std/expect';
import { makeEnv } from './helpers/env.ts';
import {
  createAppPasswordRow,
  listAppPasswordRows,
  findAppPasswordByName,
  findMatchingAppPassword,
  deleteAppPasswordRow,
  revokeRefreshTokensByAppPasswordName,
} from '../src/db/app-password.ts';
import { storeRefreshToken, getRefreshToken } from '../src/db/account.ts';
import { hashPassword } from '../src/lib/password.ts';
import type { Env } from '../src/env.ts';

const DID = 'did:example:test';

describe('app-password DAL', () => {
  let env: Env;
  beforeEach(async () => {
    env = await makeEnv();
  });

  it('inserts and lists app passwords', async () => {
    const created = await createAppPasswordRow(env, {
      did: DID, name: 'phone', passwordScrypt: 'salt:hash', privileged: false,
    });
    expect(created.name).toBe('phone');
    expect(typeof created.createdAt).toBe('number');
    await createAppPasswordRow(env, {
      did: DID, name: 'cli', passwordScrypt: 'salt:hash2', privileged: true,
    });
    const rows = await listAppPasswordRows(env, DID);
    expect(rows.map((row) => row.name).sort()).toEqual(['cli', 'phone']);
  });

  it('rejects duplicate names per DID', async () => {
    await createAppPasswordRow(env, {
      did: DID, name: 'phone', passwordScrypt: 'salt:hash', privileged: false,
    });
    await expect(
      createAppPasswordRow(env, {
        did: DID, name: 'phone', passwordScrypt: 'salt:other', privileged: false,
      }),
    ).rejects.toThrow();
  });

  it('findAppPasswordByName returns the row or null', async () => {
    await createAppPasswordRow(env, {
      did: DID, name: 'phone', passwordScrypt: 'salt:hash', privileged: false,
    });
    expect((await findAppPasswordByName(env, DID, 'phone'))?.name).toBe('phone');
    expect(await findAppPasswordByName(env, DID, 'absent')).toBe(null);
  });

  it('findMatchingAppPassword returns the matching row when format and hash match', async () => {
    const correct = await hashPassword('abcd-efgh-2345-67mn');
    await createAppPasswordRow(env, {
      did: DID, name: 'cli', passwordScrypt: correct, privileged: true,
    });
    const match = await findMatchingAppPassword(env, DID, 'abcd-efgh-2345-67mn');
    expect(match?.name).toBe('cli');
    expect(match?.privileged).toBe(true);
  });

  it('findMatchingAppPassword returns null for non-app-password-format input', async () => {
    await createAppPasswordRow(env, {
      did: DID,
      name: 'cli',
      passwordScrypt: await hashPassword('abcd-efgh-2345-67mn'),
      privileged: false,
    });
    expect(await findMatchingAppPassword(env, DID, 'arbitrary primary password')).toBe(null);
  });

  it('findMatchingAppPassword returns null when format matches but hash does not', async () => {
    await createAppPasswordRow(env, {
      did: DID,
      name: 'cli',
      passwordScrypt: await hashPassword('abcd-efgh-2345-67mn'),
      privileged: false,
    });
    expect(await findMatchingAppPassword(env, DID, 'zzzz-zzzz-zzzz-zzzz')).toBe(null);
  });

  it('deleteAppPasswordRow removes the row and reports whether anything was removed', async () => {
    await createAppPasswordRow(env, {
      did: DID, name: 'phone', passwordScrypt: 'salt:hash', privileged: false,
    });
    expect(await deleteAppPasswordRow(env, DID, 'phone')).toBe(true);
    expect(await findAppPasswordByName(env, DID, 'phone')).toBe(null);
    expect(await deleteAppPasswordRow(env, DID, 'phone')).toBe(false);
  });

  it('revokeRefreshTokensByAppPasswordName revokes only matching rows', async () => {
    await storeRefreshToken(env, {
      id: 'r1', did: DID, expiresAt: 9_999_999_999, appPasswordName: 'phone',
    });
    await storeRefreshToken(env, {
      id: 'r2', did: DID, expiresAt: 9_999_999_999, appPasswordName: 'cli',
    });
    await storeRefreshToken(env, {
      id: 'r3', did: DID, expiresAt: 9_999_999_999, appPasswordName: null,
    });
    expect(await revokeRefreshTokensByAppPasswordName(env, DID, 'phone')).toBe(1);
    expect((await getRefreshToken(env, 'r1'))?.revokedAt).toBeTruthy();
    expect((await getRefreshToken(env, 'r2'))?.revokedAt).toBeFalsy();
    expect((await getRefreshToken(env, 'r3'))?.revokedAt).toBeFalsy();
  });
});
