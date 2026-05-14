import { describe, it } from './helpers/bdd.ts';
import { expect } from '@std/expect';
import { generateAppPasswordSecret, isAppPasswordFormat } from '../src/lib/app-password.ts';

describe('app-password generator', () => {
  it('produces a 19-character xxxx-xxxx-xxxx-xxxx secret', () => {
    const secret = generateAppPasswordSecret();
    expect(secret.length).toBe(19);
    expect(secret).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/);
  });

  it('produces different secrets on subsequent calls', () => {
    expect(generateAppPasswordSecret()).not.toBe(generateAppPasswordSecret());
  });
});

describe('app-password format predicate', () => {
  it('accepts xxxx-xxxx-xxxx-xxxx with lowercase base32 characters', () => {
    expect(isAppPasswordFormat('abcd-efgh-2345-6xyz')).toBe(true);
  });

  it('rejects strings shorter than 19 characters', () => {
    expect(isAppPasswordFormat('abcd-efgh-2345')).toBe(false);
  });

  it('rejects uppercase letters', () => {
    expect(isAppPasswordFormat('ABCD-EFGH-2345-6XYZ')).toBe(false);
  });

  it('rejects digits outside base32 alphabet', () => {
    expect(isAppPasswordFormat('abcd-efgh-2345-6xy0')).toBe(false);
  });

  it('rejects a primary password shape', () => {
    expect(isAppPasswordFormat('s3cret-primary-pass')).toBe(false);
  });
});
