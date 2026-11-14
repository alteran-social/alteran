import { expect } from '@std/expect';
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto-spaces';
import { createSpaceCredential, createSpaceSigHeaders } from '@atproto/space';
import { describe, it } from './helpers/bdd';
import {
  verifySpaceCredential,
  type VerifySpaceCredentialOptions,
} from '../src/lib/spaces/credential-verifier';

const AUTHORITY = 'did:plc:3g2gv2ca25gfnbobdkhxcnbd';
const OTHER_AUTHORITY = 'did:plc:44ybard66vv44zksje25o7dz';
const AUDIENCE = 'did:plc:ewvi7nxzyoun6zhxrhs64oiz';
const OTHER_AUDIENCE = 'did:plc:ragtjsm2j2vknwkz3zp4oxrd';
const SPACE = `at://${AUTHORITY}/space/com.example.group/default` as const;
const OTHER_SPACE = `at://${AUTHORITY}/space/com.example.group/other` as const;

type Signer = P256Keypair | Secp256k1Keypair;
type FixtureOptions = {
  readonly authority?: typeof AUTHORITY | typeof OTHER_AUTHORITY;
  readonly subject?: typeof SPACE | typeof OTHER_SPACE;
  readonly signer?: Signer;
  readonly holder?: P256Keypair;
  readonly proofHolder?: P256Keypair;
  readonly scheme?: string;
  readonly claims?: Record<string, unknown>;
  readonly jwsHeader?: Record<string, unknown>;
};

const signingKey = await Secp256k1Keypair.create();
const holderKey = await P256Keypair.create();

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll(
    '/',
    '_',
  ).replace(/=+$/, '');
}

async function changeClaims(
  token: string,
  claims: Record<string, unknown>,
  signer: Signer,
  headerChanges: Record<string, unknown>,
): Promise<string> {
  const [header, payload] = token.split('.');
  const originalHeader = JSON.parse(
    atob(header.replaceAll('-', '+').replaceAll('_', '/')),
  ) as Record<string, unknown>;
  const original = JSON.parse(
    atob(payload.replaceAll('-', '+').replaceAll('_', '/')),
  ) as Record<string, unknown>;
  const encoded = base64Url(
    new TextEncoder().encode(JSON.stringify({ ...original, ...claims })),
  );
  const encodedHeader = base64Url(
    new TextEncoder().encode(
      JSON.stringify({ ...originalHeader, ...headerChanges }),
    ),
  );
  const content = `${encodedHeader}.${encoded}`;
  return `${content}.${
    base64Url(await signer.sign(new TextEncoder().encode(content)))
  }`;
}

async function fixture(configuration: FixtureOptions = {}): Promise<{
  readonly credential: string;
  readonly options: VerifySpaceCredentialOptions;
}> {
  const signer = configuration.signer ?? signingKey;
  const holder = configuration.holder ?? holderKey;
  let credential = await createSpaceCredential({
    iss: configuration.authority ?? AUTHORITY,
    sub: configuration.subject ?? SPACE,
    keyId: holder.did() as `did:${string}:${string}`,
    keypair: signer,
  });
  if (configuration.claims || configuration.jwsHeader) {
    credential = await changeClaims(
      credential,
      configuration.claims ?? {},
      signer,
      configuration.jwsHeader ?? {},
    );
  }
  const authorization = `${
    configuration.scheme ?? 'Atproto-Space-Credential'
  } ${credential}`;
  const signed = await createSpaceSigHeaders({
    authorization,
    audience: AUDIENCE,
    keypair: configuration.proofHolder ?? holder,
  });
  return {
    credential,
    options: {
      space: SPACE,
      expectedAudience: AUDIENCE,
      headers: new Headers(signed.headers),
      getAuthoritySigningKey: () => Promise.resolve(signer.did()),
      isRevoked: () => Promise.resolve(false),
    },
  };
}

describe('space credential verifier', () => {
  it('authorizes a verified credential and permits replay to the same audience', async () => {
    const { options } = await fixture();
    const revocationChecks: Array<[string, string]> = [];
    const verify = () =>
      verifySpaceCredential({
        ...options,
        isRevoked: (space, credentialId) => {
          revocationChecks.push([space, credentialId]);
          return Promise.resolve(false);
        },
      });
    const first = await verify();
    const second = await verify();
    expect(first.tag).toBe('authorized');
    expect(second).toEqual(first);
    if (first.tag !== 'authorized') {
      throw new Error('Expected authorized credential');
    }
    expect(first.space).toBe(SPACE);
    expect(first.authority).toBe(AUTHORITY);
    expect(first.audience).toBe(AUDIENCE);
    expect(revocationChecks).toEqual([[SPACE, first.credentialId], [
      SPACE,
      first.credentialId,
    ]]);
  });

  it('accepts a freshly signed lower-case scheme but not a changed signed value', async () => {
    const { options } = await fixture({ scheme: 'atproto-space-credential' });
    expect((await verifySpaceCredential(options)).tag).toBe('authorized');
    const headers = new Headers(options.headers);
    const value = headers.get('authorization') ?? '';
    headers.set(
      'authorization',
      value.replace('atproto-space-credential', 'Atproto-Space-Credential'),
    );
    expect(await verifySpaceCredential({ ...options, headers })).toEqual({
      tag: 'invalid',
    });
  });

  it('rejects a credential from another authority before resolving its key', async () => {
    const { options } = await fixture({ authority: OTHER_AUTHORITY });
    let calls = 0;
    const result = await verifySpaceCredential({
      ...options,
      getAuthoritySigningKey: () => {
        calls++;
        return Promise.resolve(signingKey.did());
      },
    });
    expect(result).toEqual({ tag: 'invalid' });
    expect(calls).toBe(0);
  });

  it('does not resolve the issuer of an expired credential from another authority', async () => {
    const now = Math.floor(Date.now() / 1000);
    const { options } = await fixture({
      authority: OTHER_AUTHORITY,
      claims: { iat: now - 100, exp: now - 10 },
    });
    let calls = 0;
    const result = await verifySpaceCredential({
      ...options,
      getAuthoritySigningKey: () => {
        calls++;
        return Promise.resolve(signingKey.did());
      },
    });
    expect(result).toEqual({ tag: 'invalid' });
    expect(calls).toBe(0);
  });

  it('rejects a different subject and malformed space references', async () => {
    const { options } = await fixture({ subject: OTHER_SPACE });
    expect(await verifySpaceCredential(options)).toEqual({ tag: 'invalid' });
    const valid = await fixture();
    expect(
      await verifySpaceCredential({ ...valid.options, space: `${SPACE}/` }),
    ).toEqual({ tag: 'invalid' });
    expect(
      await verifySpaceCredential({
        ...valid.options,
        space: `${SPACE}/did:plc:invalid/com.example.post/one`,
      }),
    )
      .toEqual({ tag: 'invalid' });
  });

  it('rejects replay to a different audience', async () => {
    const { options } = await fixture();
    expect(
      await verifySpaceCredential({
        ...options,
        expectedAudience: OTHER_AUDIENCE,
      }),
    ).toEqual({ tag: 'invalid' });
    const headers = new Headers(options.headers);
    headers.set('atproto-space-audience', OTHER_AUDIENCE);
    expect(
      await verifySpaceCredential({
        ...options,
        headers,
        expectedAudience: OTHER_AUDIENCE,
      }),
    )
      .toEqual({ tag: 'invalid' });
  });

  it('rejects a JWT audience claim instead of ignoring an intended restriction', async () => {
    for (const audience of [AUDIENCE, null]) {
      const { options } = await fixture({ claims: { aud: audience } });
      expect(await verifySpaceCredential(options)).toEqual({ tag: 'invalid' });
    }
  });

  it('rejects unsupported critical and unencoded JWS extensions', async () => {
    for (
      const jwsHeader of [
        { crit: ['unknown'], unknown: 'required' },
        { crit: ['b64'], b64: false },
        { b64: true },
      ]
    ) {
      const { options } = await fixture({ jwsHeader });
      expect(await verifySpaceCredential(options)).toEqual({ tag: 'invalid' });
    }
  });

  it('enforces an optional JWT not-before claim', async () => {
    const now = Math.floor(Date.now() / 1000);
    for (const notBefore of [now + 60, 'tomorrow', null]) {
      const { options } = await fixture({ claims: { nbf: notBefore } });
      expect(await verifySpaceCredential(options)).toEqual({ tag: 'invalid' });
    }
    const valid = await fixture({ claims: { nbf: now - 1 } });
    expect((await verifySpaceCredential(valid.options)).tag).toBe('authorized');
  });

  it('rejects expired, future-issued, and overlong credentials', async () => {
    const now = Math.floor(Date.now() / 1000);
    for (
      const claims of [
        { iat: now - 100, exp: now - 10 },
        { iat: now + 10, exp: now + 100 },
        { iat: now, exp: now + 3601 },
      ]
    ) {
      const { options } = await fixture({ claims });
      expect(await verifySpaceCredential(options)).toEqual({ tag: 'invalid' });
    }
  });

  it('rejects a proof made by a key other than the credential holder', async () => {
    const { options } = await fixture({
      proofHolder: await P256Keypair.create(),
    });
    expect(await verifySpaceCredential(options)).toEqual({ tag: 'invalid' });
  });

  it('rejects altered or ambiguous credentials and bounded headers', async () => {
    const { credential, options } = await fixture();
    const variants: Array<[string, string]> = [
      [
        'authorization',
        `Atproto-Space-Credential ${credential}, Atproto-Space-Credential ${credential}`,
      ],
      [
        'authorization',
        `Atproto-Space-Credential ${credential} ` + 'x'.repeat(8192),
      ],
      ['signature-input', 'x'.repeat(8193)],
      ['signature', 'not-a-signature'],
    ];
    for (const [name, value] of variants) {
      const headers = new Headers(options.headers);
      headers.set(name, value);
      expect(await verifySpaceCredential({ ...options, headers })).toEqual({
        tag: 'invalid',
      });
    }
  });

  it('rejects multiple signatures tagged as space credentials', async () => {
    const { options } = await fixture();
    const headers = new Headers(options.headers);
    const input = headers.get('signature-input') ?? '';
    const second = input.slice(input.indexOf('=') + 1);
    headers.set('signature-input', `${input}, second=${second}`);
    expect(await verifySpaceCredential({ ...options, headers })).toEqual({
      tag: 'invalid',
    });
  });

  it('rejects a locally revoked credential', async () => {
    const { options } = await fixture();
    expect(
      await verifySpaceCredential({
        ...options,
        isRevoked: () => Promise.resolve(true),
      }),
    )
      .toEqual({ tag: 'invalid' });
  });

  it('rejects a credential that expires while checking revocation', async () => {
    const actualNow = Date.now;
    let currentTime = actualNow();
    Date.now = () => currentTime;
    try {
      const { options } = await fixture();
      const result = await verifySpaceCredential({
        ...options,
        isRevoked: () => {
          currentTime += 606_000;
          return Promise.resolve(false);
        },
      });
      expect(result).toEqual({ tag: 'invalid' });
    } finally {
      Date.now = actualNow;
    }
  });

  it('uses the key resolver that was present when verification began', async () => {
    const { options } = await fixture();
    const other = await P256Keypair.create();
    const mutable = { ...options };
    const pending = verifySpaceCredential(mutable);
    mutable.getAuthoritySigningKey = () => Promise.resolve(other.did());
    expect((await pending).tag).toBe('authorized');
  });

  it('uses the revocation checker that was present when verification began', async () => {
    const { options } = await fixture();
    let started = () => {};
    let release = () => {};
    const entered = new Promise<void>((resolve) => started = resolve);
    const gate = new Promise<void>((resolve) => release = resolve);
    const mutable = {
      ...options,
      getAuthoritySigningKey: async () => {
        started();
        await gate;
        return signingKey.did();
      },
      isRevoked: () => Promise.resolve(true),
    };
    const pending = verifySpaceCredential(mutable);
    await entered;
    mutable.isRevoked = () => Promise.resolve(false);
    release();
    expect(await pending).toEqual({ tag: 'invalid' });
  });

  it('fails closed without leaking errors when revocation or key resolution is unavailable', async () => {
    const { credential, options } = await fixture();
    const fail = () =>
      Promise.reject(new Error(`private provider error ${credential}`));
    const resolverResult = await verifySpaceCredential({
      ...options,
      getAuthoritySigningKey: fail,
    });
    const revocationResult = await verifySpaceCredential({
      ...options,
      isRevoked: fail,
    });
    expect(resolverResult).toEqual({ tag: 'unavailable' });
    expect(revocationResult).toEqual({ tag: 'unavailable' });
    expect(JSON.stringify([resolverResult, revocationResult])).not.toContain(
      credential,
    );
    expect(
      await verifySpaceCredential({
        ...options,
        getAuthoritySigningKey: () => Promise.resolve('not-a-key'),
      }),
    )
      .toEqual({ tag: 'unavailable' });
  });

  it('refreshes a rotated authority key at most once for each supported algorithm', async () => {
    const newSigningKey = await P256Keypair.create();
    const { options } = await fixture({ signer: newSigningKey });
    for (
      const staleKey of [
        await P256Keypair.create(),
        await Secp256k1Keypair.create(),
      ]
    ) {
      const calls: Array<[string, boolean]> = [];
      const result = await verifySpaceCredential({
        ...options,
        getAuthoritySigningKey: (authority, forceRefresh) => {
          calls.push([authority, forceRefresh]);
          return Promise.resolve(
            forceRefresh ? newSigningKey.did() : staleKey.did(),
          );
        },
      });
      expect(result.tag).toBe('authorized');
      expect(calls).toEqual([[AUTHORITY, false], [AUTHORITY, true]]);
    }
  });

  it('does not repeatedly refresh keys for an invalid credential', async () => {
    const { options } = await fixture();
    const invalidKey = await P256Keypair.create();
    const calls: boolean[] = [];
    const result = await verifySpaceCredential({
      ...options,
      getAuthoritySigningKey: (_authority, forceRefresh) => {
        calls.push(forceRefresh);
        return Promise.resolve(invalidKey.did());
      },
    });
    expect(result).toEqual({ tag: 'invalid' });
    expect(calls).toEqual([false, true]);
  });
});
