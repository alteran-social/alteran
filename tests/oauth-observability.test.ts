import { expect } from '@std/expect';
import { describe, it } from '@std/testing/bdd';
import { logOauth, summarizeParForm, summarizeTokenForm } from '../src/lib/oauth/observability';

const PRIVATE = 'private-space-identifier';

describe('OAuth structured observability', () => {
  it('keeps bounded form summaries without storing supplied values', () => {
    const par = new URLSearchParams({
      scope: `atproto space:com.example.forum?skey=${PRIVATE}&action=read_self`,
      redirect_uri: `https://client.example/${PRIVATE}`,
      response_type: PRIVATE,
      grant_type: PRIVATE,
      code_challenge_method: PRIVATE,
      state: PRIVATE,
      code_challenge: PRIVATE,
      client_assertion: PRIVATE,
    });
    const summary = summarizeParForm(par);
    expect(summary).toEqual({
      hasRedirectUri: true,
      responseType: 'other',
      grantType: 'other',
      hasScope: true,
      scopeCount: 2,
      codeChallengeMethod: 'other',
      hasState: true,
      hasCodeChallenge: true,
      hasClientAssertion: true,
    });
    expect(JSON.stringify(summary)).not.toContain(PRIVATE);
    expect(summarizeParForm(new URLSearchParams({ scope: 'a '.repeat(1000) })).scopeCount).toBe(128);
    expect(summarizeParForm(new URLSearchParams()).hasScope).toBe(false);

    const token = summarizeTokenForm(new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: PRIVATE,
      redirect_uri: PRIVATE,
      code: PRIVATE,
      code_verifier: PRIVATE,
      client_assertion_type: PRIVATE,
    }));
    expect(token).toEqual({
      grantType: 'authorization_code',
      hasClientId: true,
      hasRedirectUri: true,
      hasCode: true,
      hasCodeVerifier: true,
      hasRefreshToken: false,
      hasClientAssertion: false,
      clientAssertionType: 'other',
    });
    expect(JSON.stringify(token)).not.toContain(PRIVATE);
  });

  it('allowlists log fields for every endpoint and arbitrary error context', () => {
    const lines: string[] = [];
    const originalLog = console.log;
    const originalError = console.error;
    console.log = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    console.error = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    try {
      for (const endpoint of ['par', 'token', 'authorize', 'consent', 'revoke'] as const) {
        const request = new Request(`https://pds.example/${PRIVATE}?scope=${PRIVATE}`, { method: 'POST' });
        logOauth(request, {
          endpoint,
          stage: PRIVATE,
          outcome: 'error',
          requestId: PRIVATE,
          clientId: `http://localhost?scope=${PRIVATE}`,
          error: new Error(PRIVATE),
          form: {
            scope: PRIVATE,
            clientId: PRIVATE,
            redirectUri: PRIVATE,
            responseType: PRIVATE,
            grantType: PRIVATE,
            codeChallengeMethod: PRIVATE,
            clientAssertionType: PRIVATE,
            scopeCount: 999_999,
          },
          metadataStatus: 999_999,
          metadataContentType: `application/${PRIVATE}`,
          metadataRedirected: true,
        });
      }
    } finally {
      console.log = originalLog;
      console.error = originalError;
    }
    expect(lines).toHaveLength(5);
    expect(lines.join('\n')).not.toContain(PRIVATE);
    for (const line of lines) {
      const record = JSON.parse(line) as Record<string, unknown>;
      expect(record.stage).toBe('other');
      expect(record.hasError).toBe(true);
      expect(record.requestId).toBeNull();
      expect(record.clientKind).toBe('loopback');
      expect(record.metadataStatus).toBeNull();
      expect(record.metadataContentType).toBe('other');
      expect(record.metadataRedirected).toBe(true);
      expect(record.path).not.toContain(PRIVATE);
    }
    expect((JSON.parse(lines[0]) as { form: { scopeCount: number } }).form.scopeCount).toBe(128);
  });

  it('retains only safe stage, request, and response categories', () => {
    const lines: string[] = [];
    const original = console.log;
    console.log = (...values: unknown[]) => lines.push(values.map(String).join(' '));
    try {
      logOauth(new Request('https://pds.example/oauth/par', { method: 'POST' }), {
        endpoint: 'par',
        stage: 'success',
        outcome: 'ok',
        requestId: '12345678-1234-4234-8234-123456789abc',
        clientId: 'https://client.example/metadata',
        form: summarizeParForm(new URLSearchParams({
          scope: 'atproto', response_type: 'code', code_challenge_method: 'S256',
        })),
        metadataStatus: 200,
        metadataContentType: 'application/json; charset=utf-8',
        metadataRedirected: false,
      });
    } finally {
      console.log = original;
    }
    const record = JSON.parse(lines[0]) as Record<string, unknown>;
    expect(record.type).toBe('oauth_par');
    expect(record.stage).toBe('success');
    expect(record.path).toBe('/oauth/par');
    expect(record.requestId).toBe('12345678-1234-4234-8234-123456789abc');
    expect(record.clientKind).toBe('other');
    expect(record.metadataStatus).toBe(200);
    expect(record.metadataContentType).toBe('json');
    expect(record.metadataRedirected).toBe(false);
  });
});
