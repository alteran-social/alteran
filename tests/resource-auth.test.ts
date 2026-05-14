import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { handleResourceAuthError, ResourceAuthError } from '../src/lib/oauth/resource';

describe('resource auth helpers', () => {
  it('maps expired token errors to ExpiredToken responses', async () => {
    const res = await handleResourceAuthError({} as any, new ResourceAuthError('expired_token'));
    expect(res).toBeInstanceOf(Response);
    expect(res?.status).toBe(400);
    const body = await res?.json();
    expect(body).toEqual({ error: 'ExpiredToken', message: 'Access token expired' });
  });

  it('maps invalid token errors to InvalidToken responses', async () => {
    const res = await handleResourceAuthError({} as any, new ResourceAuthError('invalid_token'));
    expect(res).toBeInstanceOf(Response);
    expect(res?.status).toBe(400);
    const body = await res?.json();
    expect(body).toEqual({ error: 'InvalidToken', message: 'Invalid or malformed access token' });
  });
});
