import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { resolveRequestedScope } from '../src/lib/oauth/requested-scope';

const CREATE = 'repo:academy.rawkode.tartan.signature?action=create';
const DELETE = 'repo:academy.rawkode.tartan.signature?action=delete';
const DECLARED = `atproto transition:generic ${CREATE} ${DELETE}`;

describe('requested OAuth scope', () => {
  it('grants declared granular repo scopes verbatim', () => {
    const requested = `atproto ${CREATE} ${DELETE}`;
    expect(resolveRequestedScope(requested, DECLARED)).toEqual({ tag: 'granted', scope: requested });
  });

  it('grants a scope with a repeated action parameter', () => {
    const scope = 'repo:academy.rawkode.tartan.signature?action=create&action=delete';
    expect(resolveRequestedScope(`atproto ${scope}`, `atproto ${scope}`)).toEqual({
      tag: 'granted',
      scope: `atproto ${scope}`,
    });
  });

  it('grants each scope value once', () => {
    expect(resolveRequestedScope(`atproto ${CREATE} atproto ${CREATE}`, DECLARED)).toEqual({
      tag: 'granted',
      scope: `atproto ${CREATE}`,
    });
  });

  it('requires the atproto scope', () => {
    expect(resolveRequestedScope(CREATE, DECLARED).tag).toBe('invalid');
  });

  it('rejects the openid scope', () => {
    expect(resolveRequestedScope('atproto openid', 'atproto openid').tag).toBe('invalid');
  });

  it('rejects a scope the client metadata does not declare', () => {
    expect(resolveRequestedScope('atproto repo:app.bsky.feed.post', DECLARED).tag).toBe('invalid');
  });

  it('leaves permission-set scopes out of the grant because they are not resolved', () => {
    const declared = 'atproto include:app.bsky.authFullApp';
    expect(resolveRequestedScope(declared, declared)).toEqual({ tag: 'granted', scope: 'atproto' });
  });

  it('leaves a repo scope whose collection is not an NSID out of the grant', () => {
    const declared = 'atproto repo:x%20(read-only)';
    expect(resolveRequestedScope(declared, declared)).toEqual({ tag: 'granted', scope: 'atproto' });
  });

  it('rejects whitespace other than single spaces between scope values', () => {
    const declared = 'atproto repo:app.bsky.feed.post';
    expect(resolveRequestedScope('atproto\trepo:app.bsky.feed.post', declared).tag).toBe('invalid');
    expect(resolveRequestedScope('atproto  repo:app.bsky.feed.post', declared).tag).toBe('invalid');
  });

  it('leaves scope values this server cannot enforce out of the grant', () => {
    const declared = 'atproto repo:app.bsky.feed.post?action=publish future:thing';
    expect(resolveRequestedScope(declared, declared)).toEqual({ tag: 'granted', scope: 'atproto' });
  });
});
