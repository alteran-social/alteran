import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { consentPermissions, describeConsentPermission } from '../src/lib/oauth/consent-scopes';

function describeScope(scope: string): string[] {
  return consentPermissions(scope).map(describeConsentPermission);
}

describe('consent permission descriptions', () => {
  it('names the collection and every action granted on it', () => {
    const scope = 'atproto repo:academy.rawkode.tartan.signature?action=create repo:academy.rawkode.tartan.signature?action=delete';
    expect(describeScope(scope)).toEqual([
      'Know which account you are',
      'Create and delete records in the collection academy.rawkode.tartan.signature',
    ]);
  });

  it('treats a repo scope without actions as every action', () => {
    expect(describeScope('repo:app.bsky.feed.post')).toEqual([
      'Create, update and delete records in the collection app.bsky.feed.post',
    ]);
  });

  it('spells out a wildcard collection', () => {
    expect(describeScope('repo:*?action=delete')).toEqual(['Delete records in any collection']);
  });

  it('lists each collection of a multi-collection scope', () => {
    expect(describeScope('repo?collection=app.bsky.feed.post&collection=app.bsky.feed.like&action=create')).toEqual([
      'Create records in the collection app.bsky.feed.post',
      'Create records in the collection app.bsky.feed.like',
    ]);
  });

  it('shows the decoded collection of a percent-encoded scope', () => {
    expect(describeScope('repo:app.bsky.feed%2Epost?action=create')).toEqual([
      'Create records in the collection app.bsky.feed.post',
    ]);
  });

  it('warns that transition:generic is broad', () => {
    expect(describeScope('transition:generic')[0]).toContain('Full access to your repository');
  });

  it('describes an account scope with both actions as read and change', () => {
    expect(describeScope('account:email?action=read&action=manage')).toEqual([
      'Read and change your account email',
    ]);
  });

  it('shows nothing for scope values the server does not accept', () => {
    expect(describeScope('identity:bogus account:bogus blob:bogus rpc:%3Cimg%3E?aud=*')).toEqual([]);
  });

  it('describes blob and rpc permissions', () => {
    expect(describeScope('blob:image/* rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app%23bsky_appview')).toEqual([
      'Upload files of type image/*',
      'Call app.bsky.feed.getTimeline on did:web:api.bsky.app#bsky_appview on your behalf',
    ]);
  });
});
