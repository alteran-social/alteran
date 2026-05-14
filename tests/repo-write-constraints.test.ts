import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { lexicons } from '@atproto/api';
import { enforceRepoWriteLexiconConstraints } from '../src/lib/repo-write-blob-constraints';
import { validateRawRecord } from '../src/lib/repo-write-data';

const BLOB_CID = 'bafkreigh2akiscaildc4q7fapfs3krvmxz2s5tapqyqdr6fhyjn4zpd6du';

describe('repo write pure constraints', () => {
  it('rejects forbidden raw record keys before lexicon conversion', () => {
    const record = JSON.parse('{"$type":"com.example.record","__proto__":{"polluted":true}}');

    expect(() => validateRawRecord('com.example.record', record)).toThrow('forbidden object key');
  });

  it('enforces strict ATProto datetime formats', () => {
    const record = {
      $type: 'app.bsky.feed.post',
      text: 'loose datetime',
      createdAt: '2024-01-01T00:00:00',
    };

    expect(() => enforceRepoWriteLexiconConstraints(def('app.bsky.feed.post'), record))
      .toThrow('datetime');
  });

  it('enforces blob accept and maxSize constraints', () => {
    const gifProfile = {
      $type: 'app.bsky.actor.profile',
      displayName: 'Tester',
      avatar: blob('image/gif', 100),
    };
    expect(() => enforceRepoWriteLexiconConstraints(def('app.bsky.actor.profile'), gifProfile))
      .toThrow('mime type is not accepted');

    const oversizedProfile = {
      $type: 'app.bsky.actor.profile',
      displayName: 'Tester',
      avatar: blob('image/png', 1_000_001),
    };
    expect(() => enforceRepoWriteLexiconConstraints(def('app.bsky.actor.profile'), oversizedProfile))
      .toThrow('exceeds maxSize');
  });

  it('allows accepted blob constraints through nested unions', () => {
    const post = {
      $type: 'app.bsky.feed.post',
      text: 'image',
      createdAt: '2026-05-13T00:00:00.000Z',
      embed: {
        $type: 'app.bsky.embed.images',
        images: [{ image: blob('image/png', 100), alt: '' }],
      },
    };

    expect(() => enforceRepoWriteLexiconConstraints(def('app.bsky.feed.post'), post)).not.toThrow();
  });

  it('enforces blob constraints through lex-prefixed union discriminators', () => {
    const post = {
      $type: 'app.bsky.feed.post',
      text: 'image',
      createdAt: '2026-05-13T00:00:00.000Z',
      embed: {
        $type: 'lex:app.bsky.embed.images',
        images: [{ image: blob('image/png', 1_000_001), alt: '' }],
      },
    };

    expect(() => enforceRepoWriteLexiconConstraints(def('app.bsky.feed.post'), post))
      .toThrow('exceeds maxSize');
  });
});

function def(nsid: string): Record<string, unknown> {
  const value = lexicons.getDef(nsid);
  if (!value) throw new Error(`missing lexicon: ${nsid}`);
  return value as Record<string, unknown>;
}

function blob(mimeType: string, size: number): Record<string, unknown> {
  return {
    $type: 'blob',
    ref: { $link: BLOB_CID },
    mimeType,
    size,
  };
}
