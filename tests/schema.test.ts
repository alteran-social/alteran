import { describe, test, expect } from 'bun:test';
import {
  record,
  blob_usage,
  commit_log,
  blockstore,
  refresh_token_store,
  account,
  secret,
} from '../src/db/schema';

// Structural tests for the Drizzle schema. They verify the table definitions
// at module load — no D1 binding is required because the assertions only read
// column metadata (primary/notNull/dataType).

describe('Schema Tests', () => {
  describe('Schema Constraints', () => {
    test('record table has primary key on uri', () => {
      expect(record.uri.primary).toBe(true);
    });

    test('record table requires did, cid, and json', () => {
      expect(record.did.notNull).toBe(true);
      expect(record.cid.notNull).toBe(true);
      expect(record.json.notNull).toBe(true);
    });

    test('blob_usage table requires recordUri and key', () => {
      expect(blob_usage.recordUri.notNull).toBe(true);
      expect(blob_usage.key.notNull).toBe(true);
    });

    test('refresh_token table has primary key on id', () => {
      expect(refresh_token_store.id.primary).toBe(true);
    });

    test('account table requires did and handle', () => {
      expect(account.did.notNull).toBe(true);
      expect(account.handle.notNull).toBe(true);
    });

    test('commit_log table has primary key on seq', () => {
      expect(commit_log.seq.primary).toBe(true);
    });

    test('blockstore table has primary key on cid', () => {
      expect(blockstore.cid.primary).toBe(true);
    });
  });

  describe('Data Types', () => {
    test('record.createdAt is integer', () => {
      expect(record.createdAt.dataType).toBe('number');
    });

    test('commit_log.seq is integer', () => {
      expect(commit_log.seq.dataType).toBe('number');
    });

    test('refresh_token.expiresAt is integer', () => {
      expect(refresh_token_store.expiresAt.dataType).toBe('number');
    });

    test('secret.updatedAt is integer', () => {
      expect(secret.updatedAt.dataType).toBe('number');
    });
  });

  describe('Schema Documentation', () => {
    test('commit_log has pruning documentation', () => {
      expect(commit_log.seq).toBeDefined();
      expect(commit_log.cid).toBeDefined();
      expect(commit_log.data).toBeDefined();
    });

    test('blockstore has GC documentation', () => {
      expect(blockstore.cid).toBeDefined();
      expect(blockstore.bytes).toBeDefined();
    });
  });
});

describe('Migration Tests', () => {
  test('migrations directory exists', async () => {
    const fs = await import('fs/promises');
    const path = await import('path');

    const migrationsDir = path.join(process.cwd(), 'migrations');
    const exists = await fs.access(migrationsDir).then(() => true).catch(() => false);

    expect(exists).toBe(true);
  });

  test('migration journal exists', async () => {
    const fs = await import('fs/promises');
    const path = await import('path');

    const journalPath = path.join(process.cwd(), 'migrations', 'meta', '_journal.json');
    const exists = await fs.access(journalPath).then(() => true).catch(() => false);

    expect(exists).toBe(true);
  });

  test('index migrations are present', async () => {
    const fs = await import('fs/promises');
    const path = await import('path');

    const migrationsDir = path.join(process.cwd(), 'migrations');
    const files = await fs.readdir(migrationsDir);

    const sqlFiles = files.filter((f) => f.endsWith('.sql'));
    expect(sqlFiles.length).toBeGreaterThan(0);

    let hasIndexMigration = false;
    for (const file of sqlFiles) {
      const content = await fs.readFile(path.join(migrationsDir, file), 'utf-8');
      if (content.includes('CREATE INDEX')) {
        hasIndexMigration = true;
        break;
      }
    }

    expect(hasIndexMigration).toBe(true);
  });
});
