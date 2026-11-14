import { sql } from 'drizzle-orm';
import { check, index, integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

export const space_owner_listing = sqliteTable('space_owner_listing', {
  spaceRef: text('space_ref').primaryKey().notNull(),
  authorityDid: text('authority_did').notNull(),
  authorityIncarnation: text('authority_incarnation').notNull(),
  spaceType: text('space_type').notNull(),
  creationNonce: text('creation_nonce').notNull(),
}, (table) => ({
  ownerType: index('space_owner_listing_owner_type').on(
    table.authorityDid, table.authorityIncarnation, table.spaceType, table.spaceRef,
  ),
}));

export const space_owner_unclassified = sqliteTable('space_owner_unclassified', {
  spaceRef: text('space_ref').primaryKey().notNull(),
  authorityDid: text('authority_did').notNull(),
  spaceType: text('space_type').notNull(),
}, (table) => ({
  authorityType: index('space_owner_unclassified_authority_type').on(
    table.authorityDid, table.spaceType, table.spaceRef,
  ),
}));

export const space_owner_quarantine_global = sqliteTable('space_owner_quarantine_global', {
  id: integer('id').primaryKey().notNull(),
}, (table) => ({
  singleton: check('space_owner_quarantine_global_singleton', sql`${table.id} = 1`),
}));
