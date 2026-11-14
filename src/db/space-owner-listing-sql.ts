export const SPACE_OWNER_POLICY_LISTED = `EXISTS (SELECT 1 FROM space_owner_listing listing
  WHERE listing.space_ref = s.space_ref COLLATE BINARY AND listing.authority_did = p.authority_did COLLATE BINARY
    AND listing.authority_incarnation = p.authority_incarnation AND listing.space_type = s.space_type COLLATE BINARY
    AND listing.creation_nonce = p.creation_nonce)
  AND NOT EXISTS (SELECT 1 FROM space_owner_unclassified quarantine WHERE quarantine.space_ref = s.space_ref COLLATE BINARY)`;

export const SPACE_OWNER_CATALOG_PRESENT = `EXISTS (SELECT 1 FROM space_owner_classification candidate
  WHERE candidate.space_ref IS ? COLLATE BINARY AND (
    (candidate.indexable = 1 AND candidate.classified = 1 AND EXISTS (SELECT 1 FROM space_owner_listing listing
      WHERE listing.space_ref = candidate.space_ref COLLATE BINARY AND listing.authority_did = candidate.authority_did COLLATE BINARY
        AND listing.authority_incarnation = candidate.authority_incarnation AND listing.space_type = candidate.space_type COLLATE BINARY
        AND listing.creation_nonce = candidate.creation_nonce)
      AND NOT EXISTS (SELECT 1 FROM space_owner_unclassified quarantine WHERE quarantine.space_ref = candidate.space_ref COLLATE BINARY))
    OR (candidate.indexable = 1 AND candidate.classified = 0 AND EXISTS (SELECT 1 FROM space_owner_unclassified quarantine
      WHERE quarantine.space_ref = candidate.space_ref COLLATE BINARY AND quarantine.authority_did = candidate.authority_did COLLATE BINARY
        AND quarantine.space_type = candidate.space_type COLLATE BINARY)
      AND NOT EXISTS (SELECT 1 FROM space_owner_listing listing WHERE listing.space_ref = candidate.space_ref COLLATE BINARY))
    OR (candidate.indexable = 0 AND EXISTS (SELECT 1 FROM space_owner_quarantine_global global_quarantine WHERE global_quarantine.id = 1))
  ))`;
