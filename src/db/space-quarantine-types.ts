export type SpaceQuarantineHandle = {
  readonly id: string;
  readonly token: string;
  readonly spaceRef: string;
  readonly repoDid: string;
};

export type SpaceQuarantineStep =
  | { readonly tag: 'progress'; readonly records: number }
  | { readonly tag: 'complete'; readonly records: number }
  | { readonly tag: 'invalid' | 'unsupported' | 'unavailable' };

export type QuarantineJobRow = {
  id: string;
  token: string;
  renewal_nonce: string;
  space_ref: string;
  repo_did: string;
  epoch_id: string;
  generation: number;
  rev: string;
  cursor: string;
  sequence: number;
  record_count: number;
  expected_hash: number[];
  accumulated_hash: number[];
};

export function quarantineJobArgs(handle: SpaceQuarantineHandle, nonce: string) {
  return [handle.id, handle.token, nonce, handle.spaceRef, handle.repoDid] as const;
}
