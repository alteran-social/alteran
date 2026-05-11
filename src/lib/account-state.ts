/**
 * Finite-state machine for account lifecycle.
 *
 * The AT Protocol wire format encodes account status as two fields:
 *   { active: boolean; status?: string }
 *
 * That representation lets you express illegal combinations (e.g.
 * `active: true` paired with `status: "takendown"`). Internally we model
 * the same domain as a discriminated union so the compiler enforces the
 * invariant: every state is either active OR carries a specific reason
 * for being inactive, never both. Conversion to the wire shape happens
 * only at the firehose boundary.
 */

export type AccountState =
  | { readonly tag: 'active' }
  | { readonly tag: 'takendown' }
  | { readonly tag: 'suspended'; readonly until?: string }
  | { readonly tag: 'deactivated' }
  | { readonly tag: 'deleted' };

export type AccountStateTag = AccountState['tag'];

const ACTIVE: AccountState = { tag: 'active' };
const TAKENDOWN: AccountState = { tag: 'takendown' };
const DEACTIVATED: AccountState = { tag: 'deactivated' };
const DELETED: AccountState = { tag: 'deleted' };

export type AccountEvent =
  | { readonly tag: 'activate' }
  | { readonly tag: 'takedown' }
  | { readonly tag: 'suspend'; readonly until?: string }
  | { readonly tag: 'deactivate' }
  | { readonly tag: 'delete' };

/**
 * Apply an event to a state and return the next state.
 *
 * Illegal transitions (e.g. activating a deleted account) throw; this is a
 * fail-fast contract so bugs surface at the call site instead of silently
 * corrupting the firehose. Callers should validate authorization before
 * passing an event to transition.
 */
export function transition(state: AccountState, event: AccountEvent): AccountState {
  if (state.tag === 'deleted') {
    throw new Error(`Account is deleted; cannot apply ${event.tag}`);
  }
  switch (event.tag) {
    case 'activate':
      return ACTIVE;
    case 'takedown':
      return TAKENDOWN;
    case 'suspend':
      return event.until ? { tag: 'suspended', until: event.until } : { tag: 'suspended' };
    case 'deactivate':
      return DEACTIVATED;
    case 'delete':
      return DELETED;
  }
}

export type AccountWireStatus = {
  readonly active: boolean;
  readonly status?: string;
};

// The AT Protocol firehose #account event carries only { active, status } —
// the spec has no slot for `until`. Wire round-trips through
// fromWireStatus(toWireStatus) are intentionally lossy on the suspended
// expiry; persistence uses toRow/fromRow which preserve the full FSM.
export function toWireStatus(state: AccountState): AccountWireStatus {
  switch (state.tag) {
    case 'active':
      return { active: true };
    case 'takendown':
      return { active: false, status: 'takendown' };
    case 'suspended':
      return { active: false, status: 'suspended' };
    case 'deactivated':
      return { active: false, status: 'deactivated' };
    case 'deleted':
      return { active: false, status: 'deleted' };
  }
}

export function fromWireStatus(wire: AccountWireStatus): AccountState {
  if (wire.active) return ACTIVE;
  switch (wire.status) {
    case 'takendown':
      return TAKENDOWN;
    case 'suspended':
      return { tag: 'suspended' };
    case 'deactivated':
      return DEACTIVATED;
    case 'deleted':
      return DELETED;
    default:
      // Unknown / missing status from an older wire payload — treat as a
      // suspended account so reads still gate but writes are blocked.
      return { tag: 'suspended' };
  }
}

export function isActive(state: AccountState): boolean {
  return state.tag === 'active';
}

// Persistence shape. The account_state table mirrors this row exactly. We
// keep both `active` (for legacy reads + cheap filters) and `status` /
// `suspended_until` so the full FSM can be recovered from D1.
export type AccountStateRow = {
  readonly active: boolean;
  readonly status: string | null;
  readonly suspended_until: number | null;
};

export function toRow(state: AccountState): AccountStateRow {
  switch (state.tag) {
    case 'active':
      return { active: true, status: null, suspended_until: null };
    case 'takendown':
      return { active: false, status: 'takendown', suspended_until: null };
    case 'suspended':
      return {
        active: false,
        status: 'suspended',
        suspended_until: state.until ? Date.parse(state.until) : null,
      };
    case 'deactivated':
      return { active: false, status: 'deactivated', suspended_until: null };
    case 'deleted':
      return { active: false, status: 'deleted', suspended_until: null };
  }
}

export function fromRow(row: AccountStateRow): AccountState {
  if (row.active) return ACTIVE;
  switch (row.status) {
    case 'takendown':
      return TAKENDOWN;
    case 'suspended': {
      const until = row.suspended_until !== null
        ? new Date(row.suspended_until).toISOString()
        : undefined;
      return until ? { tag: 'suspended', until } : { tag: 'suspended' };
    }
    case 'deleted':
      return DELETED;
    case 'deactivated':
    default:
      // null / unknown status with active=false is the bootstrap state for
      // freshly-created accounts that haven't been activated yet. Treat it
      // as deactivated so reads still gate but no special-case is needed.
      return DEACTIVATED;
  }
}
