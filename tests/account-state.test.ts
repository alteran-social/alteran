import { describe, it, expect } from 'bun:test';
import {
  type AccountState,
  type AccountEvent,
  transition,
  toWireStatus,
  fromWireStatus,
  isActive,
} from '../src/lib/account-state';

describe('account state machine', () => {
  describe('transition', () => {
    it('activates from any non-deleted state', () => {
      const states: AccountState[] = [
        { tag: 'takendown' },
        { tag: 'suspended' },
        { tag: 'deactivated' },
      ];
      for (const state of states) {
        expect(transition(state, { tag: 'activate' })).toEqual({ tag: 'active' });
      }
    });

    it('takes down an active account', () => {
      expect(transition({ tag: 'active' }, { tag: 'takedown' })).toEqual({ tag: 'takendown' });
    });

    it('suspends with optional expiry', () => {
      expect(transition({ tag: 'active' }, { tag: 'suspend' })).toEqual({ tag: 'suspended' });
      expect(transition({ tag: 'active' }, { tag: 'suspend', until: '2026-12-31T00:00:00Z' })).toEqual({
        tag: 'suspended',
        until: '2026-12-31T00:00:00Z',
      });
    });

    it('deactivates an active account', () => {
      expect(transition({ tag: 'active' }, { tag: 'deactivate' })).toEqual({ tag: 'deactivated' });
    });

    it('deletes from any non-deleted state', () => {
      const states: AccountState[] = [
        { tag: 'active' },
        { tag: 'takendown' },
        { tag: 'suspended' },
        { tag: 'deactivated' },
      ];
      for (const state of states) {
        expect(transition(state, { tag: 'delete' })).toEqual({ tag: 'deleted' });
      }
    });

    it('refuses to apply any event to a deleted account', () => {
      const events: AccountEvent[] = [
        { tag: 'activate' },
        { tag: 'takedown' },
        { tag: 'suspend' },
        { tag: 'deactivate' },
        { tag: 'delete' },
      ];
      for (const event of events) {
        expect(() => transition({ tag: 'deleted' }, event)).toThrow(
          `Account is deleted; cannot apply ${event.tag}`,
        );
      }
    });
  });

  describe('wire format round-trips', () => {
    const cases: { state: AccountState; wire: { active: boolean; status?: string } }[] = [
      { state: { tag: 'active' }, wire: { active: true } },
      { state: { tag: 'takendown' }, wire: { active: false, status: 'takendown' } },
      { state: { tag: 'suspended' }, wire: { active: false, status: 'suspended' } },
      { state: { tag: 'deactivated' }, wire: { active: false, status: 'deactivated' } },
      { state: { tag: 'deleted' }, wire: { active: false, status: 'deleted' } },
    ];

    for (const { state, wire } of cases) {
      it(`maps ${state.tag} to active=${wire.active}/status=${wire.status ?? 'undefined'}`, () => {
        expect(toWireStatus(state)).toEqual(wire);
        expect(fromWireStatus(wire)).toEqual(state);
      });
    }

    it('treats unknown wire status as suspended (fail-safe)', () => {
      expect(fromWireStatus({ active: false, status: 'mysterious' })).toEqual({ tag: 'suspended' });
      expect(fromWireStatus({ active: false })).toEqual({ tag: 'suspended' });
    });
  });

  describe('isActive', () => {
    it('returns true only for the active tag', () => {
      expect(isActive({ tag: 'active' })).toBe(true);
      expect(isActive({ tag: 'takendown' })).toBe(false);
      expect(isActive({ tag: 'suspended' })).toBe(false);
      expect(isActive({ tag: 'deactivated' })).toBe(false);
      expect(isActive({ tag: 'deleted' })).toBe(false);
    });
  });
});
