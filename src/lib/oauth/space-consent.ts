import type { ParRecord, StoredSpaceConsent } from "./store";
import {
  createExplicitSpaceConsent,
  restoreExplicitSpaceConsent,
  type ExplicitSpaceConsent,
  type ExplicitSpaceConsentBinding,
} from "../spaces/explicit-read-consent";
import { isSpaceScope } from "../spaces/explicit-read-grant";

export function hasSpaceScope(scope: string): boolean {
  return scope.split(" ").some(isSpaceScope);
}

function binding(par: ParRecord, subject: string, accountIncarnation: string): ExplicitSpaceConsentBinding {
  return {
    subject,
    accountIncarnation,
    clientId: par.client_id,
    dpopJkt: par.dpopJkt,
    clientAuthMethod: par.clientAuthMethod,
    clientAuthKeyId: par.clientAuthKeyId ?? null,
    clientAuthKeyBinding: par.clientAuthKeyBinding ?? null,
  };
}

export function createParSpaceConsent(
  par: ParRecord,
  subject: string,
  accountIncarnation: string,
): Promise<ExplicitSpaceConsent | null> {
  return createExplicitSpaceConsent(binding(par, subject, accountIncarnation), par.scope);
}

export function restoreParSpaceConsent(
  par: ParRecord,
  subject: string,
  stored: StoredSpaceConsent,
): Promise<ExplicitSpaceConsent | null> {
  return restoreExplicitSpaceConsent(
    stored.serialized, stored.digest, binding(par, subject, stored.accountIncarnation), stored.tokenScope, par.scope,
  );
}
