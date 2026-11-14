import type { OAuthSpaceGrant } from "../../db/oauth-space-grant";

declare const brand: unique symbol;

export type VerifiedSpacePrincipal = {
  readonly [brand]: true;
  readonly sessionId: string;
  readonly accessJti: string;
  readonly did: string;
  readonly clientId: string;
  readonly jkt: string;
  readonly scope: string;
  readonly expiresAt: number;
  readonly proofIssuedAt: number;
  readonly grant: OAuthSpaceGrant;
};

export { consumeVerifiedSpacePrincipal, isVerifiedSpacePrincipal } from "./resource";
