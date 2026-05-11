// DPoP verification raises `use_dpop_nonce` errors that must carry the current
// nonce back to the client (the OAuth 2.1 / DPoP RFC requires the next request
// to include this nonce in the proof JWT). Modelling it as a typed class lets
// callers narrow with `instanceof` instead of poking string properties off an
// any-typed Error.
export class DpopNonceError extends Error {
  public readonly code = 'use_dpop_nonce' as const;
  public readonly nonce: string;

  constructor(message: string, nonce: string) {
    super(message);
    this.name = 'DpopNonceError';
    this.nonce = nonce;
  }
}
