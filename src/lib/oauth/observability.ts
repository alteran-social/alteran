import { errorMessage } from '../errors';

export type OauthParStage =
  | 'metadata_fetch'
  | 'metadata_shape'
  | 'par_validate'
  | 'client_auth'
  | 'dpop'
  | 'outer'
  | 'success';

export type OauthParFormSummary = {
  redirectUri: string;
  responseType: string;
  grantType: string | null;
  scope: string;
  codeChallengeMethod: string;
  hasState: boolean;
  hasCodeChallenge: boolean;
  hasClientAssertion: boolean;
};

export type OauthParLogDetails = {
  outcome: 'ok' | 'error';
  requestId?: string | null;
  error?: unknown;
  clientId?: string | null;
  form?: OauthParFormSummary | null;
  metadataStatus?: number | null;
  metadataContentType?: string | null;
  metadataRedirected?: boolean | null;
};

// Read context off an Error attached by safeFetchJson when the metadata HTTP
// roundtrip itself failed; absent for shape/validation errors that never made
// a request.
export type FetchAugmentedError = Error & {
  metadataStatus?: number;
  metadataContentType?: string | null;
  metadataRedirected?: boolean;
};

export function readFetchContext(error: unknown): {
  metadataStatus: number | null;
  metadataContentType: string | null;
  metadataRedirected: boolean | null;
} {
  if (!(error instanceof Error)) {
    return { metadataStatus: null, metadataContentType: null, metadataRedirected: null };
  }
  const augmented = error as FetchAugmentedError;
  return {
    metadataStatus: typeof augmented.metadataStatus === 'number' ? augmented.metadataStatus : null,
    metadataContentType: augmented.metadataContentType ?? null,
    metadataRedirected: typeof augmented.metadataRedirected === 'boolean' ? augmented.metadataRedirected : null,
  };
}

export function summarizeParForm(form: URLSearchParams): OauthParFormSummary {
  return {
    redirectUri: form.get('redirect_uri') ?? '',
    responseType: form.get('response_type') ?? '',
    grantType: form.get('grant_type'),
    scope: form.get('scope') ?? '',
    codeChallengeMethod: form.get('code_challenge_method') ?? '',
    hasState: !!form.get('state'),
    hasCodeChallenge: !!form.get('code_challenge'),
    hasClientAssertion: !!form.get('client_assertion'),
  };
}

export function logOauthPar(
  stage: OauthParStage,
  request: Request,
  details: OauthParLogDetails,
): void {
  const url = new URL(request.url);
  const record = {
    level: details.outcome === 'ok' ? 'info' : 'error',
    type: 'oauth_par',
    stage,
    outcome: details.outcome,
    requestId: details.requestId ?? null,
    method: request.method,
    path: url.pathname,
    timestamp: new Date().toISOString(),
    clientId: details.clientId ?? null,
    errorMessage: details.error !== undefined ? errorMessage(details.error) : null,
    form: details.form ?? null,
    metadataStatus: details.metadataStatus ?? null,
    metadataContentType: details.metadataContentType ?? null,
    metadataRedirected: details.metadataRedirected ?? null,
  };
  if (details.outcome === 'ok') {
    console.log(JSON.stringify(record));
  } else {
    console.error(JSON.stringify(record));
  }
}
