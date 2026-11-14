export type OauthEndpoint = 'par' | 'authorize' | 'consent' | 'token' | 'revoke';

export type OauthParStage =
  | 'metadata_fetch'
  | 'metadata_shape'
  | 'par_validate'
  | 'client_auth'
  | 'dpop'
  | 'outer'
  | 'success';

export type OauthTokenStage =
  | 'dpop'
  | 'parse'
  | 'unsupported_grant'
  | 'auth_code'
  | 'refresh_token'
  | 'client_auth'
  | 'session_issue'
  | 'outer'
  | 'success';

export type OauthParFormSummary = {
  hasRedirectUri: boolean;
  responseType: 'code' | 'other' | 'missing';
  grantType: 'authorization_code' | 'refresh_token' | 'other' | 'missing';
  hasScope: boolean;
  scopeCount: number;
  codeChallengeMethod: 'S256' | 'other' | 'missing';
  hasState: boolean;
  hasCodeChallenge: boolean;
  hasClientAssertion: boolean;
};

export type OauthTokenFormSummary = {
  grantType: 'authorization_code' | 'refresh_token' | 'other' | 'missing';
  hasClientId: boolean;
  hasRedirectUri: boolean;
  hasCode: boolean;
  hasCodeVerifier: boolean;
  hasRefreshToken: boolean;
  hasClientAssertion: boolean;
  clientAssertionType: 'jwt_bearer' | 'other' | 'missing';
};

export type OauthLogDetails = {
  endpoint: OauthEndpoint;
  stage: string;
  outcome: 'ok' | 'error';
  requestId?: string | null;
  error?: unknown;
  clientId?: string | null;
  form?: Record<string, unknown> | null;
  metadataStatus?: number | null;
  metadataContentType?: string | null;
  metadataRedirected?: boolean | null;
};

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
    hasRedirectUri: !!form.get('redirect_uri'),
    responseType: protocolValue(form.get('response_type'), ['code']),
    grantType: protocolValue(form.get('grant_type'), ['authorization_code', 'refresh_token']),
    hasScope: form.has('scope'),
    scopeCount: countScopeValues(form.get('scope') ?? ''),
    codeChallengeMethod: protocolValue(form.get('code_challenge_method'), ['S256']),
    hasState: !!form.get('state'),
    hasCodeChallenge: !!form.get('code_challenge'),
    hasClientAssertion: !!form.get('client_assertion'),
  };
}

export function summarizeTokenForm(form: URLSearchParams): OauthTokenFormSummary {
  const assertionType = form.get('client_assertion_type');
  return {
    grantType: protocolValue(form.get('grant_type'), ['authorization_code', 'refresh_token']),
    hasClientId: !!form.get('client_id'),
    hasRedirectUri: !!form.get('redirect_uri'),
    hasCode: !!form.get('code'),
    hasCodeVerifier: !!form.get('code_verifier'),
    hasRefreshToken: !!form.get('refresh_token'),
    hasClientAssertion: !!form.get('client_assertion'),
    clientAssertionType: !assertionType ? 'missing' :
      assertionType === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' ? 'jwt_bearer' : 'other',
  };
}

export function logOauth(request: Request, details: OauthLogDetails): void {
  const endpoint = safeEndpoint(details.endpoint);
  const outcome = details.outcome === 'ok' ? 'ok' : 'error';
  const record = {
    level: outcome === 'ok' ? 'info' : 'error',
    type: `oauth_${endpoint}`,
    stage: safeStage(endpoint, details.stage),
    outcome,
    requestId: safeRequestId(details.requestId),
    method: request.method === 'GET' || request.method === 'POST' ? request.method : 'other',
    path: endpoint === 'other' ? '/oauth' : `/oauth/${endpoint}`,
    timestamp: new Date().toISOString(),
    clientKind: clientKind(details.clientId),
    hasError: details.error !== undefined,
    form: safeFormSummary(endpoint, details.form),
    metadataStatus: safeStatus(details.metadataStatus),
    metadataContentType: contentTypeClass(details.metadataContentType),
    metadataRedirected: typeof details.metadataRedirected === 'boolean' ? details.metadataRedirected : null,
  };
  if (outcome === 'ok') {
    console.log(JSON.stringify(record));
  } else {
    console.error(JSON.stringify(record));
  }
}

const ENDPOINTS = new Set(['par', 'authorize', 'consent', 'token', 'revoke']);
const PAR_STAGES = new Set(['metadata_fetch', 'metadata_shape', 'par_validate', 'client_auth', 'dpop', 'outer', 'success']);
const TOKEN_STAGES = new Set(['dpop', 'parse', 'unsupported_grant', 'auth_code', 'refresh_token', 'client_auth', 'session_issue', 'outer', 'success']);
const MAX_LOGGED_SCOPE_COUNT = 128;

function safeEndpoint(value: unknown): OauthEndpoint | 'other' {
  return typeof value === 'string' && ENDPOINTS.has(value) ? value as OauthEndpoint : 'other';
}

function safeStage(endpoint: OauthEndpoint | 'other', value: unknown): string {
  if (typeof value !== 'string') return 'other';
  if (endpoint === 'par' && PAR_STAGES.has(value)) return value;
  if (endpoint === 'token' && TOKEN_STAGES.has(value)) return value;
  return 'other';
}

function safeRequestId(value: unknown): string | null {
  return typeof value === 'string' &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
    ? value : null;
}

function clientKind(value: unknown): 'missing' | 'loopback' | 'other' {
  if (typeof value !== 'string' || !value) return 'missing';
  return value.startsWith('http://localhost') ? 'loopback' : 'other';
}

function protocolValue<T extends string>(value: unknown, allowed: readonly T[]): T | 'other' | 'missing' {
  if (value === null || value === undefined || value === '' || value === 'missing') return 'missing';
  return typeof value === 'string' && allowed.includes(value as T) ? value as T : 'other';
}

function countScopeValues(value: string): number {
  let count = 0;
  let inside = false;
  for (const character of value) {
    if (character === ' ') {
      inside = false;
    } else if (!inside) {
      count++;
      if (count >= MAX_LOGGED_SCOPE_COUNT) return MAX_LOGGED_SCOPE_COUNT;
      inside = true;
    }
  }
  return count;
}

function safeStatus(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;
}

function contentTypeClass(value: unknown): 'json' | 'other' | null {
  if (typeof value !== 'string' || !value) return null;
  if (value.length > 256) return 'other';
  const type = value.split(';', 1)[0].trim().toLowerCase();
  return type === 'application/json' || type.endsWith('+json') ? 'json' : 'other';
}

function safeFormSummary(endpoint: OauthEndpoint | 'other', value: Record<string, unknown> | null | undefined) {
  if (!value || typeof value !== 'object') return null;
  if (endpoint === 'par') {
    return {
      hasRedirectUri: value.hasRedirectUri === true,
      responseType: protocolValue(value.responseType, ['code']),
      grantType: protocolValue(value.grantType, ['authorization_code', 'refresh_token']),
      hasScope: value.hasScope === true,
      scopeCount: typeof value.scopeCount === 'number' && Number.isSafeInteger(value.scopeCount) && value.scopeCount >= 0
        ? Math.min(value.scopeCount, MAX_LOGGED_SCOPE_COUNT) : null,
      codeChallengeMethod: protocolValue(value.codeChallengeMethod, ['S256']),
      hasState: value.hasState === true,
      hasCodeChallenge: value.hasCodeChallenge === true,
      hasClientAssertion: value.hasClientAssertion === true,
    };
  }
  if (endpoint === 'token') {
    return {
      grantType: protocolValue(value.grantType, ['authorization_code', 'refresh_token']),
      hasClientId: value.hasClientId === true,
      hasRedirectUri: value.hasRedirectUri === true,
      hasCode: value.hasCode === true,
      hasCodeVerifier: value.hasCodeVerifier === true,
      hasRefreshToken: value.hasRefreshToken === true,
      hasClientAssertion: value.hasClientAssertion === true,
      clientAssertionType: protocolValue(value.clientAssertionType, ['jwt_bearer']),
    };
  }
  return null;
}

// Backward-compatible alias for PAR call sites.
export function logOauthPar(
  stage: OauthParStage,
  request: Request,
  details: Omit<OauthLogDetails, 'endpoint' | 'stage'>,
): void {
  logOauth(request, { ...details, endpoint: 'par', stage });
}
