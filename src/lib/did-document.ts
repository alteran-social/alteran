import type { Env } from '../env';
import { canonicalPdsOrigin, validAtprotoHandle } from './public-host';

export interface DidDocument {
  '@context': string[];
  id: string;
  alsoKnownAs: string[];
  verificationMethod: any[];
  service: Array<{
    id: string;
    type: string;
    serviceEndpoint: string;
  }>;
}

export async function buildDidDocument(env: Env, did: string, handle: string): Promise<DidDocument> {
  const claimedHandle = validAtprotoHandle(handle);
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    alsoKnownAs: claimedHandle ? [`at://${claimedHandle}`] : [],
    verificationMethod: [],
    service: [
      {
        id: '#atproto_pds',
        type: 'AtprotoPersonalDataServer',
        serviceEndpoint: await canonicalPdsOrigin(env),
      },
    ],
  };
}
