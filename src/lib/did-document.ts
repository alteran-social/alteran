import type { Env } from '../env';
import { getRuntimeString } from './secrets';

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
  const hostname = await getRuntimeString(env, 'PDS_HOSTNAME', handle);

  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    alsoKnownAs: [`at://${handle}`],
    verificationMethod: [],
    service: [
      {
        id: '#atproto_pds',
        type: 'AtprotoPersonalDataServer',
        serviceEndpoint: `https://${hostname}`,
      },
    ],
  };
}
