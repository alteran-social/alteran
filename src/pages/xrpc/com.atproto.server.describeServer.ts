import type { APIContext } from 'astro';
import { getAppViewConfig } from '../../lib/appview';

export const prerender = false;

export function GET({ locals }: APIContext) {
  const { env } = locals;
  const did = env.PDS_DID as string;
  const availableUserDomains: string[] = [];

  const links = typeof env.PDS_LINK_PRIVACY === 'string' || typeof env.PDS_LINK_TOS === 'string'
    ? {
        $type: 'com.atproto.server.describeServer#links' as const,
        ...(typeof env.PDS_LINK_PRIVACY === 'string' ? { privacyPolicy: env.PDS_LINK_PRIVACY } : {}),
        ...(typeof env.PDS_LINK_TOS === 'string' ? { termsOfService: env.PDS_LINK_TOS } : {}),
      }
    : undefined;

  const contact = typeof env.PDS_CONTACT_EMAIL === 'string'
    ? {
        $type: 'com.atproto.server.describeServer#contact' as const,
        email: env.PDS_CONTACT_EMAIL,
      }
    : undefined;

  const appView = getAppViewConfig(env);

  const body = {
    did,
    availableUserDomains,
    inviteCodeRequired: false,
    phoneVerificationRequired: false,
    ...(links ? { links } : {}),
    ...(contact ? { contact } : {}),
    ...(appView
      ? {
          services: {
            appview: {
              $type: 'com.atproto.server.describeServer#service' as const,
              serviceEndpoint: appView.url,
              did: appView.did,
            },
          },
        }
      : {}),
  };
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  });
}
