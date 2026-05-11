import type { Env } from '../../env';
import { ServerMisconfigured } from '../errors';
import type { AppViewConfig, ServiceConfig, ServiceId } from './types';

const DEFAULT_APPVIEW_URL = 'https://api.bsky.app';
const DEFAULT_APPVIEW_DID = 'did:web:api.bsky.app';
const DEFAULT_CHAT_URL = 'https://api.bsky.chat';
const DEFAULT_CHAT_DID = 'did:web:api.bsky.chat';
const DEFAULT_OZONE_URL = 'https://mod.bsky.app';
const DEFAULT_OZONE_DID = 'did:plc:ar7c4by46qjdydhdevvrndac';

function trimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

export function getAppViewConfig(env: Env): AppViewConfig | null {
  const url = trimmedString(env.PDS_BSKY_APP_VIEW_URL) ?? DEFAULT_APPVIEW_URL;
  const did = trimmedString(env.PDS_BSKY_APP_VIEW_DID) ?? DEFAULT_APPVIEW_DID;
  if (!url || !did) return null;
  const cdnUrlPattern = trimmedString(env.PDS_BSKY_APP_VIEW_CDN_URL_PATTERN);
  return { url, did, cdnUrlPattern };
}

function getChatConfig(env: Env): ServiceConfig {
  return {
    id: 'bsky_chat',
    url: trimmedString(env.PDS_BSKY_CHAT_URL) ?? DEFAULT_CHAT_URL,
    did: trimmedString(env.PDS_BSKY_CHAT_DID) ?? DEFAULT_CHAT_DID,
  };
}

function getOzoneConfig(env: Env): ServiceConfig {
  return {
    id: 'atproto_labeler',
    url: trimmedString(env.PDS_OZONE_URL) ?? DEFAULT_OZONE_URL,
    did: trimmedString(env.PDS_OZONE_DID) ?? DEFAULT_OZONE_DID,
  };
}

export function getServiceRegistry(env: Env): Record<ServiceId, ServiceConfig> {
  const app = getAppViewConfig(env);
  if (!app) {
    throw new ServerMisconfigured('AppView not configured');
  }
  return {
    bsky_appview: { id: 'bsky_appview', url: app.url, did: app.did },
    bsky_chat: getChatConfig(env),
    atproto_labeler: getOzoneConfig(env),
  };
}

export function defaultServiceForNsid(env: Env, nsid: string): ServiceConfig {
  const registry = getServiceRegistry(env);
  if (nsid.startsWith('chat.bsky.')) return registry.bsky_chat;
  if (nsid.startsWith('tools.ozone.') || nsid.startsWith('com.atproto.moderation.')) {
    return registry.atproto_labeler;
  }
  return registry.bsky_appview;
}
