export type ServiceId = 'bsky_appview' | 'bsky_chat' | 'atproto_labeler';

export interface ServiceConfig {
  readonly id: ServiceId;
  readonly url: string;
  readonly did: string;
}

export interface AppViewConfig {
  readonly url: string;
  readonly did: string;
  readonly cdnUrlPattern?: string;
}

export interface ProxyTarget {
  readonly did: string;
  readonly url: string;
}

export type AuthScope =
  | 'com.atproto.access'
  | 'com.atproto.appPass'
  | 'com.atproto.appPassPrivileged'
  | 'com.atproto.signupQueued'
  | 'com.atproto.takendown';
