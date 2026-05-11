export type ServiceId = 'bsky_appview' | 'bsky_chat' | 'atproto_labeler';

export type ServiceConfig = {
  readonly id: ServiceId;
  readonly url: string;
  readonly did: string;
};

export type AppViewConfig = {
  readonly url: string;
  readonly did: string;
  readonly cdnUrlPattern?: string;
};

export type ProxyTarget = {
  readonly did: string;
  readonly url: string;
};

export type AuthScope =
  | 'com.atproto.access'
  | 'com.atproto.appPass'
  | 'com.atproto.appPassPrivileged'
  | 'com.atproto.signupQueued'
  | 'com.atproto.takendown';
