export type { AppViewConfig, ServiceConfig, ServiceId, ProxyTarget, AuthScope } from './appview/types';
export { getAppViewConfig } from './appview/service-config';
export { createServiceAuthToken, getAppViewServiceToken } from './appview/service-jwt';
export { proxyAppView } from './appview/proxy';
export type { ProxyAppViewOptions } from './appview/proxy';
