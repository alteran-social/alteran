import type { APIContext } from 'astro';
import type { Env } from '../../src/env.ts';
import { ctx as workerExecutionContext } from './env.ts';

type Method = 'GET' | 'POST';

type BuildOptions = {
  method?: Method;
  url?: string;
  body?: unknown;
  bearerToken?: string;
  ip?: string;
};

export function buildHandlerContext(env: Env, options: BuildOptions = {}): APIContext {
  const method = options.method ?? 'POST';
  const url = options.url ?? `https://test.example/xrpc/${method.toLowerCase()}`;
  const headers = new Headers();
  if (options.body !== undefined && method !== 'GET') {
    headers.set('content-type', 'application/json');
  }
  if (options.bearerToken) {
    headers.set('authorization', `Bearer ${options.bearerToken}`);
  }
  if (options.ip) {
    headers.set('cf-connecting-ip', options.ip);
  }
  const request = new Request(url, {
    method,
    headers,
    body: options.body === undefined || method === 'GET' ? null : JSON.stringify(options.body),
  });
  return {
    request,
    url: new URL(url),
    locals: {
      env,
      cfContext: workerExecutionContext,
    },
  } as unknown as APIContext;
}
