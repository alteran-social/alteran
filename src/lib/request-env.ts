import { AsyncLocalStorage } from "node:async_hooks";
import type { Env } from "../env";

const requestEnvironment = new AsyncLocalStorage<Env>();

export function withRequestEnv<T>(env: Env, callback: () => T): T {
  return requestEnvironment.run(env, callback);
}

export function currentRequestEnv(): Env | undefined {
  return requestEnvironment.getStore();
}
