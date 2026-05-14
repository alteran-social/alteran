// Thin wrapper around @std/testing/bdd that disables Deno's per-test
// leak/exit sanitizers. Miniflare retains a workerd subprocess and signal
// handlers for the lifetime of the test process by design (see
// tests/helpers/env.ts), so the sanitizers produce noise rather than signal.

import {
  describe as _describe,
  it as _it,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
} from "@std/testing/bdd";

const relax = {
  sanitizeOps: false,
  sanitizeResources: false,
  sanitizeExit: false,
} as const;

type SuiteFn = () => void;
type TestFn = () => void | Promise<void>;
type Modifier = "default" | "skip" | "only";

function callDescribe(mode: Modifier, name: string, fn: SuiteFn): void {
  const opts = { name, ...relax };
  if (mode === "skip") {
    _describe.skip(opts, fn);
    return;
  }
  if (mode === "only") {
    _describe.only(opts, fn);
    return;
  }
  _describe(opts, fn);
}

function callIt(mode: Modifier, name: string, fn: TestFn): void {
  const opts = { name, ...relax };
  if (mode === "skip") {
    _it.skip(opts, fn);
    return;
  }
  if (mode === "only") {
    _it.only(opts, fn);
    return;
  }
  _it(opts, fn);
}

type DescribeFn = ((name: string, fn: SuiteFn) => void) & {
  skip: (name: string, fn: SuiteFn) => void;
  only: (name: string, fn: SuiteFn) => void;
  ignore: (name: string, fn: SuiteFn) => void;
};

type ItFn = ((name: string, fn: TestFn) => void) & {
  skip: (name: string, fn: TestFn) => void;
  only: (name: string, fn: TestFn) => void;
  ignore: (name: string, fn: TestFn) => void;
  todo: (name: string, fn?: TestFn) => void;
};

export const describe: DescribeFn = Object.assign(
  (name: string, fn: SuiteFn) => callDescribe("default", name, fn),
  {
    skip: (name: string, fn: SuiteFn) => callDescribe("skip", name, fn),
    only: (name: string, fn: SuiteFn) => callDescribe("only", name, fn),
    ignore: (name: string, fn: SuiteFn) => callDescribe("skip", name, fn),
  },
);

export const it: ItFn = Object.assign(
  (name: string, fn: TestFn) => callIt("default", name, fn),
  {
    skip: (name: string, fn: TestFn) => callIt("skip", name, fn),
    only: (name: string, fn: TestFn) => callIt("only", name, fn),
    ignore: (name: string, fn: TestFn) => callIt("skip", name, fn),
    todo: (name: string, fn?: TestFn) => callIt("skip", name, fn ?? (() => {})),
  },
);

export const test = it;
export { beforeAll, afterAll, beforeEach, afterEach };
