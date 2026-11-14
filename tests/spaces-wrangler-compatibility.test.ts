import { expect } from '@std/expect';
import { join } from 'node:path';
import { readWranglerCompatibility } from './helpers/wrangler-compatibility';

Deno.test('request signal checks reject contradictory named-environment flags', async () => {
  const root = await Deno.makeTempDir();
  const config = join(root, 'wrangler.jsonc');
  try {
    const write = (base: string[], production?: string[]) => Deno.writeTextFile(config, JSON.stringify({
      compatibility_date: '2025-09-27', compatibility_flags: base,
      env: { production: production ? { compatibility_flags: production } : {} },
    }));
    await write(['nodejs_compat', 'enable_request_signal']);
    expect((await readWranglerCompatibility(root)).compatibilityFlags).toContain('enable_request_signal');
    for (const [base, production] of [
      [['enable_request_signal', 'disable_request_signal'], undefined],
      [['enable_request_signal'], ['enable_request_signal', 'disable_request_signal']],
      [['enable_request_signal'], ['nodejs_compat']],
    ] as [string[], string[] | undefined][]) {
      await write(base, production);
      await expect(readWranglerCompatibility(root)).rejects.toThrow();
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});
