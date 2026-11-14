import { parseSpaceWriteJson } from "../../src/lib/spaces/write-json";

export default {
  async fetch(request: Request): Promise<Response> {
    const input = new Uint8Array(await request.arrayBuffer());
    const result = parseSpaceWriteJson(input);
    if (
      result.tag !== "valid" || !result.value ||
      typeof result.value !== "object" || Array.isArray(result.value)
    ) {
      return Response.json({ tag: result.tag });
    }
    const record = result.value as {
      readonly n?: unknown;
      readonly child?: unknown;
    };
    return Response.json({
      tag: result.tag,
      type: typeof record.n,
      value: String(record.n),
      frozen: Object.isFrozen(result.value) && Object.isFrozen(record.child),
    });
  },
};
