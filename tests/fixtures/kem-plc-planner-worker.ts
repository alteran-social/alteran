import { planKemPlcUpdate } from '../../src/lib/spaces/kem-plc-plan';

export default {
  async fetch(request: Request): Promise<Response> {
    const input: unknown = await request.json();
    if (!Array.isArray(input) || input.length !== 8) return new Response(null, { status: 400 });
    return Response.json(planKemPlcUpdate(input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]));
  },
};
