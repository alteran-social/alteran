import { expect } from "@std/expect";
import { describe, it } from "./helpers/bdd";
import { createSpaceConsentSnapshot, restoreSpaceConsentSnapshot } from "../src/lib/spaces/consent-snapshot";
import { materializeCollectionFreeReadSelf, materializeSpacePermission, parseSpacePermission } from "../src/lib/spaces/oauth-scopes";

const SUBJECT = "did:plc:alice";
const CLIENT = "https://client.example/client-metadata.json";
const TYPE = "com.example.forum";
const THREAD = "com.example.thread";
const CID = "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua";

describe("collection-free Space consent snapshots", () => {
  it("keeps collection-free and declaration-backed grants distinct for the same type", async () => {
    const scope = `space:${TYPE}?action=read_self`;
    const requested = parseSpacePermission(scope);
    const writeScope = `space:${TYPE}?action=create`;
    const writeRequested = parseSpacePermission(writeScope);
    if (!requested || !writeRequested) throw new Error("Expected requests");
    const permission = materializeCollectionFreeReadSelf(requested, SUBJECT);
    const writePermission = materializeSpacePermission(writeRequested, SUBJECT, { spaceType: TYPE, collections: [THREAD] });
    if (!permission || !writePermission) throw new Error("Expected grants");
    const read = { requestedScope: scope, permission };
    const write = { requestedScope: writeScope, permission: writePermission };
    const evidence = [{ spaceType: TYPE, publisherDid: SUBJECT, recordCid: CID, headCid: CID,
      revision: "3n2a5tw2wd22l", observedAt: 1, key: "any", collections: [THREAD] }];
    for (const grants of [[read, write], [write, read]]) {
      const seal = await createSpaceConsentSnapshot({ subject: SUBJECT, clientId: CLIENT, grants, declarations: evidence });
      if (!seal) throw new Error("Expected snapshot");
      const restored = await restoreSpaceConsentSnapshot(seal.serialized, {
        subject: SUBJECT, clientId: CLIENT, digest: seal.digest,
      });
      expect(restored?.grants).toEqual(grants);
      expect(restored?.declarations).toHaveLength(1);
    }
    expect(await createSpaceConsentSnapshot({ subject: SUBJECT, clientId: CLIENT, grants: [read],
      declarations: evidence })).toBeNull();
    for (const forged of [
      `space:${TYPE}?collection=${THREAD}&action=read_self`,
      `space:${TYPE}`,
      `space:${TYPE}?action=read`,
      `space:${TYPE}?action=read_self&manage=create`,
    ]) {
      expect(await createSpaceConsentSnapshot({ subject: SUBJECT, clientId: CLIENT,
        grants: [{ ...read, requestedScope: forged }], declarations: [] })).toBeNull();
    }
  });
});
