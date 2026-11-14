import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { Buffer } from "node:buffer";
import { encodeRecordBlock } from "../src/services/repo/blockstore-ops";
import {
  applySpaceSetHashChanges,
  spaceRecordHashElement,
  spaceSetHashDigest,
} from "../src/lib/spaces/lthash";

describe("Spaces reference PDS vectors", () => {
  it("reproduces the record CID and commit digest of a reference PDS repo", async () => {
    const [cid] = await encodeRecordBlock({
      $type: "com.example.note",
      text: "Reference fixture",
    });
    expect(cid.toString()).toBe(
      "bafyreie42kbiqjv2iy5mdsnfoogerllgjxlg5qwx3dyydpgykgumpwojsa",
    );

    const state = applySpaceSetHashChanges(null, [{
      action: "add",
      element: spaceRecordHashElement(
        "com.example.note",
        "fixture-1",
        cid.toString(),
      ),
    }]);
    expect(Buffer.from(spaceSetHashDigest(state)).toString("base64url"))
      .toBe("HHjmAtQ2W_w_9uRua0rrO5l4bMoJzT-uA-7nsrHCiVE");
  });
});
