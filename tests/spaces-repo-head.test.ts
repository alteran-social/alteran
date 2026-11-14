import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { base36 } from "multiformats/bases/base36";
import { base32 } from "multiformats/bases/base32";
import { base58btc } from "multiformats/bases/base58";
import { CID } from "multiformats/cid";
import { parsePublicRepoHead } from "../src/lib/spaces/repo-head";

const CID_VALUE = "bafyreie42kbiqjv2iy5mdsnfoogerllgjxlg5qwx3dyydpgykgumpwojsa";
const REVISION = "3n2a5tw2wd22l";

describe("Public repository head parsing", () => {
  it("normalizes equivalent CID encodings to one value", () => {
    const cid = CID.parse(CID_VALUE);
    for (
      const value of [CID_VALUE, cid.toString(base58btc), cid.toString(base36)]
    ) {
      expect(parsePublicRepoHead({ cid: value, rev: REVISION })).toEqual({
        cid: CID_VALUE,
        revision: REVISION,
      });
    }
  });

  it("rejects malformed heads, non-CBOR CIDs and invalid revisions", () => {
    for (
      const value of [
        null,
        {},
        { cid: CID_VALUE, rev: "bad" },
        { cid: "not-a-cid", rev: REVISION },
        { cid: "b".repeat(129), rev: REVISION },
        {
          cid: "bafkreigh2akiscaildcw453z4evvz664ucit4szqg3yxmrv3h7z5o4xqye",
          rev: REVISION,
        },
      ]
    ) expect(parsePublicRepoHead(value)).toBeNull();
  });

  it("rejects overlong varints in each CID component", () => {
    const canonical = CID.parse(CID_VALUE).bytes;
    for (let index = 0; index < 4; index++) {
      const bytes = Uint8Array.from([
        ...canonical.slice(0, index),
        canonical[index] | 0x80,
        0,
        ...canonical.slice(index + 1),
      ]);
      expect(parsePublicRepoHead({ cid: base32.encode(bytes), rev: REVISION }))
        .toBeNull();
    }
  });
});
