import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classify, signLikeQuickNode, verifyQuickNode, type StreamMatch } from "../src/watchdog.ts";

const match = (signature: string, extra: string[] = []): StreamMatch => ({
  signature,
  signatures: [signature, ...extra],
  blockTime: 1_800_000_000,
  usdcDelta: -1,
  solDelta: 0,
});

describe("QuickNode webhook verification", () => {
  const body = JSON.stringify({ matches: [match("abc")] });

  it("accepts a correctly signed body", () => {
    assert.equal(verifyQuickNode(Buffer.from(body), signLikeQuickNode(body, "tok"), "tok"), true);
  });
  it("rejects a tampered body", () => {
    const headers = signLikeQuickNode(body, "tok");
    assert.equal(verifyQuickNode(Buffer.from(body.replace("abc", "xyz")), headers, "tok"), false);
  });
  it("rejects the wrong token and missing headers", () => {
    assert.equal(verifyQuickNode(Buffer.from(body), signLikeQuickNode(body, "other"), "tok"), false);
    assert.equal(verifyQuickNode(Buffer.from(body), {}, "tok"), false);
  });
});

describe("classify()", () => {
  it("treats a spend carrying any of our signatures as ours (x402: the vendor pays the fee, we co-sign)", () => {
    const r = classify({ matches: [match("vendorFeeSig", ["ourSig"])] }, new Set(["ourSig"]));
    assert.equal(r.ours.length, 1);
    assert.equal(r.outOfBand.length, 0);
  });
  it("flags a spend we never signed as out-of-band", () => {
    const r = classify({ matches: [match("leakedKeySig")] }, new Set(["ourSig"]));
    assert.equal(r.outOfBand.length, 1);
  });
  it("ignores heartbeats and junk", () => {
    assert.deepEqual(classify({ heartbeat: 150, matches: [] }, new Set()), { ours: [], outOfBand: [] });
    assert.deepEqual(classify(null, new Set()), { ours: [], outOfBand: [] });
  });
});
