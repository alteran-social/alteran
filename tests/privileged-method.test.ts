import { describe, it } from "./helpers/bdd";
import { expect } from "@std/expect";
import { isChatMethod, isPrivilegedMethod } from "../src/lib/privileged-method";

describe("isPrivilegedMethod", () => {
  const privileged = [
    "chat.bsky.convo.acceptConvo",
    "chat.bsky.convo.addReaction",
    "chat.bsky.convo.removeReaction",
    "chat.bsky.convo.listConvoRequests",
    "chat.bsky.convo.updateAllRead",
    "chat.bsky.convo.getConvoAvailability",
    "chat.bsky.group.createGroup",
    "chat.bsky.futureMethod",
    "CHAT.BSKY.CONVO.FUTUREMETHOD",
    "com.atproto.server.createAccount",
    "com.atproto.server.createaccount",
  ];

  for (const lexiconMethod of privileged) {
    it(`requires privileged access for ${lexiconMethod}`, () => {
      expect(isPrivilegedMethod(lexiconMethod)).toBe(true);
    });
  }

  const open = [
    "chat.bskyish.futureMethod",
    "com.atproto.server.createAccountExtra",
    "app.bsky.feed.getTimeline",
    "com.atproto.server.getSession",
  ];

  for (const lexiconMethod of open) {
    it(`does not require privileged access for ${lexiconMethod}`, () => {
      expect(isPrivilegedMethod(lexiconMethod)).toBe(false);
    });
  }

  it("treats only the chat.bsky. prefix as chat", () => {
    expect(isChatMethod("chat.bsky.convo.acceptConvo")).toBe(true);
    expect(isChatMethod("CHAT.BSKY.CONVO.FUTUREMETHOD")).toBe(true);
    expect(isChatMethod("chat.bskyish.futureMethod")).toBe(false);
    expect(isChatMethod("com.atproto.server.createAccount")).toBe(false);
  });
});
