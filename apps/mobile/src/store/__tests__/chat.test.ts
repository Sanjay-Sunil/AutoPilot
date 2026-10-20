import { safeFileName } from "../../services/fileName";
import { ChatItem, mergeAgent } from "../chat";

describe("chat.agent streaming merge", () => {
  it("joins deltas by task_id and replaces with final text", () => {
    let items: ChatItem[] = [];
    items = mergeAgent(items, { task_id: "t1", text: "Hel", final: false, brain: "local" }, 1).items;
    items = mergeAgent(items, { task_id: "t2", text: "Other", final: false, brain: "claude" }, 2).items;
    items = mergeAgent(items, { task_id: "t1", text: "lo", final: false, brain: "local" }, 3).items;
    expect(items).toHaveLength(2);
    expect(items[0]).toMatchObject({ kind: "agent", text: "Hello", final: false });
    const r = mergeAgent(items, { task_id: "t1", text: "Hello world", final: true, brain: "claude" }, 4);
    expect(r.finalText).toBe("Hello world");
    expect(r.items[0]).toMatchObject({ text: "Hello world", final: true, brain: "claude" });
    // a later reply for the same task starts a new bubble
    const r2 = mergeAgent(r.items, { task_id: "t1", text: "Next", final: false, brain: "rules" }, 5);
    expect(r2.items).toHaveLength(3);
    expect(r2.finalText).toBeNull();
  });
});

describe("safeFileName", () => {
  it("strips path traversal and control chars", () => {
    expect(safeFileName("../../etc/passwd")).toBe("passwd");
    expect(safeFileName("C:\\x\\a?b.txt")).toBe("a_b.txt");
    expect(safeFileName("..")).toBe("file");
    expect(safeFileName(".hidden")).toBe("hidden");
  });
});
