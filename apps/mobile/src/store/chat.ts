import type { Brain } from "../protocol/Brain";
import type { ChatAgent } from "../protocol/ChatAgent";

export type ChatItem =
  | { kind: "user"; id: string; text: string; voice: boolean; ts: number }
  | { kind: "agent"; id: string; taskId: string; text: string; brain: Brain; final: boolean; ts: number }
  | { kind: "task"; id: string; taskId: string; ts: number }
  | { kind: "notice"; id: string; text: string; level: "info" | "warn" | "error"; ts: number };

/**
 * Merges a chat.agent message: deltas append to the open (non-final) reply of the same task;
 * a final message replaces the text with the full reply.
 */
export function mergeAgent(items: ChatItem[], m: ChatAgent, now: number): { items: ChatItem[]; finalText: string | null } {
  let idx = -1;
  for (let i = items.length - 1; i >= 0; i--) {
    const it = items[i];
    if (it.kind === "agent" && it.taskId === m.task_id && !it.final) {
      idx = i;
      break;
    }
  }
  if (idx === -1) {
    const item: ChatItem = { kind: "agent", id: `a-${m.task_id}-${now}-${items.length}`, taskId: m.task_id, text: m.text, brain: m.brain, final: m.final, ts: now };
    return { items: [...items, item], finalText: m.final ? m.text : null };
  }
  const prev = items[idx] as Extract<ChatItem, { kind: "agent" }>;
  const next: ChatItem = { ...prev, text: m.final ? m.text : prev.text + m.text, brain: m.brain, final: m.final };
  const out = items.slice();
  out[idx] = next;
  return { items: out, finalText: m.final ? next.text : null };
}

/** Bound memory: keep the newest N items. */
export const MAX_ITEMS = 300;
export function trim(items: ChatItem[]): ChatItem[] {
  return items.length > MAX_ITEMS ? items.slice(items.length - MAX_ITEMS) : items;
}
