import { create } from "zustand";
import type { ApprovalRequest } from "../protocol/ApprovalRequest";
import type { Brain } from "../protocol/Brain";
import type { ChatAgent } from "../protocol/ChatAgent";
import type { TaskUpdate } from "../protocol/TaskUpdate";
import type { PairedLaptop } from "../keys/laptopStore";
import type { FullFrame } from "../transport/frames";
import { ChatItem, mergeAgent, trim } from "./chat";

export type ConnStatus = "idle" | "connecting" | "open" | "offline";

export interface Settings {
  cloud_enabled: boolean;
  cloud_allow_high_sensitivity: boolean;
  preferred_cloud: Brain;
  voice_replies: boolean;
}

export interface Transfer {
  id: string;
  name: string;
  direction: "down" | "up";
  size: number;
  done: number;
  state: "waiting" | "active" | "ok" | "failed";
  error?: string;
  uri?: string;
}

export interface Pairing {
  code: string | null;
  status: "connecting" | "confirm" | "ok" | "failed";
  error?: string;
}

interface AppState {
  booted: boolean;
  laptop: PairedLaptop | null;
  conn: ConnStatus;
  connUrl: string | null;
  connError: string | null;
  pairing: Pairing | null;
  items: ChatItem[];
  tasks: Record<string, TaskUpdate>;
  approvals: ApprovalRequest[];
  frame: FullFrame | null;
  live: boolean;
  screenActive: boolean;
  settings: Settings;
  transfers: Record<string, Transfer>;

  set: (p: Partial<AppState>) => void;
  addUser: (text: string, voice: boolean) => void;
  addAgent: (m: ChatAgent) => string | null;
  upsertTask: (t: TaskUpdate) => void;
  addNotice: (text: string, level: "info" | "warn" | "error") => void;
  pushApproval: (a: ApprovalRequest) => void;
  removeApproval: (id: string) => void;
  putTransfer: (t: Transfer) => void;
  patchTransfer: (id: string, p: Partial<Transfer>) => void;
}

export const DEFAULT_SETTINGS: Settings = {
  cloud_enabled: true,
  cloud_allow_high_sensitivity: false,
  preferred_cloud: "claude",
  voice_replies: false,
};

let seq = 0;
const nid = (p: string) => `${p}-${Date.now()}-${seq++}`;

export const useApp = create<AppState>((set, get) => ({
  booted: false,
  laptop: null,
  conn: "idle",
  connUrl: null,
  connError: null,
  pairing: null,
  items: [],
  tasks: {},
  approvals: [],
  frame: null,
  live: false,
  screenActive: false,
  settings: DEFAULT_SETTINGS,
  transfers: {},

  set: (p) => set(p),
  addUser: (text, voice) => set((s) => ({ items: trim([...s.items, { kind: "user", id: nid("u"), text, voice, ts: Date.now() }]) })),
  addAgent: (m) => {
    const { items, finalText } = mergeAgent(get().items, m, Date.now());
    set({ items: trim(items) });
    return finalText;
  },
  upsertTask: (t) =>
    set((s) => {
      const isNew = !s.tasks[t.task_id];
      return {
        tasks: { ...s.tasks, [t.task_id]: t },
        items: isNew ? trim([...s.items, { kind: "task", id: nid("t"), taskId: t.task_id, ts: Date.now() }]) : s.items,
      };
    }),
  addNotice: (text, level) => set((s) => ({ items: trim([...s.items, { kind: "notice", id: nid("n"), text, level, ts: Date.now() }]) })),
  pushApproval: (a) => set((s) => (s.approvals.some((x) => x.approval_id === a.approval_id) ? s : { approvals: [...s.approvals, a] })),
  removeApproval: (id) => set((s) => ({ approvals: s.approvals.filter((a) => a.approval_id !== id) })),
  putTransfer: (t) => set((s) => ({ transfers: { ...s.transfers, [t.id]: t } })),
  patchTransfer: (id, p) =>
    set((s) => (s.transfers[id] ? { transfers: { ...s.transfers, [id]: { ...s.transfers[id], ...p } } } : s)),
}));
