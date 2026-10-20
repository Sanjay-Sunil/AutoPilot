import type { Brain } from "./protocol/Brain";
import type { RiskTier } from "./protocol/RiskTier";
import type { TaskState } from "./protocol/TaskState";

export const C = {
  bg: "#0b0d12",
  surface: "#151922",
  surface2: "#1d2330",
  border: "#2a3242",
  text: "#e8ecf3",
  dim: "#8b95a7",
  accent: "#5b8cff",
  green: "#2ecc71",
  amber: "#f5a623",
  red: "#ff4d4f",
  kill: "#e5252a",
};

export const RISK_COLOR: Record<RiskTier, string> = { read: C.green, write: C.amber, destructive: C.red };

export const BRAIN_COLOR: Record<Brain, string> = {
  rules: "#7f8c8d",
  laya: "#9b59b6",
  local: "#16a085",
  claude: "#d97757",
  openai: "#10a37f",
  gemini: "#4285f4",
};

export const STATE_ICON: Record<TaskState, string> = {
  planned: "○",
  running: "◐",
  waiting_approval: "⏸",
  done: "✓",
  failed: "✕",
  cancelled: "⊘",
};

export const STATE_COLOR: Record<TaskState, string> = {
  planned: C.dim,
  running: C.accent,
  waiting_approval: C.amber,
  done: C.green,
  failed: C.red,
  cancelled: C.dim,
};
