import { loadSettingsJson, saveSettingsJson } from "../keys/laptopStore";
import { DEFAULT_SETTINGS, Settings, useApp } from "../store/useApp";

export async function loadSettings(): Promise<void> {
  try {
    const s = await loadSettingsJson();
    if (s) useApp.getState().set({ settings: { ...DEFAULT_SETTINGS, ...(JSON.parse(s) as Partial<Settings>) } });
  } catch {
    /* defaults */
  }
}

export async function updateSettings(p: Partial<Settings>, send: (s: Partial<Settings>) => void): Promise<void> {
  const next = { ...useApp.getState().settings, ...p };
  useApp.getState().set({ settings: next });
  send(p);
  await saveSettingsJson(JSON.stringify(next));
}
