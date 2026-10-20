import * as SecureStore from "expo-secure-store";

export interface PairedLaptop {
  /** base64url X25519 static key, pinned. */
  pk: string;
  name: string;
  addrs: string[];
  relay: string | null;
  pairedAt: number;
}

const KEY = "autopilot.paired_laptop";
const OPTS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

export async function loadLaptop(): Promise<PairedLaptop | null> {
  const s = await SecureStore.getItemAsync(KEY, OPTS);
  if (!s) return null;
  try {
    return JSON.parse(s) as PairedLaptop;
  } catch {
    return null;
  }
}

export async function saveLaptop(l: PairedLaptop): Promise<void> {
  await SecureStore.setItemAsync(KEY, JSON.stringify(l), OPTS);
}

export async function clearLaptop(): Promise<void> {
  await SecureStore.deleteItemAsync(KEY, OPTS);
}

const SETTINGS_KEY = "autopilot.settings";

export async function loadSettingsJson(): Promise<string | null> {
  return SecureStore.getItemAsync(SETTINGS_KEY);
}

export async function saveSettingsJson(s: string): Promise<void> {
  await SecureStore.setItemAsync(SETTINGS_KEY, s);
}
