import * as SecureStore from "expo-secure-store";
import { generateKeyPair, KeyPair, keyPairFromPrivate } from "../noise";
import { fromBase64, toBase64Url } from "../util/bytes";

const KEY = "autopilot.device_x25519_sk";
const OPTS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

let cached: KeyPair | null = null;

/** Phone's long-term Noise static key, generated once and kept in Keychain/Keystore. */
export async function getDeviceKey(): Promise<KeyPair> {
  if (cached) return cached;
  const stored = await SecureStore.getItemAsync(KEY, OPTS);
  if (stored) {
    cached = keyPairFromPrivate(fromBase64(stored));
  } else {
    const kp = generateKeyPair();
    await SecureStore.setItemAsync(KEY, toBase64Url(kp.privateKey), OPTS);
    cached = kp;
  }
  return cached;
}
