import * as Speech from "expo-speech";

export function speak(text: string): void {
  const t = text.trim();
  if (!t) return;
  Speech.stop();
  Speech.speak(t.length > 1200 ? t.slice(0, 1200) : t, { rate: 1.0 });
}

export function stopSpeaking(): void {
  Speech.stop();
}
