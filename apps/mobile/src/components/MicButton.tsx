import { ExpoSpeechRecognitionModule, useSpeechRecognitionEvent } from "expo-speech-recognition";
import { useRef, useState } from "react";
import { Alert, Pressable, StyleSheet, Text } from "react-native";
import { stopSpeaking } from "../services/voice";
import { C } from "../theme";

/** Hold to talk: on-device speech recognition; the final transcript is passed to onText. */
export function MicButton({ onText, onPartial }: { onText: (t: string) => void; onPartial?: (t: string) => void }) {
  const [listening, setListening] = useState(false);
  const transcript = useRef("");
  const held = useRef(false);

  useSpeechRecognitionEvent("result", (e) => {
    const t = e.results[0]?.transcript ?? "";
    transcript.current = t;
    onPartial?.(t);
  });
  useSpeechRecognitionEvent("end", () => {
    setListening(false);
    const t = transcript.current.trim();
    transcript.current = "";
    onPartial?.("");
    if (t) onText(t);
  });
  useSpeechRecognitionEvent("error", (e) => {
    setListening(false);
    if (e.error !== "no-speech" && e.error !== "aborted") Alert.alert("Voice input", e.message);
  });

  const start = async () => {
    held.current = true;
    stopSpeaking();
    const perm = await ExpoSpeechRecognitionModule.requestPermissionsAsync();
    if (!perm.granted) {
      Alert.alert("Microphone", "Allow microphone and speech recognition to use voice.");
      return;
    }
    if (!held.current) return; // released before permission resolved
    transcript.current = "";
    setListening(true);
    ExpoSpeechRecognitionModule.start({ lang: "en-US", interimResults: true, continuous: true, requiresOnDeviceRecognition: false });
  };
  const stop = () => {
    held.current = false;
    if (listening) ExpoSpeechRecognitionModule.stop();
  };

  return (
    <Pressable
      accessibilityLabel="Hold to talk"
      onPressIn={start}
      onPressOut={stop}
      style={[styles.btn, listening && styles.active]}
    >
      <Text style={styles.icon}>{listening ? "●" : "🎙"}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  btn: { width: 46, height: 46, borderRadius: 23, backgroundColor: C.surface2, alignItems: "center", justifyContent: "center" },
  active: { backgroundColor: C.red },
  icon: { color: "white", fontSize: 20 },
});
