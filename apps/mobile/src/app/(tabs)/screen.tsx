import { useFocusEffect } from "expo-router";
import { useCallback } from "react";
import { Image, Pressable, StyleSheet, Switch, Text, View } from "react-native";
import { send } from "../../services/connection";
import { useApp } from "../../store/useApp";
import { C } from "../../theme";

const FPS = 2;

function stopLive() {
  if (useApp.getState().live) {
    send({ type: "screen.request", payload: { action: "stop", max_width: null, fps: null, quality: null } });
    useApp.getState().set({ live: false });
  }
}

export default function ScreenScreen() {
  const frame = useApp((s) => s.frame);
  const live = useApp((s) => s.live);
  const active = useApp((s) => s.screenActive);
  const open = useApp((s) => s.conn === "open");

  // Frames only flow while this screen is focused (battery + privacy).
  useFocusEffect(useCallback(() => () => stopLive(), []));

  const snapshot = () => send({ type: "screen.request", payload: { action: "snapshot", max_width: null, fps: null, quality: null } });
  const toggle = (on: boolean) => {
    if (on) {
      if (send({ type: "screen.request", payload: { action: "start", max_width: null, fps: FPS, quality: null } })) useApp.getState().set({ live: true });
    } else stopLive();
  };

  return (
    <View style={styles.root}>
      <View style={styles.viewer}>
        {frame ? (
          <Image
            style={{ width: "100%", aspectRatio: frame.width && frame.height ? frame.width / frame.height : 16 / 9 }}
            source={{ uri: `data:image/jpeg;base64,${frame.jpegB64}` }}
            resizeMode="contain"
            fadeDuration={0}
          />
        ) : (
          <Text style={styles.dim}>No frame yet. Take a snapshot or go live.</Text>
        )}
      </View>
      <View style={styles.controls}>
        <Pressable style={[styles.btn, !open && styles.disabled]} disabled={!open} onPress={snapshot}>
          <Text style={styles.btnText}>Snapshot</Text>
        </Pressable>
        <View style={styles.liveRow}>
          <Text style={styles.label}>Live ({FPS} fps)</Text>
          <Switch value={live} onValueChange={toggle} disabled={!open} trackColor={{ true: C.red }} />
        </View>
      </View>
      {active ? <Text style={styles.rec}>● Laptop is streaming its screen</Text> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 12 },
  viewer: { flex: 1, backgroundColor: "#000", borderRadius: 12, alignItems: "center", justifyContent: "center", overflow: "hidden" },
  dim: { color: C.dim },
  controls: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginTop: 12 },
  btn: { backgroundColor: C.accent, paddingHorizontal: 18, paddingVertical: 12, borderRadius: 10 },
  disabled: { opacity: 0.4 },
  btnText: { color: "white", fontWeight: "700" },
  liveRow: { flexDirection: "row", alignItems: "center", gap: 8 },
  label: { color: C.text },
  rec: { color: C.red, textAlign: "center", marginTop: 8, fontSize: 12 },
});
