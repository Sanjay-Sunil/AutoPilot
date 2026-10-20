import { router } from "expo-router";
import { Alert, Pressable, ScrollView, StyleSheet, Switch, Text, View } from "react-native";
import type { Brain } from "../../protocol/Brain";
import type { SettingsUpdate } from "../../protocol/SettingsUpdate";
import { send, unpair } from "../../services/connection";
import { updateSettings } from "../../services/settings";
import { Settings, useApp } from "../../store/useApp";
import { BRAIN_COLOR, C } from "../../theme";

const CLOUDS: Brain[] = ["claude", "openai", "gemini"];

function push(p: Partial<Settings>) {
  const payload: SettingsUpdate = {
    cloud_enabled: p.cloud_enabled ?? null,
    cloud_allow_high_sensitivity: p.cloud_allow_high_sensitivity ?? null,
    preferred_cloud: p.preferred_cloud ?? null,
    voice_replies: p.voice_replies ?? null,
  };
  send({ type: "settings.update", payload });
}

function Toggle({ label, hint, value, onChange }: { label: string; hint?: string; value: boolean; onChange: (v: boolean) => void }) {
  return (
    <View style={styles.row}>
      <View style={{ flex: 1 }}>
        <Text style={styles.label}>{label}</Text>
        {hint ? <Text style={styles.hint}>{hint}</Text> : null}
      </View>
      <Switch value={value} onValueChange={onChange} trackColor={{ true: C.accent }} />
    </View>
  );
}

export default function SettingsScreen() {
  const s = useApp((x) => x.settings);
  const laptop = useApp((x) => x.laptop);
  const connUrl = useApp((x) => x.connUrl);
  const set = (p: Partial<Settings>) => void updateSettings(p, push);

  const confirmUnpair = () =>
    Alert.alert("Unpair laptop?", "You will need to scan a new pairing QR code to reconnect.", [
      { text: "Cancel", style: "cancel" },
      {
        text: "Unpair",
        style: "destructive",
        onPress: async () => {
          await unpair();
          router.replace("/pair");
        },
      },
    ]);

  return (
    <ScrollView contentContainerStyle={styles.root}>
      <Text style={styles.section}>Cloud</Text>
      <Toggle label="Cloud brains enabled" hint="Allow Claude / OpenAI / Gemini for complex tasks" value={s.cloud_enabled} onChange={(v) => set({ cloud_enabled: v })} />
      <Toggle
        label="Allow high-sensitivity data in cloud"
        hint="Off keeps sensitive content on the laptop's local model"
        value={s.cloud_allow_high_sensitivity}
        onChange={(v) => set({ cloud_allow_high_sensitivity: v })}
      />
      <Text style={styles.label}>Preferred cloud</Text>
      <View style={styles.chips}>
        {CLOUDS.map((b) => (
          <Pressable key={b} onPress={() => set({ preferred_cloud: b })} style={[styles.chip, s.preferred_cloud === b && { backgroundColor: BRAIN_COLOR[b], borderColor: BRAIN_COLOR[b] }]}>
            <Text style={styles.chipText}>{b}</Text>
          </Pressable>
        ))}
      </View>

      <Text style={styles.section}>Voice</Text>
      <Toggle label="Speak agent replies" value={s.voice_replies} onChange={(v) => set({ voice_replies: v })} />

      <Text style={styles.section}>Laptop</Text>
      <View style={styles.card}>
        <Text style={styles.label}>{laptop?.name ?? "Not paired"}</Text>
        {connUrl ? <Text style={styles.hint}>via {connUrl.replace(/\?.*$/, "")}</Text> : null}
        {laptop ? <Text style={styles.mono}>key {laptop.pk.slice(0, 16)}…</Text> : null}
      </View>
      <Pressable style={styles.danger} onPress={confirmUnpair}>
        <Text style={styles.dangerText}>Unpair</Text>
      </Pressable>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { padding: 16 },
  section: { color: C.dim, fontSize: 12, fontWeight: "700", textTransform: "uppercase", marginTop: 18, marginBottom: 6 },
  row: { flexDirection: "row", alignItems: "center", paddingVertical: 10, gap: 12 },
  label: { color: C.text, fontSize: 15 },
  hint: { color: C.dim, fontSize: 12, marginTop: 2 },
  mono: { color: C.dim, fontFamily: "monospace", fontSize: 12, marginTop: 4 },
  chips: { flexDirection: "row", gap: 8, marginTop: 8 },
  chip: { borderWidth: 1, borderColor: C.border, borderRadius: 16, paddingHorizontal: 14, paddingVertical: 7 },
  chipText: { color: C.text, fontWeight: "600" },
  card: { backgroundColor: C.surface, borderRadius: 10, padding: 12 },
  danger: { marginTop: 24, borderWidth: 1, borderColor: C.red, borderRadius: 10, padding: 14, alignItems: "center" },
  dangerText: { color: C.red, fontWeight: "700" },
});
