import { useState } from "react";
import { FlatList, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { pickAndSend, requestFile, shareFile } from "../../services/files";
import { Transfer, useApp } from "../../store/useApp";
import { C } from "../../theme";

function fmt(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function Row({ t }: { t: Transfer }) {
  const pct = t.size ? Math.round((t.done / t.size) * 100) : 0;
  const color = t.state === "ok" ? C.green : t.state === "failed" ? C.red : C.accent;
  return (
    <Pressable style={styles.row} disabled={!t.uri} onPress={() => t.uri && shareFile(t.uri)}>
      <Text style={styles.dir}>{t.direction === "down" ? "↓" : "↑"}</Text>
      <View style={{ flex: 1 }}>
        <Text style={styles.name} numberOfLines={1}>
          {t.name}
        </Text>
        <View style={styles.bar}>
          <View style={[styles.fill, { width: `${pct}%`, backgroundColor: color }]} />
        </View>
        <Text style={styles.meta}>
          {t.state === "failed" ? `Failed: ${t.error ?? ""}` : `${fmt(t.done)} / ${fmt(t.size)} · ${t.state}`}
        </Text>
      </View>
    </Pressable>
  );
}

export default function FilesScreen() {
  const transfers = useApp((s) => s.transfers);
  const open = useApp((s) => s.conn === "open");
  const [path, setPath] = useState("");
  const list = Object.values(transfers).reverse();

  return (
    <View style={styles.root}>
      <Text style={styles.h}>Get a file from the laptop</Text>
      <View style={styles.inputRow}>
        <TextInput
          style={styles.input}
          value={path}
          onChangeText={setPath}
          placeholder="Documents/report.pdf"
          placeholderTextColor={C.dim}
          autoCapitalize="none"
          autoCorrect={false}
        />
        <Pressable
          style={[styles.btn, (!open || !path.trim()) && styles.disabled]}
          disabled={!open || !path.trim()}
          onPress={() => requestFile(path.trim())}
        >
          <Text style={styles.btnText}>Get</Text>
        </Pressable>
      </View>
      <Pressable style={[styles.btn, styles.wide, !open && styles.disabled]} disabled={!open} onPress={() => void pickAndSend()}>
        <Text style={styles.btnText}>Send a file to the laptop…</Text>
      </Pressable>
      <FlatList data={list} keyExtractor={(t) => t.id} renderItem={({ item }) => <Row t={item} />} ListEmptyComponent={<Text style={styles.empty}>No transfers yet.</Text>} />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 12 },
  h: { color: C.text, fontWeight: "700", marginBottom: 8 },
  inputRow: { flexDirection: "row", gap: 8 },
  input: { flex: 1, color: C.text, backgroundColor: C.surface, borderRadius: 10, paddingHorizontal: 12, borderWidth: 1, borderColor: C.border },
  btn: { backgroundColor: C.accent, paddingHorizontal: 18, paddingVertical: 12, borderRadius: 10, alignItems: "center" },
  wide: { marginVertical: 12 },
  disabled: { opacity: 0.4 },
  btnText: { color: "white", fontWeight: "700" },
  row: { flexDirection: "row", alignItems: "center", backgroundColor: C.surface, borderRadius: 10, padding: 10, marginBottom: 8, gap: 10 },
  dir: { color: C.text, fontSize: 18, width: 20, textAlign: "center" },
  name: { color: C.text, fontWeight: "600" },
  bar: { height: 4, backgroundColor: C.surface2, borderRadius: 2, marginVertical: 6, overflow: "hidden" },
  fill: { height: 4 },
  meta: { color: C.dim, fontSize: 12 },
  empty: { color: C.dim, textAlign: "center", marginTop: 30 },
});
