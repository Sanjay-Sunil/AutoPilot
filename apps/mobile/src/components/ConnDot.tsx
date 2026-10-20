import { StyleSheet, Text, View } from "react-native";
import { useApp } from "../store/useApp";
import { C } from "../theme";

export function ConnDot() {
  const conn = useApp((s) => s.conn);
  const name = useApp((s) => s.laptop?.name);
  const color = conn === "open" ? C.green : conn === "connecting" ? C.amber : C.red;
  return (
    <View style={styles.row}>
      <View style={[styles.dot, { backgroundColor: color }]} />
      <Text style={styles.text} numberOfLines={1}>
        {name ?? "AutoPilot"}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  row: { flexDirection: "row", alignItems: "center", marginLeft: 12, maxWidth: 180 },
  dot: { width: 9, height: 9, borderRadius: 5, marginRight: 7 },
  text: { color: C.text, fontWeight: "600" },
});
