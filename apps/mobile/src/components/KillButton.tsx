import { Alert, Pressable, StyleSheet, Text } from "react-native";
import { send } from "../services/connection";
import { C } from "../theme";

/** Always-visible kill switch: stops all agent actions and the screen stream on the laptop. */
export function KillButton() {
  const onPress = () => {
    const ok = send({ type: "control.kill", payload: { reason: "phone kill switch" } });
    if (!ok) Alert.alert("Not connected", "The kill command could not be delivered. Use the laptop tray or hotkey.");
  };
  return (
    <Pressable accessibilityRole="button" accessibilityLabel="Kill all agent actions" onPress={onPress} style={({ pressed }) => [styles.btn, pressed && { opacity: 0.7 }]} hitSlop={8}>
      <Text style={styles.text}>KILL</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  btn: { backgroundColor: C.kill, paddingHorizontal: 14, paddingVertical: 7, borderRadius: 8, marginRight: 12 },
  text: { color: "white", fontWeight: "900", letterSpacing: 1 },
});
