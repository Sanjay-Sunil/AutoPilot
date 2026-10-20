import { memo } from "react";
import { StyleSheet, Text, View } from "react-native";
import type { Brain } from "../protocol/Brain";
import { BRAIN_COLOR } from "../theme";

export const BrainBadge = memo(function BrainBadge({ brain }: { brain: Brain }) {
  const color = BRAIN_COLOR[brain] ?? "#666";
  return (
    <View style={[styles.badge, { borderColor: color }]}>
      <Text style={[styles.text, { color }]}>{brain}</Text>
    </View>
  );
});

const styles = StyleSheet.create({
  badge: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 6, paddingVertical: 1, alignSelf: "flex-start" },
  text: { fontSize: 10, fontWeight: "700", textTransform: "uppercase", letterSpacing: 0.5 },
});
