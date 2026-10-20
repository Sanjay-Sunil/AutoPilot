import { memo } from "react";
import { StyleSheet, Text, View } from "react-native";
import { useApp } from "../store/useApp";
import { C, RISK_COLOR, STATE_COLOR, STATE_ICON } from "../theme";
import { BrainBadge } from "./BrainBadge";

export const TaskCard = memo(function TaskCard({ taskId }: { taskId: string }) {
  const task = useApp((s) => s.tasks[taskId]);
  if (!task) return null;
  return (
    <View style={styles.card}>
      <View style={styles.header}>
        <Text style={[styles.icon, { color: STATE_COLOR[task.state] }]}>{STATE_ICON[task.state]}</Text>
        <Text style={styles.title} numberOfLines={2}>
          {task.title}
        </Text>
        <Text style={[styles.state, { color: STATE_COLOR[task.state] }]}>{task.state.replace("_", " ")}</Text>
      </View>
      {task.steps.map((st, i) => (
        <View key={i} style={styles.step}>
          <Text style={[styles.icon, { color: STATE_COLOR[st.state] }]}>{STATE_ICON[st.state]}</Text>
          <View style={styles.stepBody}>
            <Text style={styles.stepText}>
              <Text style={[styles.tool, { color: RISK_COLOR[st.risk] }]}>{st.tool}</Text> {st.summary}
            </Text>
            {st.output ? (
              <Text style={styles.output} numberOfLines={3}>
                {st.output}
              </Text>
            ) : null}
          </View>
          <BrainBadge brain={st.brain} />
        </View>
      ))}
    </View>
  );
});

const styles = StyleSheet.create({
  card: { backgroundColor: C.surface, borderRadius: 12, borderWidth: 1, borderColor: C.border, padding: 12, marginVertical: 6 },
  header: { flexDirection: "row", alignItems: "center", marginBottom: 6 },
  title: { color: C.text, fontWeight: "700", flex: 1, marginLeft: 6 },
  state: { fontSize: 11, fontWeight: "600", textTransform: "uppercase" },
  step: { flexDirection: "row", alignItems: "flex-start", paddingVertical: 4, gap: 6 },
  stepBody: { flex: 1 },
  icon: { width: 16, textAlign: "center", fontSize: 14 },
  stepText: { color: C.text, fontSize: 13 },
  tool: { fontFamily: "monospace", fontWeight: "700" },
  output: { color: C.dim, fontSize: 12, fontFamily: "monospace", marginTop: 2 },
});
