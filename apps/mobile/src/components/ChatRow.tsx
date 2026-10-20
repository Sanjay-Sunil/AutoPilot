import { memo } from "react";
import { StyleSheet, Text, View } from "react-native";
import type { ChatItem } from "../store/chat";
import { C } from "../theme";
import { BrainBadge } from "./BrainBadge";
import { TaskCard } from "./TaskCard";

export const ChatRow = memo(function ChatRow({ item }: { item: ChatItem }) {
  switch (item.kind) {
    case "user":
      return (
        <View style={[styles.bubble, styles.user]}>
          <Text style={styles.text}>
            {item.voice ? "🎙 " : ""}
            {item.text}
          </Text>
        </View>
      );
    case "agent":
      return (
        <View style={[styles.bubble, styles.agent]}>
          <BrainBadge brain={item.brain} />
          <Text style={[styles.text, { marginTop: 4 }]}>
            {item.text}
            {item.final ? "" : " ▍"}
          </Text>
        </View>
      );
    case "task":
      return <TaskCard taskId={item.taskId} />;
    case "notice":
      return <Text style={[styles.notice, item.level === "error" && { color: C.red }, item.level === "warn" && { color: C.amber }]}>{item.text}</Text>;
  }
});

const styles = StyleSheet.create({
  bubble: { maxWidth: "85%", borderRadius: 14, padding: 10, marginVertical: 4 },
  user: { alignSelf: "flex-end", backgroundColor: C.accent },
  agent: { alignSelf: "flex-start", backgroundColor: C.surface2 },
  text: { color: C.text, fontSize: 15, lineHeight: 21 },
  notice: { color: C.dim, fontSize: 12, textAlign: "center", marginVertical: 6 },
});
