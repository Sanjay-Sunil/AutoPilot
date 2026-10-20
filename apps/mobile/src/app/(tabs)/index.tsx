import { useCallback, useRef, useState } from "react";
import { FlatList, KeyboardAvoidingView, Platform, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { ChatRow } from "../../components/ChatRow";
import { MicButton } from "../../components/MicButton";
import { send } from "../../services/connection";
import type { ChatItem } from "../../store/chat";
import { useApp } from "../../store/useApp";
import { C } from "../../theme";

export default function ChatScreen() {
  const items = useApp((s) => s.items);
  const conn = useApp((s) => s.conn);
  const connError = useApp((s) => s.connError);
  const [text, setText] = useState("");
  const [partial, setPartial] = useState("");
  const list = useRef<FlatList<ChatItem>>(null);

  const submit = useCallback((t: string, voice: boolean) => {
    const body = t.trim();
    if (!body) return;
    if (!send({ type: "chat.user", payload: { text: body, voice } })) {
      useApp.getState().addNotice("Not connected — message not sent", "warn");
      return;
    }
    useApp.getState().addUser(body, voice);
  }, []);

  return (
    <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === "ios" ? "padding" : undefined} keyboardVerticalOffset={90}>
      {conn !== "open" ? (
        <Text style={styles.banner}>{conn === "connecting" ? "Connecting…" : `Offline${connError ? ` — ${connError}` : ""}`}</Text>
      ) : null}
      <FlatList
        ref={list}
        style={styles.flex}
        contentContainerStyle={styles.list}
        data={items}
        keyExtractor={(i) => i.id}
        renderItem={({ item }) => <ChatRow item={item} />}
        onContentSizeChange={() => list.current?.scrollToEnd({ animated: false })}
        ListEmptyComponent={<Text style={styles.empty}>Ask your laptop to do something.</Text>}
        removeClippedSubviews
        windowSize={9}
      />
      {partial ? <Text style={styles.partial}>{partial}</Text> : null}
      <View style={styles.composer}>
        <TextInput
          style={styles.input}
          value={text}
          onChangeText={setText}
          placeholder="Message"
          placeholderTextColor={C.dim}
          multiline
          onSubmitEditing={() => {
            submit(text, false);
            setText("");
          }}
        />
        {text.trim() ? (
          <Pressable
            style={styles.send}
            onPress={() => {
              submit(text, false);
              setText("");
            }}
          >
            <Text style={styles.sendText}>➤</Text>
          </Pressable>
        ) : (
          <MicButton onText={(t) => submit(t, true)} onPartial={setPartial} />
        )}
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
  list: { padding: 12, flexGrow: 1 },
  empty: { color: C.dim, textAlign: "center", marginTop: 80 },
  banner: { backgroundColor: C.surface2, color: C.amber, textAlign: "center", padding: 6, fontSize: 12 },
  partial: { color: C.dim, fontStyle: "italic", paddingHorizontal: 16, paddingBottom: 4 },
  composer: { flexDirection: "row", alignItems: "flex-end", padding: 8, gap: 8, borderTopWidth: 1, borderTopColor: C.border, backgroundColor: C.surface },
  input: { flex: 1, color: C.text, backgroundColor: C.bg, borderRadius: 20, paddingHorizontal: 14, paddingVertical: 10, maxHeight: 120, fontSize: 15 },
  send: { width: 46, height: 46, borderRadius: 23, backgroundColor: C.accent, alignItems: "center", justifyContent: "center" },
  sendText: { color: "white", fontSize: 18 },
});
