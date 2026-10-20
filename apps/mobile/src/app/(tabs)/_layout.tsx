import { Redirect, Tabs } from "expo-router";
import { Text } from "react-native";
import { ConnDot } from "../../components/ConnDot";
import { KillButton } from "../../components/KillButton";
import { useApp } from "../../store/useApp";
import { C } from "../../theme";

const icon = (glyph: string) =>
  function TabIcon({ color }: { color: import("react-native").ColorValue }) {
    return <Text style={{ color, fontSize: 18 }}>{glyph}</Text>;
  };

export default function TabsLayout() {
  const paired = useApp((s) => !!s.laptop);
  const pairing = useApp((s) => s.pairing);
  if (!paired && !pairing) return <Redirect href="/pair" />;
  return (
    <Tabs
      screenOptions={{
        headerStyle: { backgroundColor: C.surface },
        headerTintColor: C.text,
        headerTitle: "",
        headerLeft: () => <ConnDot />,
        headerRight: () => <KillButton />,
        tabBarStyle: { backgroundColor: C.surface, borderTopColor: C.border },
        tabBarActiveTintColor: C.accent,
        tabBarInactiveTintColor: C.dim,
        sceneStyle: { backgroundColor: C.bg },
      }}
    >
      <Tabs.Screen name="index" options={{ title: "Chat", tabBarIcon: icon("💬") }} />
      <Tabs.Screen name="screen" options={{ title: "Screen", tabBarIcon: icon("🖥") }} />
      <Tabs.Screen name="files" options={{ title: "Files", tabBarIcon: icon("📁") }} />
      <Tabs.Screen name="settings" options={{ title: "Settings", tabBarIcon: icon("⚙") }} />
    </Tabs>
  );
}
