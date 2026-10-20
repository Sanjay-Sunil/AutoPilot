import "react-native-get-random-values"; // crypto.getRandomValues for @noble/* — must load first
import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { useEffect } from "react";
import { ActivityIndicator, View } from "react-native";
import { ApprovalSheet } from "../components/ApprovalSheet";
import { boot } from "../services/connection";
import { useApp } from "../store/useApp";
import { C } from "../theme";

export default function RootLayout() {
  const booted = useApp((s) => s.booted);
  useEffect(() => {
    void boot();
  }, []);

  if (!booted) {
    return (
      <View style={{ flex: 1, backgroundColor: C.bg, alignItems: "center", justifyContent: "center" }}>
        <ActivityIndicator color={C.accent} />
      </View>
    );
  }
  return (
    <>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: C.surface },
          headerTintColor: C.text,
          contentStyle: { backgroundColor: C.bg },
        }}
      >
        <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
        <Stack.Screen name="pair" options={{ title: "Pair with laptop", presentation: "modal" }} />
      </Stack>
      <ApprovalSheet />
    </>
  );
}
