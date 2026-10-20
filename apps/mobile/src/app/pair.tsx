import { CameraView, useCameraPermissions } from "expo-camera";
import { router, useLocalSearchParams } from "expo-router";
import { useEffect, useRef, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { cancelPairing, pair } from "../services/connection";
import { useApp } from "../store/useApp";
import { C } from "../theme";
import { parsePairingUri, QrError } from "../transport/qr";

export default function PairScreen() {
  const [perm, requestPerm] = useCameraPermissions();
  const pairing = useApp((s) => s.pairing);
  const [manual, setManual] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const handled = useRef(false);
  const [scanned, setScanned] = useState(false);

  const start = (uri: string) => {
    if (handled.current) return;
    try {
      const qr = parsePairingUri(uri);
      handled.current = true;
      setScanned(true);
      setErr(null);
      void pair(qr);
    } catch (e) {
      setErr(e instanceof QrError ? e.message : "Invalid pairing code");
    }
  };

  // Deep link: autopilot://pair?d=... opens this route with `d` set.
  const { d } = useLocalSearchParams<{ d?: string }>();
  useEffect(() => {
    if (d && !handled.current) {
      try {
        const qr = parsePairingUri(`autopilot://pair?d=${d}`);
        handled.current = true;
        void pair(qr);
      } catch {
        /* user can scan instead */
      }
    }
  }, [d]);

  const reset = () => {
    cancelPairing();
    handled.current = false;
    setScanned(false);
  };

  if (pairing) {
    return (
      <View style={styles.center}>
        {pairing.status === "connecting" ? (
          <>
            <ActivityIndicator color={C.accent} size="large" />
            <Text style={styles.msg}>Connecting to laptop…</Text>
          </>
        ) : null}
        {pairing.status === "confirm" || pairing.status === "ok" ? (
          <>
            <Text style={styles.msg}>Check that the laptop shows the same code:</Text>
            <Text style={styles.code}>{pairing.code?.replace(/(\d{3})(\d{3})/, "$1 $2")}</Text>
            {pairing.status === "confirm" ? (
              <>
                <ActivityIndicator color={C.accent} />
                <Text style={styles.hint}>Waiting for the laptop to accept… If the codes differ, cancel now.</Text>
              </>
            ) : (
              <Pressable
                style={styles.btn}
                onPress={() => {
                  useApp.getState().set({ pairing: null });
                  router.replace("/");
                }}
              >
                <Text style={styles.btnText}>Paired — continue</Text>
              </Pressable>
            )}
          </>
        ) : null}
        {pairing.status === "failed" ? (
          <>
            <Text style={[styles.msg, { color: C.red }]}>Pairing failed</Text>
            <Text style={styles.hint}>{pairing.error}</Text>
          </>
        ) : null}
        {pairing.status !== "ok" ? (
          <Pressable style={[styles.btn, styles.secondary]} onPress={reset}>
            <Text style={styles.btnText}>{pairing.status === "failed" ? "Try again" : "Cancel"}</Text>
          </Pressable>
        ) : null}
      </View>
    );
  }

  return (
    <View style={styles.root}>
      <Text style={styles.msg}>Scan the QR code shown by `autopilot pair` on your laptop.</Text>
      <View style={styles.cam}>
        {perm?.granted ? (
          <CameraView
            style={StyleSheet.absoluteFill}
            facing="back"
            barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
            onBarcodeScanned={scanned ? undefined : (r) => start(r.data)}
          />
        ) : (
          <Pressable style={styles.btn} onPress={() => void requestPerm()}>
            <Text style={styles.btnText}>Allow camera</Text>
          </Pressable>
        )}
      </View>
      {err ? <Text style={styles.err}>{err}</Text> : null}
      <Text style={styles.hint}>Or paste the pairing link:</Text>
      <View style={styles.row}>
        <TextInput
          style={styles.input}
          value={manual}
          onChangeText={setManual}
          placeholder="autopilot://pair?d=…"
          placeholderTextColor={C.dim}
          autoCapitalize="none"
          autoCorrect={false}
        />
        <Pressable style={styles.btn} onPress={() => start(manual)}>
          <Text style={styles.btnText}>Pair</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: C.bg },
  center: { flex: 1, padding: 24, alignItems: "center", justifyContent: "center", gap: 14, backgroundColor: C.bg },
  cam: { aspectRatio: 1, borderRadius: 16, overflow: "hidden", backgroundColor: C.surface, alignItems: "center", justifyContent: "center", marginVertical: 16 },
  msg: { color: C.text, fontSize: 16, textAlign: "center" },
  hint: { color: C.dim, textAlign: "center", marginTop: 4 },
  code: { color: C.text, fontSize: 48, fontWeight: "800", letterSpacing: 6, fontVariant: ["tabular-nums"] },
  err: { color: C.red, textAlign: "center" },
  row: { flexDirection: "row", gap: 8, marginTop: 8 },
  input: { flex: 1, color: C.text, backgroundColor: C.surface, borderRadius: 10, paddingHorizontal: 12, borderWidth: 1, borderColor: C.border },
  btn: { backgroundColor: C.accent, paddingHorizontal: 18, paddingVertical: 12, borderRadius: 10, alignItems: "center" },
  secondary: { backgroundColor: C.surface2 },
  btnText: { color: "white", fontWeight: "700" },
});
