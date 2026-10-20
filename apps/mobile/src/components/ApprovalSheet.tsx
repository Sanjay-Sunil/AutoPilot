import * as LocalAuthentication from "expo-local-authentication";
import { useEffect, useState } from "react";
import { Modal, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import type { ApprovalDecision } from "../protocol/ApprovalDecision";
import type { ApprovalRequest } from "../protocol/ApprovalRequest";
import { send } from "../services/connection";
import { useApp } from "../store/useApp";
import { C, RISK_COLOR } from "../theme";

function useCountdown(expiresAt: number | undefined): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!expiresAt) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [expiresAt]);
  return expiresAt ? Math.max(0, Math.ceil((expiresAt - now) / 1000)) : 0;
}

async function confirmBiometric(req: ApprovalRequest): Promise<boolean> {
  // Falls back to the device passcode when no biometrics are enrolled; fails closed otherwise.
  const res = await LocalAuthentication.authenticateAsync({
    promptMessage: `Approve destructive action: ${req.tool}`,
    disableDeviceFallback: false,
    cancelLabel: "Cancel",
  });
  return res.success;
}

/** Modal sheet for the oldest pending approval. */
export function ApprovalSheet() {
  const req = useApp((s) => s.approvals[0]);
  const pending = useApp((s) => s.approvals.length);
  const remove = useApp((s) => s.removeApproval);
  const left = useCountdown(req?.expires_at_ms);
  const [busy, setBusy] = useState(false);
  const [errState, setErrState] = useState<{ id: string; msg: string } | null>(null);
  // Errors are scoped to the approval they belong to, so a new request starts clean.
  const err = errState && errState.id === req?.approval_id ? errState.msg : null;

  useEffect(() => {
    if (req && left === 0 && Date.now() >= req.expires_at_ms) remove(req.approval_id); // expired = deny on laptop
  }, [left, req, remove]);

  if (!req) return null;
  const color = RISK_COLOR[req.risk];

  const setErr = (msg: string) => setErrState({ id: req.approval_id, msg });
  const decide = async (decision: ApprovalDecision) => {
    if (busy) return;
    setBusy(true);
    try {
      if (decision !== "deny" && req.risk === "destructive" && !(await confirmBiometric(req))) {
        setErr("Authentication failed — not approved.");
        return;
      }
      if (Date.now() >= req.expires_at_ms) {
        remove(req.approval_id);
        return;
      }
      if (!send({ type: "approval.response", payload: { approval_id: req.approval_id, decision } })) {
        setErr("Not connected — try again when the connection is back.");
        return;
      }
      remove(req.approval_id);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal transparent animationType="slide" visible onRequestClose={() => decide("deny")}>
      <View style={styles.backdrop}>
        <View style={[styles.sheet, { borderTopColor: color }]}>
          <View style={styles.row}>
            <View style={[styles.tier, { backgroundColor: color }]}>
              <Text style={styles.tierText}>{req.risk.toUpperCase()}</Text>
            </View>
            <Text style={styles.timer}>{left}s</Text>
          </View>
          <Text style={styles.tool}>{req.tool}</Text>
          <Text style={styles.summary}>{req.summary}</Text>
          {req.preview ? (
            <ScrollView style={styles.preview}>
              <Text style={styles.previewText}>{req.preview}</Text>
            </ScrollView>
          ) : null}
          {err ? <Text style={styles.err}>{err}</Text> : null}
          <View style={styles.actions}>
            <Btn label="Deny" color={C.surface2} onPress={() => decide("deny")} disabled={busy} />
            {req.risk === "write" ? <Btn label="Approve for task" color="#8a6a1f" onPress={() => decide("approve_for_task")} disabled={busy} /> : null}
            <Btn label={req.risk === "destructive" ? "Approve 🔒" : "Approve"} color={color === C.green ? "#1f8a50" : color} onPress={() => decide("approve")} disabled={busy} />
          </View>
          {pending > 1 ? <Text style={styles.more}>+{pending - 1} more pending</Text> : null}
        </View>
      </View>
    </Modal>
  );
}

function Btn({ label, color, onPress, disabled }: { label: string; color: string; onPress: () => void; disabled?: boolean }) {
  return (
    <Pressable onPress={onPress} disabled={disabled} style={({ pressed }) => [styles.btn, { backgroundColor: color, opacity: pressed || disabled ? 0.6 : 1 }]}>
      <Text style={styles.btnText}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "rgba(0,0,0,0.55)" },
  sheet: { backgroundColor: C.surface, borderTopLeftRadius: 18, borderTopRightRadius: 18, borderTopWidth: 4, padding: 18, paddingBottom: 34 },
  row: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  tier: { borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3 },
  tierText: { color: "#000", fontWeight: "900", fontSize: 12 },
  timer: { color: C.dim, fontVariant: ["tabular-nums"], fontWeight: "700" },
  tool: { color: C.text, fontFamily: "monospace", fontSize: 16, fontWeight: "700", marginTop: 12 },
  summary: { color: C.text, fontSize: 15, marginTop: 6 },
  preview: { maxHeight: 220, backgroundColor: C.bg, borderRadius: 8, padding: 10, marginTop: 10 },
  previewText: { color: C.dim, fontFamily: "monospace", fontSize: 12 },
  err: { color: C.red, marginTop: 10 },
  actions: { flexDirection: "row", gap: 8, marginTop: 16 },
  btn: { flex: 1, paddingVertical: 14, borderRadius: 10, alignItems: "center" },
  btnText: { color: "white", fontWeight: "800" },
  more: { color: C.dim, textAlign: "center", marginTop: 10, fontSize: 12 },
});
