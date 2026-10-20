/** Strip any path components and unsafe characters from a name supplied by the peer. */
export function safeFileName(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "";
  const clean = base.replace(/[\u0000-\u001f<>:"|?*]/g, "_").replace(/^\.+/, "").trim();
  return (clean || "file").slice(0, 120);
}
