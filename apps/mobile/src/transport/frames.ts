import type { ScreenFrame } from "../protocol/ScreenFrame";
import { concat, fromBase64, toBase64 } from "../util/bytes";

export interface FullFrame {
  frameId: number;
  width: number;
  height: number;
  /** Complete base64 JPEG. */
  jpegB64: string;
}

/**
 * Reassembles split screen.frame parts. Keeps only the newest in-progress frame: once a newer
 * frame id shows up, older partial frames are dropped (we always want the latest picture).
 */
export class FrameAssembler {
  private current: { id: number; parts: (string | undefined)[]; got: number; w: number; h: number } | null = null;
  private lastDone = -1;

  push(f: ScreenFrame): FullFrame | null {
    if (f.parts < 1 || f.part < 0 || f.part >= f.parts || f.parts > 4096) return null;
    if (f.frame_id <= this.lastDone) return null;
    if (!this.current || f.frame_id > this.current.id) {
      this.current = { id: f.frame_id, parts: new Array(f.parts), got: 0, w: f.width, h: f.height };
    } else if (f.frame_id < this.current.id || f.parts !== this.current.parts.length) {
      return null;
    }
    const c = this.current;
    if (c.parts[f.part] === undefined) {
      c.parts[f.part] = f.data_b64;
      c.got++;
    }
    if (c.got < c.parts.length) return null;
    this.current = null;
    this.lastDone = c.id;
    return { frameId: c.id, width: c.w, height: c.h, jpegB64: joinBase64(c.parts as string[]) };
  }

  reset(): void {
    this.current = null;
    this.lastDone = -1;
  }
}

/**
 * Joins base64 parts. If the sender split the raw bytes on 3-byte boundaries, plain concatenation
 * works; if a part carries padding mid-stream we decode/re-encode to stay correct.
 */
function joinBase64(parts: string[]): string {
  if (parts.slice(0, -1).every((p) => !p.includes("="))) return parts.join("");
  return toBase64(concat(...parts.map(fromBase64)));
}
