// Byte/string helpers shared by the credential and AppTransaction code. Strict
// decoders: anything outside the expected alphabet throws, so a malformed
// token fails closed instead of decoding to something surprising.

const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(bytes: Uint8Array): string {
  // fatal: invalid UTF-8 throws rather than decoding to U+FFFD.
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
}

function bytesToBinary(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function binaryToBytes(raw: string): Uint8Array {
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** Base64url without padding (RFC 7515 §2). */
export function b64urlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return btoa(bytesToBinary(bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url decode: unpadded, url alphabet only. */
export function b64urlDecode(s: string): Uint8Array {
  if (!B64URL_RE.test(s) || s.length % 4 === 1) throw new Error("invalid base64url");
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  return binaryToBytes(atob(std + "=".repeat((4 - (std.length % 4)) % 4)));
}

/** Standard base64 (with padding), as used by the JWS `x5c` header (RFC 7515 §4.1.6). */
export function b64Decode(s: string): Uint8Array {
  if (!B64_RE.test(s) || s.length % 4 !== 0) throw new Error("invalid base64");
  return binaryToBytes(atob(s));
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** WebCrypto wants a BufferSource backed by a plain ArrayBuffer. */
export function buf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
