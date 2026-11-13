// A deliberately small, strict DER reader: just enough ASN.1 to slice an
// X.509 certificate into the fields the AppTransaction check needs. It never
// decodes anything it does not have to, and it rejects every encoding DER
// forbids (indefinite lengths, non-minimal lengths, high tag numbers,
// trailing bytes) so a malformed certificate fails instead of being guessed at.
//
// Why hand-rolled rather than a library: the only fields read from a
// certificate are either covered by a signature that is verified before they
// are trusted (intermediate and leaf are each checked against their issuer's
// key with WebCrypto) or byte-compared against the pinned Apple root. A
// parsing mistake can therefore only cause a rejection, never acceptance of
// attacker-chosen data. Keeping it in-tree avoids a runtime dependency tree
// and keeps every check visible in this repo.

export interface Tlv {
  tag: number;
  /** Offset of the tag byte within the input. */
  start: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset one past the last content byte. */
  end: number;
  /** The whole element, tag and length included (what X.509 signs). */
  raw: Uint8Array;
  /** The content bytes only. */
  content: Uint8Array;
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
  /** [0] constructed, context-specific (X.509 version). */
  CTX0: 0xa0,
  /** [3] constructed, context-specific (X.509 extensions). */
  CTX3: 0xa3,
} as const;

/** Upper bound on any single length; certificates are a few KB. */
const MAX_LENGTH = 1 << 20;

export function readTlv(bytes: Uint8Array, offset: number, limit = bytes.length): Tlv {
  if (offset >= limit) throw new Error("der: truncated");
  const tag = bytes[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error("der: high tag numbers unsupported");
  let pos = offset + 1;
  if (pos >= limit) throw new Error("der: truncated length");
  const first = bytes[pos++];
  let length: number;
  if (first < 0x80) {
    length = first;
  } else {
    const n = first & 0x7f;
    if (n === 0) throw new Error("der: indefinite length");
    if (n > 3) throw new Error("der: length too large");
    if (pos + n > limit) throw new Error("der: truncated length");
    if (bytes[pos] === 0) throw new Error("der: non-minimal length");
    length = 0;
    for (let i = 0; i < n; i++) length = (length << 8) | bytes[pos++];
    if (length < 0x80) throw new Error("der: non-minimal length");
  }
  if (length > MAX_LENGTH) throw new Error("der: length too large");
  const end = pos + length;
  if (end > limit) throw new Error("der: truncated content");
  return {
    tag,
    start: offset,
    contentStart: pos,
    end,
    raw: bytes.subarray(offset, end),
    content: bytes.subarray(pos, end),
  };
}

/** Parses `bytes` as exactly one element, with nothing after it. */
export function readOnly(bytes: Uint8Array): Tlv {
  const tlv = readTlv(bytes, 0);
  if (tlv.end !== bytes.length) throw new Error("der: trailing bytes");
  return tlv;
}

/** The elements inside a constructed element, in order. */
export function children(parent: Tlv): Tlv[] {
  if ((parent.tag & 0x20) === 0) throw new Error("der: not constructed");
  const out: Tlv[] = [];
  let pos = 0;
  while (pos < parent.content.length) {
    const child = readTlv(parent.content, pos);
    out.push(child);
    pos = child.end;
  }
  return out;
}

export function expectTag(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (!tlv || tlv.tag !== tag) throw new Error(`der: expected ${what}`);
  return tlv;
}

/** Dotted-decimal form of an OBJECT IDENTIFIER's content bytes. */
export function decodeOid(tlv: Tlv): string {
  expectTag(tlv, TAG.OID, "OID");
  const c = tlv.content;
  if (c.length === 0) throw new Error("der: empty OID");
  const arcs: number[] = [];
  let value = 0;
  let started = false;
  for (let i = 0; i < c.length; i++) {
    const b = c[i];
    if (!started && b === 0x80) throw new Error("der: non-minimal OID arc");
    started = true;
    value = value * 128 + (b & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER / 128) throw new Error("der: OID arc too large");
    if ((b & 0x80) === 0) {
      arcs.push(value);
      value = 0;
      started = false;
    }
  }
  if (started) throw new Error("der: truncated OID");
  const head = arcs[0];
  const firstArc = head < 40 ? 0 : head < 80 ? 1 : 2;
  return [firstArc, head - firstArc * 40, ...arcs.slice(1)].join(".");
}

/** UTCTime / GeneralizedTime (the `Z` forms RFC 5280 §4.1.2.5 mandates) → epoch ms. */
export function decodeTime(tlv: Tlv): number {
  const s = new TextDecoder().decode(tlv.content);
  let m: RegExpExecArray | null;
  let year: number;
  if (tlv.tag === TAG.UTC_TIME) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error("der: bad UTCTime");
    const yy = Number(m[1]);
    year = yy >= 50 ? 1900 + yy : 2000 + yy; // RFC 5280 §4.1.2.5.1
  } else if (tlv.tag === TAG.GENERALIZED_TIME) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
    if (!m) throw new Error("der: bad GeneralizedTime");
    year = Number(m[1]);
  } else {
    throw new Error("der: expected a time");
  }
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

/** Unsigned big-endian INTEGER content, leading zero stripped. */
export function integerBytes(tlv: Tlv): Uint8Array {
  expectTag(tlv, TAG.INTEGER, "INTEGER");
  const c = tlv.content;
  if (c.length === 0) throw new Error("der: empty INTEGER");
  if (c[0] & 0x80) throw new Error("der: negative INTEGER");
  if (c.length > 1 && c[0] === 0 && (c[1] & 0x80) === 0) throw new Error("der: non-minimal INTEGER");
  return c[0] === 0 && c.length > 1 ? c.subarray(1) : c;
}

/** BIT STRING content with zero unused bits (all X.509 bit strings we read). */
export function bitStringBytes(tlv: Tlv): Uint8Array {
  expectTag(tlv, TAG.BIT_STRING, "BIT STRING");
  if (tlv.content.length === 0 || tlv.content[0] !== 0) throw new Error("der: unexpected unused bits");
  return tlv.content.subarray(1);
}
