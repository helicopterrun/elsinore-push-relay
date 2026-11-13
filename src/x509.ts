// X.509 certificate slicing and ECDSA signature checks over WebCrypto — only
// what verifying an App Store JWS chain needs (RFC 5280 §4.1 layout). Apple's
// App Store chain is all ECDSA: the root and the WWDR intermediate are P-384
// keys signing with ecdsa-with-SHA384, and the leaf carries the P-256 key that
// signs the ES256 JWS. RSA and other algorithms are rejected.

import {
  TAG,
  bitStringBytes,
  children,
  decodeOid,
  decodeTime,
  expectTag,
  integerBytes,
  readOnly,
  type Tlv,
} from "./der";
import { buf, bytesEqual } from "./encoding";

export interface Extension {
  critical: boolean;
  /** The extnValue OCTET STRING's content (the DER of the extension value). */
  value: Uint8Array;
}

export interface Certificate {
  raw: Uint8Array;
  /** The exact signed bytes: the tbsCertificate element as it appeared on the wire. */
  tbs: Uint8Array;
  signatureAlgorithm: string;
  signature: Uint8Array;
  /** DER of the issuer / subject Name, compared byte-for-byte for chaining. */
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: number;
  notAfter: number;
  /** DER SubjectPublicKeyInfo, importable with `crypto.subtle.importKey("spki", …)`. */
  spki: Uint8Array;
  keyAlgorithm: string;
  /** Named curve OID for EC keys; null otherwise. */
  namedCurve: string | null;
  extensions: Map<string, Extension>;
}

export const OID = {
  ecPublicKey: "1.2.840.10045.2.1",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  ecdsaWithSha384: "1.2.840.10045.4.3.3",
  basicConstraints: "2.5.29.19",
} as const;

const CURVES: Record<string, { name: "P-256" | "P-384"; size: number }> = {
  [OID.p256]: { name: "P-256", size: 32 },
  [OID.p384]: { name: "P-384", size: 48 },
};

const SIGNATURE_HASHES: Record<string, "SHA-256" | "SHA-384"> = {
  [OID.ecdsaWithSha256]: "SHA-256",
  [OID.ecdsaWithSha384]: "SHA-384",
};

function algorithmOid(alg: Tlv): string {
  const parts = children(expectTag(alg, TAG.SEQUENCE, "AlgorithmIdentifier"));
  return decodeOid(parts[0]);
}

export function parseCertificate(der: Uint8Array): Certificate {
  const cert = expectTag(readOnly(der), TAG.SEQUENCE, "Certificate");
  const [tbsTlv, sigAlgTlv, sigTlv, ...rest] = children(cert);
  if (rest.length) throw new Error("x509: trailing Certificate fields");
  expectTag(tbsTlv, TAG.SEQUENCE, "tbsCertificate");

  const fields = children(tbsTlv);
  let i = 0;
  // version [0] EXPLICIT — required to be v3 (value 2) since we need extensions.
  const versionTlv = expectTag(fields[i++], TAG.CTX0, "version");
  const version = integerBytes(children(versionTlv)[0]);
  if (version.length !== 1 || version[0] !== 2) throw new Error("x509: not a v3 certificate");
  expectTag(fields[i++], TAG.INTEGER, "serialNumber");
  const innerSigAlg = algorithmOid(fields[i++]);
  const issuer = expectTag(fields[i++], TAG.SEQUENCE, "issuer");
  const validity = children(expectTag(fields[i++], TAG.SEQUENCE, "validity"));
  if (validity.length !== 2) throw new Error("x509: bad validity");
  const subject = expectTag(fields[i++], TAG.SEQUENCE, "subject");
  const spkiTlv = expectTag(fields[i++], TAG.SEQUENCE, "subjectPublicKeyInfo");

  const spkiAlg = children(expectTag(children(spkiTlv)[0], TAG.SEQUENCE, "SPKI algorithm"));
  const keyAlgorithm = decodeOid(spkiAlg[0]);
  const namedCurve = keyAlgorithm === OID.ecPublicKey && spkiAlg[1]?.tag === TAG.OID ? decodeOid(spkiAlg[1]) : null;

  const extensions = new Map<string, Extension>();
  for (; i < fields.length; i++) {
    const f = fields[i];
    if (f.tag !== TAG.CTX3) continue; // issuerUniqueID / subjectUniqueID: ignored
    for (const ext of children(expectTag(children(f)[0], TAG.SEQUENCE, "Extensions"))) {
      const parts = children(expectTag(ext, TAG.SEQUENCE, "Extension"));
      const oid = decodeOid(parts[0]);
      let critical = false;
      let valueTlv = parts[1];
      if (valueTlv?.tag === TAG.BOOLEAN) {
        critical = valueTlv.content.length === 1 && valueTlv.content[0] === 0xff;
        valueTlv = parts[2];
      }
      expectTag(valueTlv, TAG.OCTET_STRING, "extnValue");
      if (extensions.has(oid)) throw new Error("x509: duplicate extension");
      extensions.set(oid, { critical, value: valueTlv.content });
    }
  }

  const signatureAlgorithm = algorithmOid(sigAlgTlv);
  // RFC 5280 §4.1.1.2: the outer and inner algorithm identifiers must match.
  if (signatureAlgorithm !== innerSigAlg) throw new Error("x509: signature algorithm mismatch");

  return {
    raw: der,
    tbs: tbsTlv.raw,
    signatureAlgorithm,
    signature: bitStringBytes(sigTlv),
    issuer: issuer.raw,
    subject: subject.raw,
    notBefore: decodeTime(validity[0]),
    notAfter: decodeTime(validity[1]),
    spki: spkiTlv.raw,
    keyAlgorithm,
    namedCurve,
    extensions,
  };
}

/** basicConstraints cA flag (RFC 5280 §4.2.1.9); false when the extension is absent. */
export function isCA(cert: Certificate): boolean {
  const ext = cert.extensions.get(OID.basicConstraints);
  if (!ext) return false;
  const seq = children(expectTag(readOnly(ext.value), TAG.SEQUENCE, "BasicConstraints"));
  const first = seq[0];
  return first?.tag === TAG.BOOLEAN && first.content.length === 1 && first.content[0] === 0xff;
}

/** Imports an EC public key from a certificate for ECDSA verification. */
export async function importEcKey(cert: Certificate): Promise<{ key: CryptoKey; size: number }> {
  if (cert.keyAlgorithm !== OID.ecPublicKey || !cert.namedCurve) throw new Error("x509: not an EC key");
  const curve = CURVES[cert.namedCurve];
  if (!curve) throw new Error("x509: unsupported curve");
  const key = await crypto.subtle.importKey(
    "spki",
    buf(cert.spki),
    { name: "ECDSA", namedCurve: curve.name },
    false,
    ["verify"],
  );
  return { key, size: curve.size };
}

/**
 * X.509 carries ECDSA signatures as DER `SEQUENCE { r INTEGER, s INTEGER }`;
 * WebCrypto wants the fixed-width `r || s` concatenation.
 */
export function ecdsaDerToRaw(sig: Uint8Array, size: number): Uint8Array {
  const parts = children(expectTag(readOnly(sig), TAG.SEQUENCE, "ECDSA-Sig-Value"));
  if (parts.length !== 2) throw new Error("x509: bad ECDSA signature");
  const out = new Uint8Array(size * 2);
  parts.forEach((p, idx) => {
    const n = integerBytes(p);
    if (n.length > size) throw new Error("x509: ECDSA integer too large");
    out.set(n, idx * size + (size - n.length));
  });
  return out;
}

/** True when `cert` was signed by `issuer`'s key and names it as its issuer. */
export async function isSignedBy(cert: Certificate, issuer: Certificate): Promise<boolean> {
  if (!bytesEqual(cert.issuer, issuer.subject)) return false;
  const hash = SIGNATURE_HASHES[cert.signatureAlgorithm];
  if (!hash) return false;
  const { key, size } = await importEcKey(issuer);
  return crypto.subtle.verify(
    { name: "ECDSA", hash },
    key,
    buf(ecdsaDerToRaw(cert.signature, size)),
    buf(cert.tbs),
  );
}
