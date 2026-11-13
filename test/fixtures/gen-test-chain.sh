#!/usr/bin/env bash
# Regenerates the TEST-ONLY certificate chains used by test/appTransaction.test.ts
# and test/worker.test.ts. They imitate the shape of Apple's App Store JWS chain
# (P-384 root and intermediate signing with SHA-384, P-256 leaf, Apple's marker
# extension OIDs) but chain to a throwaway root, never to Apple's.
#
#   test/fixtures/gen-test-chain.sh      # needs OpenSSL 3
#
# Only the leaf private key is kept (tests sign JWS with it). It protects
# nothing: it is a test key for a test root no real verifier trusts.
set -euo pipefail
cd "$(dirname "$0")/chain"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/ext.cnf" <<'CNF'
[inter]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
1.2.840.113635.100.6.2.1 = ASN1:NULL
[inter_not_ca]
basicConstraints = critical,CA:false
keyUsage = critical,keyCertSign,cRLSign
1.2.840.113635.100.6.2.1 = ASN1:NULL
[inter_no_marker]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
[leaf]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
1.2.840.113635.100.6.11.1 = ASN1:NULL
[leaf_no_marker]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
CNF

ec() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$1" -out "$2" 2>/dev/null; }

root() { # name
  ec P-384 "$work/$1.key"
  openssl req -x509 -new -key "$work/$1.key" -sha384 -days 3650 -subj "/CN=Test Root $1/O=Relay Tests" \
    -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$1.pem"
}

issue() { # name curve issuer section days
  ec "$2" "$work/$1.key"
  openssl req -new -key "$work/$1.key" -subj "/CN=Test $1/O=Relay Tests" -out "$work/$1.csr"
  openssl x509 -req -in "$work/$1.csr" -CA "$3.pem" -CAkey "$work/$3.key" -sha384 -days "$5" \
    -set_serial "0x$(openssl rand -hex 8)" -extfile "$work/ext.cnf" -extensions "$4" -out "$1.pem" 2>/dev/null
}

root root
issue intermediate P-384 root inter 1825
issue intermediate-not-ca P-384 root inter_not_ca 1825
issue intermediate-no-marker P-384 root inter_no_marker 1825
issue leaf P-256 intermediate leaf 730
# Every other leaf reuses the one kept leaf key, so tests need only one signer.
for v in leaf-no-marker:intermediate:leaf_no_marker leaf-under-not-ca:intermediate-not-ca:leaf \
         leaf-under-no-marker:intermediate-no-marker:leaf; do
  IFS=: read -r name issuer section <<<"$v"
  openssl req -new -key "$work/leaf.key" -subj "/CN=Test $name/O=Relay Tests" -out "$work/$name.csr"
  openssl x509 -req -in "$work/$name.csr" -CA "$issuer.pem" -CAkey "$work/$issuer.key" -sha384 -days 730 \
    -set_serial "0x$(openssl rand -hex 8)" -extfile "$work/ext.cnf" -extensions "$section" -out "$name.pem" 2>/dev/null
done

# A second, unrelated hierarchy: the "wrong root" cases.
root rogue-root
issue rogue-intermediate P-384 rogue-root inter 1825
openssl req -new -key "$work/leaf.key" -subj "/CN=Test rogue-leaf/O=Relay Tests" -out "$work/rogue-leaf.csr"
openssl x509 -req -in "$work/rogue-leaf.csr" -CA rogue-intermediate.pem -CAkey "$work/rogue-intermediate.key" \
  -sha384 -days 730 -set_serial "0x$(openssl rand -hex 8)" -extfile "$work/ext.cnf" -extensions leaf \
  -out rogue-leaf.pem 2>/dev/null

openssl pkey -in "$work/leaf.key" -out leaf-TEST-ONLY.key.pem
echo "wrote $(ls | wc -l | tr -d ' ') files to $(pwd)"
