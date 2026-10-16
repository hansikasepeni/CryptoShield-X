# CryptoShield X — Static Crypto Inventory Report

**Triage only:** findings require source and protocol review; this is not proof of vulnerability.

## Scan summary

- Files scanned: 3
- Scan duration: 0.000905 seconds
- Findings: 3
- Rules: 13

## Risk distribution

| Risk | Count |
|---|---:|
| high | 3 |

## Findings

| File | Line | Rule | Algorithm | Operation | Risk | Evidence |
|---|---:|---|---|---|---|---|
| `Example.java` | 2 | `JAVA_EC` | Elliptic curve | key_generation_or_signature | high | `class Example { void setup() throws Exception { KeyPairGenerator generator = KeyPairGenerator.getInstance("EC"); } }` |
| `example.c` | 2 | `C_OPENSSL_RSA` | RSA | key_generation_or_public_key_crypto | high | `void demo(void) { RSA_generate_key_ex(NULL, 2048, NULL, NULL); }` |
| `example.py` | 2 | `PY_RSA_KEYGEN` | RSA | key_generation | high | `private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)` |

## Migration triage notes

- **Example.java:2 — JAVA_EC**: For signatures evaluate ML-DSA; for key agreement evaluate ML-KEM separately.
- **example.c:2 — C_OPENSSL_RSA**: Inspect whether RSA is used for key transport, signing or another role.
- **example.py:2 — PY_RSA_KEYGEN**: Determine whether RSA supports key establishment or signatures; choose a purpose-appropriate PQC design.

## Limitations

- Line-based patterns can miss aliases, wrappers and split expressions.
- Risk labels are triage categories, not a formal risk score.
- Recommendations require protocol/library/test validation.
- No precision/recall is reported without authorized ground truth.
