# CryptoShield X — Static Crypto Inventory Report

**Triage only:** findings require source and protocol review; this is not proof of vulnerability.

## Scan summary

- Files scanned: 3
- Scan duration: 0.001512 seconds
- Findings: 3
- Rules: 13

## Risk distribution

| Risk | Count |
|---|---:|
| high | 3 |

## Findings

| File | Line | Rule | Algorithm | Operation | Risk | Evidence |
|---|---:|---|---|---|---|---|
| `example.c` | 2 | `C_OPENSSL_RSA` | RSA | key_generation_or_public_key_crypto | high | `void demo(void) { RSA_generate_key_ex(NULL, 2048, NULL, NULL); }` |
| `Example.java` | 2 | `JAVA_EC` | Elliptic curve | key_generation_or_signature | high | `class Example { void setup() throws Exception { KeyPairGenerator generator = KeyPairGenerator.getInstance("EC"); } }` |
| `example.py` | 2 | `PY_RSA_KEYGEN` | RSA | key_generation | high | `private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)` |

## Migration triage notes

- **example.c:2 — C_OPENSSL_RSA**: Inspect the surrounding code to distinguish RSA key generation, encryption, key establishment, and signatures. Assess ML-KEM for key establishment and ML-DSA for signatures where appropriate; validate the OpenSSL version, provider support, and protocol.
- **Example.java:2 — JAVA_EC**: The matched API alone may not reveal the full purpose. Determine whether the implementation uses ECDSA signatures or ECDH key agreement. Assess ML-DSA for signatures and ML-KEM for key establishment, then validate protocol and library compatibility.
- **example.py:2 — PY_RSA_KEYGEN**: Confirm whether RSA is used for key establishment, encryption, or digital signatures. For key establishment, assess a vetted ML-KEM-based design; for signatures, assess ML-DSA. Validate protocol support, library availability, and interoperability.

## Limitations

- Line-based patterns can miss aliases, wrappers and split expressions.
- Risk labels are triage categories, not a formal risk score.
- Recommendations require protocol/library/test validation.
- No precision/recall is reported without authorized ground truth.
