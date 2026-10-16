
RULES = [
    {
        "id": "PY_RSA_KEYGEN",
        "languages": ["python"],
        "pattern": r"\b(RSA\.generate|rsa\.generate_private_key)\s*\(",
        "algorithm": "RSA",
        "operation": "key_generation",
        "risk": "high",
        "confidence": "high",
        "recommendation": (
            "Confirm whether RSA is used for key establishment, encryption, "
            "or digital signatures. For key establishment, assess a vetted "
            "ML-KEM-based design; for signatures, assess ML-DSA. Validate "
            "protocol support, library availability, and interoperability."
        ),
    },
    {
        "id": "PY_ECC",
        "languages": ["python"],
        "pattern": r"\b(ec\.generate_private_key|EllipticCurvePrivateKey|SECP\d+R\d*)\b",
        "algorithm": "Elliptic curve",
        "operation": "key_agreement_or_signature",
        "risk": "high",
        "confidence": "medium",
        "recommendation": (
            "Identify the actual operation before planning migration. "
            "For ECDH key agreement, assess ML-KEM; for ECDSA signatures, "
            "assess ML-DSA. Confirm protocol and library compatibility."
        ),
    },
    {
        "id": "PY_DH",
        "languages": ["python"],
        "pattern": r"\b(dh\.generate_parameters|DHParameterNumbers|DHPublicNumbers)\b",
        "algorithm": "Diffie-Hellman",
        "operation": "key_establishment",
        "risk": "high",
        "confidence": "medium",
        "recommendation": (
            "Confirm that the code performs Diffie-Hellman key establishment. "
            "Assess a vetted ML-KEM-based design and validate protocol "
            "integration, key handling, and interoperability."
        ),
    },
    {
        "id": "PY_HASH_WEAK",
        "languages": ["python"],
        "pattern": r"\bhashlib\.(md5|sha1)\s*\(",
        "algorithm": "MD5/SHA-1",
        "operation": "hashing",
        "risk": "review",
        "confidence": "medium",
        "recommendation": (
            "Determine whether the hash is used for signatures, integrity, "
            "password storage, or non-security purposes. Select a suitable "
            "modern hash or password-hashing scheme for that role; this is "
            "not automatically a public-key post-quantum migration."
        ),
    },
    {
        "id": "PY_AES",
        "languages": ["python"],
        "pattern": r"\b(AES\.new|algorithms\.AES)\s*\(",
        "algorithm": "AES",
        "operation": "symmetric_encryption",
        "risk": "context_dependent",
        "confidence": "medium",
        "recommendation": (
            "Review AES key size, encryption mode, nonce handling, and "
            "authentication requirements. Consider applicable quantum "
            "security margins and system policy; do not replace AES solely "
            "because a public-key algorithm elsewhere is quantum-vulnerable."
        ),
    },
    {
        "id": "JAVA_RSA",
        "languages": ["java"],
        "pattern": r'\b(KeyPairGenerator\.getInstance\s*\(\s*"RSA"|Cipher\.getInstance\s*\(\s*"RSA")',
        "algorithm": "RSA",
        "operation": "key_generation_or_encryption",
        "risk": "high",
        "confidence": "high",
        "recommendation": (
            "Inspect the RSA use and its protocol role. For key establishment "
            "or public-key encryption, assess an appropriate ML-KEM-based "
            "design; for signatures, assess ML-DSA. Validate API support and "
            "interoperability rather than assuming a drop-in replacement."
        ),
    },
    {
        "id": "JAVA_EC",
        "languages": ["java"],
        "pattern": r'\b(KeyPairGenerator\.getInstance\s*\(\s*"EC"|Signature\.getInstance\s*\(\s*"SHA\d+withECDSA")',
        "algorithm": "Elliptic curve",
        "operation": "key_generation_or_signature",
        "risk": "high",
        "confidence": "high",
        "recommendation": (
            "The matched API alone may not reveal the full purpose. Determine "
            "whether the implementation uses ECDSA signatures or ECDH key "
            "agreement. Assess ML-DSA for signatures and ML-KEM for key "
            "establishment, then validate protocol and library compatibility."
        ),
    },
    {
        "id": "JAVA_DH",
        "languages": ["java"],
        "pattern": r'\b(KeyPairGenerator\.getInstance\s*\(\s*"DH"|KeyAgreement\.getInstance\s*\(\s*"DH")',
        "algorithm": "Diffie-Hellman",
        "operation": "key_establishment",
        "risk": "high",
        "confidence": "high",
        "recommendation": (
            "Confirm the Diffie-Hellman key-establishment flow. Assess a "
            "vetted ML-KEM-based design, including protocol integration, "
            "library support, and interoperability."
        ),
    },
    {
        "id": "JAVA_SHA1",
        "languages": ["java"],
        "pattern": r'\bMessageDigest\.getInstance\s*\(\s*"SHA-?1"',
        "algorithm": "SHA-1",
        "operation": "hashing",
        "risk": "review",
        "confidence": "high",
        "recommendation": (
            "Determine the SHA-1 security role and compatibility constraints. "
            "For security-sensitive hashing, evaluate a suitable modern hash "
            "and update dependent protocols or formats as needed."
        ),
    },
    {
        "id": "C_OPENSSL_RSA",
        "languages": ["c"],
        "pattern": r'\b(RSA_generate_key_ex|EVP_PKEY_RSA)\b',
        "algorithm": "RSA",
        "operation": "key_generation_or_public_key_crypto",
        "risk": "high",
        "confidence": "high",
        "recommendation": (
            "Inspect the surrounding code to distinguish RSA key generation, "
            "encryption, key establishment, and signatures. Assess ML-KEM "
            "for key establishment and ML-DSA for signatures where appropriate; "
            "validate the OpenSSL version, provider support, and protocol."
        ),
    },
    {
        "id": "C_OPENSSL_EC",
        "languages": ["c"],
        "pattern": r'\b(EC_KEY_new_by_curve_name|EVP_PKEY_EC|ECDSA_sign|ECDH_compute_key)\b',
        "algorithm": "Elliptic curve",
        "operation": "key_agreement_or_signature",
        "risk": "high",
        "confidence": "high",
        "recommendation": (
            "Inspect the call site to distinguish ECDH key agreement from "
            "ECDSA signatures. Assess ML-KEM for key establishment and "
            "ML-DSA for signatures; verify library and protocol compatibility."
        ),
    },
    {
        "id": "C_OPENSSL_DH",
        "languages": ["c"],
        "pattern": r'\b(DH_generate_key|DH_compute_key)\b',
        "algorithm": "Diffie-Hellman",
        "operation": "key_establishment",
        "risk": "high",
        "confidence": "high",
        "recommendation": (
            "Confirm how the Diffie-Hellman shared secret is established. "
            "Assess a vetted ML-KEM-based design and validate library support, "
            "protocol integration, and interoperability."
        ),
    },
    {
        "id": "C_WEAK_HASH",
        "languages": ["c"],
        "pattern": r'\b(MD5_Init|SHA1_Init)\b',
        "algorithm": "MD5/SHA-1",
        "operation": "hashing",
        "risk": "review",
        "confidence": "medium",
        "recommendation": (
            "Determine whether MD5 or SHA-1 protects signatures, integrity, "
            "or another function. Choose an appropriate modern alternative "
            "for the specific role; do not treat this finding alone as proof "
            "that public-key post-quantum migration is required."
        ),
    },
]
