# Bitcoin Transaction Parser and Signature Extractor

This project contains a Python script that **parses Bitcoin transaction data**, extracts **signatures** and **public keys**, and performs additional cryptographic operations. It helps explore Bitcoin's transaction structure by extracting key components like `r`, `s` values from signatures and calculating the **z-value (hashed message)** used in signing.

## Features
- Parses **Bitcoin transactions** from JSON.
- Extracts **signatures** and **public keys** from input scripts.
- Decodes **DER-encoded** signatures to get `r` and `s` values.
- Calculates the **z-value** (H(m)) for cryptographic validation.
- Handles transaction serialization and hashing using **double SHA-256**.

---

## Prerequisites

Ensure you have Python installed. The following libraries are required:

```bash
pip install ecdsa
