# 🔐 KMS Core: TR-31 & DUKPT Key Exchange Engine

A robust, Python-based cryptographic engine designed for the secure generation, exchange, and derivation of financial keys. This project strictly adheres to banking standards such as **ANSI X9.24** for TR-31 key blocks and implements **DUKPT** (Derived Unique Key Per Transaction).

Designed with a focus on security architecture, it enforces Split Knowledge, Dual Control, and cryptographic-grade entropy for Key Management Systems (KMS).

---

## 🚀 Core Features

* **Dual Control & Split Knowledge:** Secure recombination of Master Key (KEK) components using XOR operations, ensuring no single entity possesses the cleartext key.
* **ANSI X9.24 TR-31 Keyblocks:** * Generation and wrapping of PIN Encryption Keys (PEK) utilizing AES-256 KEKs.
  * Explicit implementation of **Version ID `D`** block headers to support advanced AES encryption (bypassing default TDES limitations).
  * Strict validation of MAC/Integrity during key unwrapping.
* **DUKPT Derivation:** Dynamic derivation of working keys from a Base Derivation Key (BDK) and Key Serial Number (KSN) for 3DES ECB payload decryption.
* **AES-CMAC Validation:** Cryptographic verification of Key Check Values (KCV) to ensure key integrity during import/export operations.

---

## 🛠️ Technology Stack

* **Language:** Python 3.11+
* **Cryptography:** `cryptography` (AES, 3DES, CMAC, OS Entropy)
* **Financial Standards:** `psec` (TR-31 / ANSI X9.24 implementation)
* **Dynamic Keys:** `dukpt`

---

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/CallMeUnlucky/tr31-key-exchange-kms.git](https://github.com/CallMeUnlucky/tr31-key-exchange-kms.git)
   cd tr31-key-exchange-kms
