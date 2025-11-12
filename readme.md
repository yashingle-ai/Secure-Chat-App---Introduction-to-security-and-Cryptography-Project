
# 🔐 Secure Chat System (E2EE with Argon2, AES-CBC, Ed25519, SHA-256)

### 📘 Institute: SVNIT Surat

### 💻 Department: Artificial Intelligence

### 👨‍💻 Team Members:

* **Yash Ingle**
* **Deep Das**

---

## 📜 Overview

This project implements a **secure end-to-end encrypted (E2EE) messaging system** designed for confidential and authenticated communication between users.
It integrates **modern cryptographic primitives** — *Argon2, AES-CBC, Ed25519, SHA-256, and Salsa20/Poly1305* — to ensure **confidentiality**, **integrity**, **authentication**, and **secure key storage**.

---

## 🔄 System Workflows

### 🧩 **Login Flow**

```
User Input → Password Verification (Argon2) → Load User Data → Menu Access
```

* Verifies the user’s password securely using Argon2.
* Loads encrypted keys and user metadata for authenticated access.

---

### ✉️ **Message Sending Flow**

```
Compose Message 
→ Decrypt Sender’s Signing Key 
→ AES-CBC Encrypt 
→ Ed25519 Sign 
→ SHA-256 Hash 
→ Store in Recipient’s Inbox
```

Each outgoing message is encrypted, signed, and integrity-verified before delivery.

---

### 📬 **Message Reading Flow**

```
Select Inbox 
→ Decrypt User’s Keys 
→ AES-CBC Decrypt 
→ Verify Signature 
→ Verify Hash (Integrity) 
→ Display Message
```

Messages are decrypted only after authentication and integrity checks pass.

---

## 🧠 Cryptographic Components

### 1. 🧩 **Argon2 (Password Hashing)**

* **Purpose:** Secure password storage and key derivation.
* **Type:** Memory-hard key derivation function (resists GPU attacks).
* **Functions:**

  * `crypto_pwhash_str()` → Hash password for storage
  * `crypto_pwhash_str_verify()` → Verify password at login
  * `crypto_pwhash()` → Derive symmetric keys from password
* **Effect:** Prevents brute-force and rainbow-table attacks.

---

### 2. 🖋️ **Ed25519 (Digital Signatures)**

* **Purpose:** Message authentication and non-repudiation.
* **Type:** EdDSA (Edwards-curve Digital Signature Algorithm).
* **Key Size:** 32-byte public key, 64-byte private key.
* **Functions:**

  * `crypto_sign_keypair()` → Generate signing keypair
  * `crypto_sign_detached()` → Sign message
  * `crypto_sign_verify_detached()` → Verify signature

---

### 3. 🧾 **SHA-256 (Message Integrity)**

* **Purpose:** Detect message tampering.
* **Output:** 256-bit digest (64 hex characters).
* **Function:** `crypto_hash_sha256()`
* **Process:**
  Message → SHA-256 → Fixed-size hash

  * If *Received Hash = Computed Hash*, message is intact ✅

---

### 4. 🔐 **Salsa20/Poly1305 (Private Key Encryption)**

* **Purpose:** Encrypt user’s private keys at rest.
* **Algorithm Type:** Authenticated Encryption (AEAD).
* **Components:**

  * **Salsa20:** Stream cipher (confidentiality)
  * **Poly1305:** Message Authentication Code (authenticity)
* **Functions:**

  * `crypto_secretbox_easy()` → Encrypt private key
  * `crypto_secretbox_open_easy()` → Decrypt private key

---

### 5. 🎲 **Random Number Generation**

* **Algorithm:** ChaCha20-based CSPRNG (Cryptographically Secure RNG).
* **Function:** `randombytes_buf()`
* **Usage:** Generates random keys, IVs, salts, and nonces for cryptographic operations.

---

### 6. 🔤 **Base64 Encoding**

* **Purpose:** Convert binary data to text for JSON storage/transmission.
* **Functions:**

  * `sodium_bin2base64()` → Binary → Base64
  * `sodium_base642bin()` → Base64 → Binary

---

## 🧱 Security Architecture

| Property            | Algorithm                 | Purpose                         |
| ------------------- | ------------------------- | ------------------------------- |
| **Confidentiality** | AES-CBC                   | Encrypts plaintext messages     |
| **Authentication**  | Ed25519                   | Verifies sender identity        |
| **Integrity**       | SHA-256                   | Detects message tampering       |
| **Key Protection**  | Argon2 + Salsa20/Poly1305 | Protects keys at rest           |
| **Randomness**      | ChaCha20 CSPRNG           | Ensures secure nonces and salts |

---

## 📦 Message Structure

Each stored message (in recipient’s inbox) follows a secure JSON format:

```json
{
  "cipher_b64": "AES-CBC encrypted message",
  "iv_b64": "Initialization vector",
  "sender": "sender_username",
  "sign_pub_b64": "Sender's Ed25519 public key",
  "signature_b64": "Ed25519 signature of plaintext",
  "sha256": "SHA-256 hash of plaintext",
  "timestamp": "2024-11-10 15:30:45"
}
```

---

## ⚙️ Hybrid Cryptosystem Design

| Layer                         | Algorithm        | Function                             |
| ----------------------------- | ---------------- | ------------------------------------ |
| **Symmetric Encryption**      | AES-CBC          | Efficient message encryption         |
| **Asymmetric Authentication** | Ed25519          | Message signing & verification       |
| **Hash Function**             | SHA-256          | Message integrity verification       |
| **Password Hashing**          | Argon2           | Secure password-based key derivation |
| **Authenticated Encryption**  | Salsa20/Poly1305 | Protect private keys at rest         |

---

## 🧩 Internal Working Summary

### **Argon2**

* Password + Salt → Multiple memory passes → Derived Key
* Output: 32-byte secure hash used for encryption or verification.

### **Ed25519**

* ECC-based digital signature system.
* Private Key + Message → Signature (R, S)
* Public Key verifies the elliptic-curve relationship.

### **SHA-256**

* Processes 512-bit blocks over 64 rounds of modular arithmetic & bitwise operations.
* Output: 256-bit digest unique to input data.

### **Salsa20/Poly1305**

* Salsa20 generates pseudorandom keystream (XOR with plaintext).
* Poly1305 computes MAC over ciphertext to ensure authenticity before decryption.

---

## 🧮 Example End-to-End Security Flow

```
Plaintext → AES-CBC Encrypt → Ciphertext
Ciphertext + Signature + Hash → Stored Securely
Recipient → Decrypt + Verify Signature + Verify Hash → Display Message
```

---

## 🏁 Conclusion

This system demonstrates a **complete cryptographic communication pipeline** integrating **password security**, **key protection**, **confidential messaging**, and **integrity verification**.
It serves as a practical example of **hybrid cryptography** and **end-to-end encryption** using **libsodium** primitives.

---

## 🧑‍🤝‍🧑 Contributors

| Name           | Role                                    | Department       |
| -------------- | --------------------------------------- | ---------------- |
| **Yash Ingle** | Developer & Cryptography Implementation | SVNIT Surat (AI) |
| **Deep Das**   | Developer & Security Flow Design        | SVNIT Surat (AI) |

---

## 📚 References

* [Libsodium Documentation](https://doc.libsodium.org)
* [RFC 9106 – Argon2 Password Hashing](https://www.rfc-editor.org/rfc/rfc9106)
* [RFC 8032 – Ed25519 Signatures](https://www.rfc-editor.org/rfc/rfc8032)
* [NIST FIPS 180-4 – SHA-256 Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

---

