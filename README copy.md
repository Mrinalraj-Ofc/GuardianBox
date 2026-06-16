# 🛡️ GuardianBox — End-to-End Encrypted File Sharing

> *"The server is blind. It stores your file. It cannot read it."*

A full-stack security internship project demonstrating **zero-knowledge architecture**, **client-side cryptography**, and **applied AES-256-GCM** using the browser-native Web Crypto API.

---

## Table of Contents

1. [Case Study — Why E2EE File Sharing Matters](#1-case-study)
2. [Cryptography Deep Dive](#2-cryptography-deep-dive)
3. [System Architecture](#3-system-architecture)
4. [How the URL Fragment Trick Works](#4-the-url-fragment-trick)
5. [Security Analysis — Attack Vectors](#5-security-analysis)
6. [Ephemeral Storage Design](#6-ephemeral-storage)
7. [Getting Started](#7-getting-started)
8. [Project Structure](#8-project-structure)

---

## 1. Case Study

### The Problem with Conventional Cloud Storage

When you upload a file to Google Drive, Dropbox, or any standard cloud service, **the service holds your encryption keys**. This means:

| Threat                        | Traditional Cloud | GuardianBox |
|-------------------------------|:-----------------:|:-----------:|
| Server-side data breach       | ❌ File exposed    | ✅ Protected |
| Rogue employee access         | ❌ Readable        | ✅ Protected |
| Government subpoena           | ❌ Can comply      | ✅ Nothing to hand over |
| Database leak                 | ❌ Metadata + file | ✅ Useless ciphertext |
| MITM (with HTTPS)             | ❌ Possible        | ✅ E2EE layer |

### Who Needs This?

- **Journalists** sharing source documents
- **Lawyers** sending privileged client files
- **Whistleblowers** transmitting evidence
- **Activists** in high-risk jurisdictions
- **Healthcare** sharing sensitive records

### The Zero-Knowledge Principle

A zero-knowledge system is one where the **service provider gains no usable information** about the data it stores. GuardianBox achieves this by ensuring encryption happens **exclusively in the browser before the upload request is even sent**. The server receives an opaque binary blob it mathematically cannot decrypt.

---

## 2. Cryptography Deep Dive

### Why AES-256-GCM?

**AES-GCM** (Galois/Counter Mode) is the gold standard for authenticated symmetric encryption because it provides:

| Property         | What it means                                                  |
|------------------|---------------------------------------------------------------|
| **Confidentiality** | Ciphertext reveals nothing about plaintext without the key |
| **Integrity**    | Any tampering with the ciphertext causes decryption to fail   |
| **Authentication** | Proves the data hasn't been modified (via 128-bit auth tag) |
| **Performance**  | Hardware-accelerated on all modern CPUs (AES-NI instruction)  |

**Key size — 256 bits:**
2²⁵⁶ ≈ 10⁷⁷ possible keys. Even at 10¹⁸ guesses/second, brute-forcing would take longer than the age of the universe.

### The Initialization Vector (IV / Nonce)

AES-GCM requires a **12-byte random nonce** per encryption. This is critical:

```
Encrypt(plaintext, key, IV₁) = ciphertext₁
Encrypt(plaintext, key, IV₁) = ciphertext₁   ← same IV = identical output (BAD)
Encrypt(plaintext, key, IV₂) = ciphertext₂   ← different IV = different output (GOOD)
```

GuardianBox generates a new cryptographically random IV on every encryption call using `crypto.getRandomValues()`. The IV is not secret — it is stored alongside the ciphertext and sent to the server. Without the key, the IV is useless.

### Key Derivation — PBKDF2

When using **password mode**, the raw password is not used directly as a key (passwords have low entropy). Instead, **PBKDF2-SHA-256** stretches the password:

```
key = PBKDF2(password, salt, iterations=100_000, keyLen=256)
```

- **Salt (16 bytes)**: Random per-file value. Prevents rainbow table attacks.
- **100,000 iterations**: Makes each guess take ~100ms. Brute-forcing 1 million passwords would take ~100,000 seconds ≈ 27 hours per machine.
- **SHA-256 PRF**: Produces a 256-bit output suitable for AES-256.

### Binary Blob Layout

The encrypted payload stored in S3 is a single packed binary:

```
┌─────────────────────────────────────────────────────────────────┐
│  SALT (16 bytes)  │  IV (12 bytes)  │  CIPHERTEXT (N + 16 bytes) │
└─────────────────────────────────────────────────────────────────┘
         ↑                  ↑                    ↑
  PBKDF2 salt          AES-GCM nonce       Encrypted data
  (not secret)         (not secret)    + 16-byte GCM auth tag
```

The `+16 bytes` is the **GCM authentication tag** appended automatically by the Web Crypto API. On decryption, if this tag fails to verify, decryption throws — indicating either a wrong key or tampered data.

---

## 3. System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        SENDER'S BROWSER                          │
│                                                                  │
│  File selected → cryptoUtils.encryptFile()                       │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  1. Generate random salt (16B) + IV (12B)                │   │
│  │  2. Derive AES-256-GCM key from password (PBKDF2)        │   │
│  │     OR generate random key directly (auto mode)          │   │
│  │  3. Encrypt: AES-GCM(plaintext, key, IV) → ciphertext    │   │
│  │  4. Pack: [salt][iv][ciphertext]                         │   │
│  └──────────────────────────────────────────────────────────┘   │
│               │                                                  │
│  FormData { encryptedBlob, iv, salt, filename, options }         │
└──────────────────────────────────────────────────────────────────┘
                │
                │  HTTP POST /api/files/upload
                │  ← NO KEY in this request
                ▼
┌──────────────────────────────────────────────────────────────────┐
│                    EXPRESS BACKEND (BLIND)                        │
│                                                                  │
│  Receives: opaque binary blob + metadata                         │
│  Stores:   blob → S3/MinIO                                       │
│            {id, iv, salt, filename, expiry} → SQLite DB          │
│  Returns:  { fileId: "abc-123" }                                 │
│                                                                  │
│  ⚠️  AT NO POINT does the server see or store the key            │
└──────────────────────────────────────────────────────────────────┘
                │
                │  Server returns: { fileId }
                ▼
┌──────────────────────────────────────────────────────────────────┐
│                    SHARE URL CONSTRUCTION                         │
│                                                                  │
│  https://guardianbox.app/file/abc-123#auto:Xj9kL2mP...          │
│                              ^^^^^^^ ^^^^^^^^^^^^^^^^^^^^        │
│                              fileId   KEY (never sent to server) │
└──────────────────────────────────────────────────────────────────┘
                │
                │  Link shared via Signal/Email/etc
                ▼
┌──────────────────────────────────────────────────────────────────┐
│                     RECIPIENT'S BROWSER                          │
│                                                                  │
│  1. JS reads key from window.location.hash (server never sees #) │
│  2. GET /api/files/abc-123 → receives encrypted blob             │
│  3. GET /api/files/abc-123/meta → receives iv, salt              │
│  4. AES-GCM decrypt(blob, key, iv) → original file bytes         │
│  5. triggerDownload() → file saved to device                     │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. The URL Fragment Trick

This is the most elegant security mechanism in GuardianBox.

### How HTTP + URLs work

A URL has this structure:
```
https://host/path?query#fragment
       ────  ────  ─────  ────────
        ↑     ↑      ↑       ↑
     server server server  CLIENT ONLY
     sees   sees   sees    (never in HTTP request)
```

**The `#fragment` part is never included in any HTTP request by the browser.** This is defined in RFC 7230 and is a fundamental property of HTTP. Even if TLS is stripped, the fragment stays local.

### What this means for GuardianBox

```
Share URL:  https://guardianbox.app/file/abc-123#auto:Xj9kL2mPqR...
                                                 ──────────────────
                                                 AES-256 key in base64
                                                 NEVER sent to server
```

The server's access logs show:
```
GET /file/abc-123  200  OK
```

No key. No fragment. The server is structurally incapable of learning the key even if it wanted to.

### Threat: What if someone intercepts the link?

If an attacker intercepts the full URL (e.g., via email metadata, URL preview services, or chat logs), **they get both the file ID and the key**. This is why GuardianBox recommends:
- Sending links via an encrypted channel (Signal, not SMS)
- Enabling `maxDownloads: 1` to prevent multiple access
- Using password mode and sending the password via a different channel

---

## 5. Security Analysis

### Attack Vector Analysis

#### ✅ Server compromise / Database leak
**Risk:** Attacker dumps the database.
**What they get:** `{id, s3_key, iv, salt, filename, expiry}`.
**Can they decrypt?** No. The IV and salt are non-secret. Without the key (which is never stored), the ciphertext is useless.
**Verdict: Fully protected.**

#### ✅ S3 Bucket compromise
**Risk:** Attacker downloads all objects from S3.
**What they get:** A collection of encrypted binary blobs.
**Can they decrypt?** No. They need the AES keys, which only exist in share URLs.
**Verdict: Fully protected.**

#### ✅ Man-in-the-Middle Attack
**Risk:** Attacker intercepts the upload request.
**What they intercept:** The encrypted blob + IV + salt. No key.
**Can they decrypt?** No.
**Verdict: Protected (and further mitigated by HTTPS/TLS).**

#### ⚠️ Link interception
**Risk:** Attacker gets the full share URL (with #fragment).
**What they get:** File ID + decryption key.
**Mitigation:** Use `maxDownloads: 1`, use encrypted channels for sharing, use password mode + separate password channel.
**Verdict: Partially mitigated — user must practice secure sharing.**

#### ⚠️ User loses the link
**Risk:** Sender deletes the URL before sharing.
**What happens:** File is permanently unrecoverable. There is no key recovery.
**Mitigation:** Copy the link immediately. This is an acceptable trade-off for E2EE.
**Verdict: Inform users clearly — no backdoor exists.**

#### ⚠️ Weak passwords (Password Mode)
**Risk:** User sets password = "1234".
**Mitigation:** PBKDF2 with 100,000 iterations slows brute-force. Frontend enforces 8-character minimum. Recommend password managers.
**Verdict: Defense-in-depth — can still be brute-forced with a very weak password.**

#### ❌ Compromised recipient device
**Risk:** Malware on the recipient's machine reads the decrypted file after download.
**Mitigation:** None at the application layer. Out of scope for E2EE — E2EE only protects data in transit and at rest.
**Verdict: Out of scope. This is a device security problem.**

### Cryptographic Properties

| Property            | GuardianBox Achieves? |
|---------------------|-----------------------|
| IND-CPA Security    | ✅ (random IV per encryption) |
| IND-CCA Security    | ✅ (GCM auth tag rejects invalid ciphertexts) |
| Forward Secrecy     | ✅ (each file has a unique key) |
| Key Commitment      | ⚠️ (AES-GCM has a theoretical multi-key commitment issue — negligible in practice) |
| Non-repudiation     | ❌ (not a goal; no digital signatures) |

---

## 6. Ephemeral Storage Design

GuardianBox implements two independent expiry mechanisms:

### Time-Based Expiry

```
files.expires_at = NOW() + N seconds
```

A `node-cron` job runs hourly:
```sql
DELETE FROM files WHERE expires_at < NOW()
```
Each deletion is a two-step operation: delete from S3, then delete from DB.

### Download-Count Expiry ("Burn After Reading")

```
files.max_downloads = N
files.download_count++ on each GET
```

When `download_count >= max_downloads` after a download:
1. S3 blob is deleted immediately (during the streaming response's `end` event)
2. DB record is deleted

This guarantees the file is gone after N recipients access it.

### Combining Both

Both limits work independently. A file configured with `expiresIn: 3600, maxDownloads: 1` will self-destruct **whichever comes first** — 1 hour or 1 download.

---

## 7. Getting Started

### Prerequisites

- Node.js 20+
- MinIO (local) or AWS S3 credentials
- Git

### Quick Start — Backend

```bash
cd backend
npm install

# Start MinIO locally (Docker)
docker run -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001"

# Create bucket via MinIO console at http://localhost:9001
# Bucket name: guardianbox-encrypted

# Environment variables
export FRONTEND_URL=http://localhost:5173
export MINIO_ENDPOINT=http://127.0.0.1:9000

npm run dev   # starts on :4000
```

### Quick Start — Frontend

```bash
cd frontend
npm install

# .env
echo "VITE_API_URL=http://localhost:4000/api" > .env

npm run dev   # starts on :5173
```

### Run Tests

```bash
cd frontend
npm test
```

---

## 8. Project Structure

```
guardianbox/
├── frontend/
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── App.css
│       ├── utils/
│       │   └── cryptoUtils.js       ← ALL crypto logic lives here
│       ├── components/
│       │   ├── Landing.jsx          ← Home page
│       │   ├── UploadPage.jsx       ← File selection, encryption, upload
│       │   └── DownloadPage.jsx     ← Fetch, decrypt, download
│       └── tests/
│           └── cryptoUtils.test.js  ← Unit tests
│
├── backend/
│   ├── server.js                    ← Express app, middleware setup
│   ├── db.js                        ← SQLite schema + queries
│   ├── storage.js                   ← S3/MinIO adapter
│   ├── cron.js                      ← Hourly cleanup job
│   ├── package.json
│   ├── middleware/
│   │   └── validate.js              ← Upload metadata validation
│   └── routes/
│       └── files.js                 ← Upload / Download / Delete routes
│
└── README.md                        ← This file
```

---

## Key Design Decisions

| Decision                            | Rationale                                                         |
|-------------------------------------|-------------------------------------------------------------------|
| **Web Crypto API** over libraries   | Browser-native, no supply chain risk, hardware-accelerated        |
| **URL # fragment** for key transport| Never sent in HTTP requests — structurally impossible to intercept |
| **SQLite** for metadata             | Simple, zero-config, no server — swap to PostgreSQL for production |
| **MinIO** for object storage        | S3-compatible, self-hostable, zero cloud dependency for dev       |
| **No key stored anywhere**          | The fundamental zero-knowledge guarantee                          |
| **Streaming downloads**             | Handles large files without buffering in memory on the server     |
| **PBKDF2 100k iterations**          | OWASP 2023 minimum — makes brute-force attacks computationally expensive |

---

*Built as part of a Security Software Engineering Internship project exploring applied cryptography and zero-knowledge system design.*
