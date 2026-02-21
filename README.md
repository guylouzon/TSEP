# Tiered Security Email Protocol (TSEP)

**TSEP** is a backward-compatible extension to SMTP that enables end-to-end encrypted email with graduated security levels. By decoupling identity and key management from email infrastructure, TSEP delegates authentication to third-party identity providers (banks, enterprise systems, or authentication apps).

## 🚀 Key Innovations

* **Multi-Tier Security**: Three distinct security levels (Cached, Online, and Time-Bound) to balance convenience and protection.
* **Identity Provider Mediation**: Offloads the burden of key management and authentication to trusted third parties.
* **Backward Compatibility**: Functions within existing SMTP infrastructure; non-TSEP clients receive a plaintext notice with a download link.
* **Cryptographic Audit Trails**: Provides non-repudiation and proof of delivery/reading.

---

## 🛡️ Security Levels

| Level | Name | Authentication | Use Case |
| --- | --- | --- | --- |
| **1** | **Cached Key** | Initial setup only | Routine communications (Statements, marketing) |
| **2** | **Online Verification** | Real-time 2FA | Sensitive actions (Password resets, small transfers) |
| **3** | **Time-Bound** | Real-time 2FA + Policy | High-stakes transactions (Wire transfers, legal docs) |

---

## 🛠️ Implementation

### Client Setup (Reference TypeScript)

```typescript
import { TSEPClient, SecurityLevel } from '@tsep/client';

const client = new TSEPClient({
  identityProvider: {
    name: 'Example Bank',
    authEndpoint: 'https://auth.bank.com/api/v1/email',
    publicKey: 'base64:...'
  },
  keyStore: new PlatformKeyStore() // Supports iOS Keychain, Android Keystore, etc.
});

await client.initialize();

```

### Sending a Message (Reference Python)

```python
from tsep import TSEPSender, SecurityLevel, SecurityPolicy

sender = TSEPSender(sender_email='noreply@bank.com', signing_key=pk)

# Level 3 Time-Bound Message
policy = SecurityPolicy(
    expires_at=datetime.now() + timedelta(minutes=15),
    max_decrypt_count=1,
    geofence={'allowed_countries': ['US']},
    read_receipt_required=True
)

message = sender.create_message(
    to='user@example.com',
    subject='Wire Transfer Approval Required',
    security_level=SecurityLevel.TIME_BOUND,
    security_policy=policy
)

```

---

## 📦 Message Envelope

TSEP messages use a JSON-based envelope embedded in a standard email body using the MIME type `application/vnd.tsep.encrypted+json`.

```json
{
  "tsep_version": "1.0",
  "security_level": 2,
  "encryption": {
    "algorithm": "X25519-ChaCha20-Poly1305",
    "ephemeral_public_key": "base64:...",
    "encrypted_body": "base64:..."
  },
  "signature": {
    "algorithm": "Ed25519",
    "sender_key_id": "sha256:..."
  }
}

```

---

## 🗺️ Roadmap

* **Phase 1 (Months 1-6)**: Pilot with select identity providers and reference implementations.
* **Phase 2 (Months 7-18)**: Expansion to major email clients (Gmail, Outlook, Apple Mail).
* **Phase 3 (Months 19-36)**: Universal mainstream adoption and cross-institution testing.
* **Phase 4 (Years 4+)**: IETF standardization and regulatory recognition (eIDAS, NIST).

---

## 📜 Governance & Compliance

* **Standards**: Target IETF Working Group "Secure Email Transport" (SET-WG).
* **Regulations**: Designed to meet GDPR, CCPA, HIPAA, and PCI-DSS requirements through granular access control and audit trails.
* **License**: Reference implementations are available under the **Apache 2.0 License**.

---

## 🤝 Contributing

We welcome community contributions! Please see our [Security Requirements](https://www.google.com/search?q=6.4) and [Technical Implementation Guidelines](https://www.google.com/search?q=7.1) for more details on how to get involved.
