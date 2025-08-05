# 🛡️ LYRA.Security

**LYRA. She signs. She verifies. She protects.**

---

## 🌐 What is LYRA?

**LYRA** (*Let Yourself Remain Authenticated*) is a self-hosted authorization system for verifying **signed requests** between **trusted systems**.  
It ensures that each request across service or company boundaries is intentional, validated, and safe — without inspecting the business payload.

---

## What is LYRA.Security

**LYRA.Security** is the cryptographic core of LYRA, providing signing, hashing, and verification logic through a unified contract model for trusted system communication.

- Defines **transport-agnostic contracts** for signing:
  - `GenericMetadata` — *caller*, *target*, *action*, *resource*, *payloadHash*, *timestamp*
  - `SignedMetadata` — algorithm + `Signature` (Base64)
  - `VerifyRequest` — `{ Metadata, Signed, (optional) Payload, RequestId }`
  - `VerifyResponse`
- Implements **canonical string** builder: `SignatureStringBuilder.BuildStringToSign(GenericMetadata)`
- Provides **cryptography helpers**:
  - `EncryptionHelper.ComputeSha512(string payload)` → Base64
  - `Signer.Sign(...)` / `Signer.Verify(...)` for `SignatureType` (e.g., `HmacSha512`, `RsaSha256`)
  - Constant‑time compare, Base64 utilities
- Keeps decisions about **policies, storage, caching** in `LYRA.Server` (out of scope here).

> No middleware or policy logic lives here. Only deterministic contracts + crypto primitives.

---

## Key Types

| Type | Purpose |
|------|---------|
| `GenericMetadata` | Canonical fields used to build the StringToSign |
| `SignedMetadata`  | Algorithm and Base64 signature over the canonical string |
| `VerifyRequest`   | `{ Metadata, Signed, Payload?, RequestId? }` sent to the server |
| `VerifyResponse`  | Indicates success/failure and diagnostics |
| `SignatureType`   | Enum of supported algorithms (e.g., `HmacSha512`, `RsaSha256`) |
| `SignatureStringBuilder` | Deterministic canonicalization of `GenericMetadata` |
| `EncryptionHelper`| SHA-512, HMAC utilities, constant‑time comparison |
| `Signer`          | High-level `Sign/Verify` API over `SignatureType` |

---

## Canonicalization (StringToSign)

`SignatureStringBuilder.BuildStringToSign(meta)` produces a **stable** string using fixed keys and order:

```
caller={caller}&target={target}&action={action}&resource={resource}&payloadHash={payloadHash}&timestamp={timestamp}
```

- No percent-encoding (values are used *as is*; ensure you pass normalized values).
- All fields are **required** and must match on both sides.
- `payloadHash` is **Base64(SHA‑512(body))`**. Server may recompute if `Payload` is provided.

---

## Example: Build + Sign (Client side)

```csharp
var metadata = new GenericMetadata
{
    CallerSystemName = "gateway@bcorp",
    TargetSystemName = "billing@acorp",
    Action = "post",
    Resource = "/subscribe",
    PayloadHash = EncryptionHelper.ComputeSha512(payloadJson),
    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
};

var toSign = SignatureStringBuilder.BuildStringToSign(metadata);
var signature = Signer.Sign(
    toSign,
    secretOrPrivateKey: secret,        // HMAC key or RSA private key PEM
    type: SignatureType.HmacSha512);

var signed = new SignedMetadata
{
    SignatureType = SignatureType.HmacSha512,
    Signature = signature              // Base64
};

var request = new VerifyRequest
{
    Metadata = metadata,
    Signed = signed,
    Payload = payloadJson,             // optional, enables server-side recompute
    RequestId = Guid.NewGuid().ToString()
};
```

---

## Example: Verify (Server side or test)

```csharp
// Rebuild canonical string
var toSign = SignatureStringBuilder.BuildStringToSign(request.Metadata);

// Optional integrity check if Payload is present
if (!string.IsNullOrEmpty(request.Payload))
{
    var recomputed = EncryptionHelper.ComputeSha512(request.Payload);
    if (!EncryptionHelper.SecureEquals(recomputed, request.Metadata.PayloadHash))
        return VerifyResponse.Fail("PayloadHash does not match payload");
}

// Verify signature
var ok = Signer.Verify(
    toSign,
    secretOrPublicKey: decryptedSecretOrPublicKey,
    signatureBase64: request.Signed.Signature,
    type: request.Signed.SignatureType);
```

---

## Test JSON (Postman)

```json
{
  "metadata": {
    "callerSystemName": "billing-api@a-corp",
    "targetSystemName": "public-api@a-corp",
    "action": "post",
    "resource": "/subscribe",
    "payloadHash": "64xtwI4iU8vvFpN3k3BQL/CYcHl1s69AVKo5eDMcZs32kuj0N/XIllvdsW/2w1aleYVHL3k4f6wcA8KSav0Fog==",
    "timestamp": "1754405311"
  },
  "signed": {
    "signatureType": "HmacSha512",
    "signature": "PUT_BASE64_SIGNATURE_HERE"
  },
  "payload": "{"email":"user@example.com","plan":"pro"}",
  "requestId": "2f3b5a6c-1d42-4a3e-9c8e-2b1d8e5a9f77"
}
```

---

## Security Notes

- Use **monotonic UTC Unix seconds** as `timestamp`. Enforce a small window (e.g., ±2h) on the server.
- Always **lowercase** `action` and keep `resource` stable (no trailing‑slash magic).
- Prefer **per‑touchpoint secrets**; rotate regularly. Store server secrets encrypted at rest.
- Use `SecureEquals` (constant‑time) for all signature/hash comparisons.

---

## Tech

- C# 12 / .NET 8
- `System.Security.Cryptography` (SHA‑512, HMAC, RSA)
- Zero third‑party dependencies

---

## License

MIT. See [LICENSE](LICENSE).

**LYRA. She signs. She verifies. She protects.**
