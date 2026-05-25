# Certificates

This folder contains **public** certificates only. Private key files (`.p12` / `.pfx`) must
never be committed to source control. Follow the sections below to obtain and install all
certificates required to run the site.

---

## Overview of required certificates

| # | Role | Store | Config key |
|---|------|-------|------------|
| 1 | SP signing / decryption certificate (Brugervendt System) | `LocalMachine\My` | `Federation > SigningCertificates` |
| 2 | Context Handler (IdP) token-signing certificate | `LocalMachine\TrustedPeople` or trust store | SAML metadata |
| 3 | STS token-signing / service certificate | supplied as base64 in `Web.config` | `SecurityTokenRequest > StsEndpointCertificate` |
| 4 | Client certificate for STS calls (mutual TLS) | `LocalMachine\My` | `SecurityTokenRequest > ClientCredential[@thumbprint]` |

---

## Certificate 1 — SP signing / decryption certificate (Brugervendt System)

This is the certificate that identifies this web application towards the Context Handler.
It is used to sign outgoing SAML `AuthnRequest` messages and to decrypt incoming
`EncryptedAssertion` elements.


## Certificate 2 — Context Handler (IdP) token-signing certificate

This public certificate is included in the IdP SAML metadata and is used by the SP to
validate incoming SAML assertions.

## Certificate 3 — STS token-signing certificate

The STS (Security Token Service) signs the SAML tokens it issues. The SP must trust this
certificate to accept the issued tokens.

`Web.config` carries the certificate as a **base64-encoded DER blob** inside
`<StsEndpointCertificate>`:

```xml
<SecurityTokenRequest>
  <StsEndpointCertificate>PASTE_BASE64_DER_BYTES_HERE</StsEndpointCertificate>
  ...
</SecurityTokenRequest>
```

## Certificate 4 — Client certificate for STS calls (mutual TLS)

This is the certificate the web application presents to the STS when requesting a
security token (WS-Trust, certificate endpoint). It acts as the client authentication
credential.
