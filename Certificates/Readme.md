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

---

## Certificate 1 — SP signing / decryption certificate (Brugervendt System)

This is the certificate that identifies this web application towards the Context Handler.
It is used to sign outgoing SAML `AuthnRequest` messages and to decrypt incoming
`EncryptedAssertion` elements.


## Certificate 2 — Context Handler (IdP) token-signing certificate

This public certificate is included in the IdP SAML metadata and is used by the SP to
validate incoming SAML assertions.
