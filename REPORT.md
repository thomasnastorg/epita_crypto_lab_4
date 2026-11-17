# Lab 4 report

Answer from **your** build: every claim points to a file in this repository or to a line in `evidence/`.

## 1. Inventory

Every key and certificate you created: what it is, algorithm and size, where the key lives, who can read it,
validity, what it is used for.

| Item | Key location | Readable by | Valid until | Purpose |
|---|---|---|---|---|
| root CA, EC P-384, self-signed, `root/certs/ca.cert.pem` | `root/private/ca.key.pem`, encrypted (AES-256, passphrase) | the `root-ca` container (no network); on the host, my user account, but only I know the passphrase | 2046-11-12, 20 years (`openssl x509 -noout -enddate`) | signs the intermediate and the root CRL, nothing else; stopped the rest of the time |
| issuing CA, EC P-384, serial `1000`, `intermediate/certs/int.cert.pem` | `intermediate/private/int.key.pem`, **not encrypted**, never committed | the `issuing-ca` container (no network); my host account | 2036-11-14, 10 years | signs leaves and the intermediate CRL |
| www.lab.internal, EC P-256, serial `1000`, `identities/www/www.cert.pem` | `identities/www/www.key.pem`, committed as `.age` only | `client`, `nginx` (read-only); the 3 age recipients | 2027-02-15, 90 days | TLS server of nginx |
| alice (old), EC P-256, serial `1002` | old key overwritten: considered stolen | the thief | **revoked** 2026-11-17, keyCompromise (`intermediate/index.txt`: `R`) | none; refused (`evidence/broken.txt`: `alice GET /admin -> 400`) |
| alice (new), EC P-256, serial `1005` | `identities/alice/alice.key.pem`, new key, `.age` | `client`; the 3 age recipients | 2027-02-15, 90 days | mTLS client, admin (`evidence/fixed.txt`: `alice GET /admin -> 200`) |
| bob, EC P-256, serial `1003` | `identities/bob/bob.key.pem`, `.age` | `client`; the 3 age recipients | 2027-02-15, 90 days | mTLS client, user |
| billing, EC P-256, serial `1004`, `URI:spiffe://lab.internal/billing` | `identities/billing/billing.key.pem`, `.age` | `client`; the 3 age recipients | 2027-02-15, 90 days | mTLS service client, `/invoices` |
| evil.example.com, EC P-256, serial `1001` | `identities/evil/evil.key.pem`, `.age` | `client`; the 3 age recipients | 2027-02-15 | nameConstraints test; still `V` in `index.txt`, should be revoked |
| CRLs: `intermediate/crl/root.crl.pem`, `int.crl.pem`, `crl-bundle.pem` | signed by root / intermediate | public | root: 2027-05-16 (180 d); intermediate: 2026-11-24 (7 d) | the intermediate CRL lists serial `1002` |

**Lifetimes.** The root lasts 20 years, the intermediate 10, the server and client certificates 90 days.

- **Root, 20 years:** replacing it means touching every trust store, so it lives long; it can, because it is
  offline and signs almost nothing. Longer would outlive the people who hold the passphrase.
- **Intermediate, 10 years:** expires before the root, so it can be replaced without touching trust stores. Its
  key is online: shorter would limit a silent compromise but means opening the root more often.
- **Leaves, 90 days:** revocation is weak (curl reads no CRL for the server), expiry is the one check every client
  does: it bounds how long a stolen key works. 1 year: a stolen key works a year and the renewal is forgotten.
  7 days: needs full automation (ACME), too fragile with manual `openssl ca`. 90 days is the web's practice.

## 2. Chain

Root, intermediate, leaves, with the extensions that constrain each one (pathlen, nameConstraints, EKU, SAN).

| Certificate | Subject, issuer | Constraining extensions | What they prevent |
|---|---|---|---|
| root CA | `C=FR, O=EPITA Lab, CN=EPITA Lab Root CA`, self-signed | `basicConstraints: critical, CA:TRUE, pathlen:1`; `keyUsage: critical, keyCertSign, cRLSign` | `pathlen:1`: below the root, one CA level only; a CA signed by the intermediate is refused. `keyUsage`: the root key signs certificates and CRLs, nothing else |
| issuing CA | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, issued by the root | `CA:TRUE, pathlen:0`; `nameConstraints: critical, permitted DNS:lab.internal` | no sub-CA; no DNS name outside `lab.internal`: `evil.example.com` → `permitted subtree violation` (phase 3) |
| www.lab.internal | `CN=www.lab.internal`, issued by the issuing CA | `CA:FALSE`; `EKU: serverAuth`; `SAN: DNS:www.lab.internal` | not usable as a client (`400 The SSL certificate error` in nginx) nor for another name |
| alice, bob | `CN=alice` / `CN=bob`, issued by the issuing CA | `CA:FALSE`; `EKU: clientAuth`; `SAN: email:<user>@lab.internal` | cannot act as server or CA; the CN gives the role (`api/app.py`) |
| billing | `CN=billing`, issued by the issuing CA | `CA:FALSE`; `EKU: clientAuth`; `SAN: URI:spiffe://lab.internal/billing` | client only (`evidence/working.txt`: `billing GET /invoices -> 200`) |

Read them from the certificates, not from the config:
`openssl x509 -in root/certs/ca.cert.pem -noout -subject -issuer -ext basicConstraints,keyUsage`.

**Bob refused with `int.crl.pem` alone (phase 5):** nginx checks revocation at every level; with no root CRL, the
intermediate cannot be checked: `error 3 at 1 depth lookup: unable to get certificate CRL`. `crl-bundle.pem`
(both CRLs) fixes it (`evidence/broken.txt`: `CRLs valid, bob not revoked`).

## 3. Key compromise

For the server key, a client key, the intermediate key and the root key: how would you notice,
what stops working or becomes unsafe, how do you recover, how long does it take?

### Server key (`identities/www/www.key.pem`)

- How you notice: nothing in this build detects it: no monitoring, no alert. You learn it from outside: the key
  found in a backup, a leak, an intrusion on the host.
- What becomes unsafe: whoever can redirect traffic (DNS, same network) can pose as `www.lab.internal`: clients send
  it their requests and trust its answers. It still cannot reach the API as alice: it has no client key. Past
  sessions stay unreadable: TLS 1.3 key exchange is ephemeral (forward secrecy). Nothing stops working.
- Recovery: new key and CSR in `client`, sign in `issuing-ca`, copy to `identities/www/`, restart nginx. Revoke the
  old serial and publish the CRL, but the clients do not check the server's revocation (`curl` reads no CRL by
  default): the old certificate stays accepted.
- How long: 10 minutes to reissue; the stolen certificate stays usable until it expires, at most 90 days.

### Client key

- How you notice: only when alice reports the theft; the API log shows `user=alice` either way.
- What becomes unsafe: the thief is alice: admin on `/admin` until revocation. Other identities are unaffected.
- Recovery: revoke serial `1002` (keyCompromise), publish the CRL and bundle, restart nginx (`evidence/broken.txt`);
  then a **new key** and certificate, serial `1005` (`evidence/fixed.txt`). `index.txt`: `1002 R`, `1005 V`.
- How long: 15 minutes once reported; the real exposure is the time between theft and report.

### Intermediate key

- How you notice: nothing detects it: a file in clear on the host, copied without trace.
- What becomes unsafe: the attacker signs any client (`CN=alice` → admin), any server under `lab.internal`, and
  forged CRLs. Still limited by `nameConstraints` and `pathlen:0`.
- Recovery: start `root-ca`, revoke intermediate serial `1000`, publish the root CRL (total outage), new
  intermediate key and certificate, reissue every leaf, new `ca-chain.pem` and CRL bundle. Trust stores unchanged.
- How long: an hour here; days in a company, as every service and person needs a new certificate.

### Root key

- How you notice: the file alone is useless without the passphrase; nothing alerts if both leak.
- What becomes unsafe: everything: a new intermediate without nameConstraints, any certificate, any CRL. A root
  cannot revoke itself.
- Recovery: new root, new intermediate, reissue everything, and **remove the old root from every trust store**.
- How long: an hour for the PKI; days to weeks for the trust stores.

## 4. Operational gaps

search answer to those questions/weaknesses

- **Root passphrase:** random, in `~/.config/epita-lab4-root-passphrase.txt` on the same laptop as the key: one
  theft gives both, and only I know it. If I leave, no new intermediate and no root CRL after 2027-05-16 (every
  client refused). Fix: key offline or in an HSM, passphrase split with Shamir (e.g. 3 of 5 custodians), a
  documented key ceremony, shares redistributed when someone leaves.
- **CRL expires after 7 days:** on 2026-11-24 the CRL in the bundle expires, nginx fails with `CRL has expired` and
  refuses **every** client. Nobody regenerates it today. Fix: a cron in `issuing-ca` running `openssl ca -gencrl`
  every 1-2 days, rebuilding `crl-bundle.pem`, reloading nginx, with an alert before Next Update.
- **Root in no trust store:** laptops via the MDM (Intune, Jamf, GPO); servers via Ansible into
  `/usr/local/share/ca-certificates/` + `update-ca-certificates`; containers baked into the base image or mounted
  (trust-manager); plus runtime stores (Java `cacerts`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`). The same
  channel must be able to remove it.
- **Intermediate key in a KMS:** generate a non-exportable P-384 key in AWS KMS (`ECC_NIST_P384`, `SIGN_VERIFY`),
  Google Cloud KMS or Azure Key Vault; sign through the KMS API, with OpenSSL 3 and a PKCS#11 provider
  (`openssl ca -provider pkcs11 -keyfile "pkcs11:object=int-ca"`) or a CA that supports it natively (`step-ca`,
  Vault PKI, AWS Private CA). Gains: the key cannot be copied, IAM limits who can sign, every signature is logged.
  Limit: the issuing CA needs network access to the KMS.
