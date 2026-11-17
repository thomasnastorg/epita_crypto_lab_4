# Lab 4 report

Answer from **your** build: every claim points to a file in this repository or to a line in `evidence/`.

## 1. Inventory

Every key and certificate you created: what it is, algorithm and size, where the key lives, who can read it,
validity, what it is used for.

| Item | Key location | Readable by | Valid until | Purpose |
|---|---|---|---|---|
| root CA, EC P-384, self-signed, `root/certs/ca.cert.pem` | `root/private/ca.key.pem`, encrypted (AES-256, passphrase) | the `root-ca` container (no network); on the host, my user account, but only I know the passphrase | 2046-11-12, 20 years (`openssl x509 -noout -enddate`) | signs the intermediate and the root CRL, nothing else; stopped the rest of the time |
| issuing CA, EC P-384, serial `1000` of the root, `intermediate/certs/int.cert.pem` | `intermediate/private/int.key.pem`, **not encrypted** (`chmod 700 intermediate/private`), never committed | the `issuing-ca` container (no network); on the host, my user account and anyone with root on the host | 2036-11-14, 10 years | signs server and client certificates and the intermediate CRL |
| root CRL, `intermediate/crl/root.crl.pem` (copy of `root/crl/root.crl.pem`), CRL number 4096 | signed by the root key | public | Next Update 2027-05-16 (180 days, `default_crl_days` in `root/openssl.cnf`) | says the intermediate is not revoked; nginx needs it to accept any client |
| intermediate CRL, `intermediate/crl/int.crl.pem`, CRL number 4097 | signed by the intermediate key | public | Next Update 2026-11-24 (7 days, `default_crl_days` in `intermediate/openssl.cnf`) | lists serial `1002` (alice, keyCompromise) |
| server `www.lab.internal`, EC P-256, serial `1000`, `identities/www/www.cert.pem` (+ `www.fullchain.pem`) | `identities/www/www.key.pem`, created in `client`; committed only as `www.key.pem.age` | the `client` and `nginx` containers (mounted read-only in nginx); the 3 age recipients | 2027-02-15, 90 days | TLS server certificate of nginx |
| alice (old), EC P-256, serial `1002`, `intermediate/newcerts/1002.pem` | the old key was overwritten in phase 6: considered stolen | the thief | 2027-02-15, but **revoked** 2026-11-17 (keyCompromise, `intermediate/index.txt`: `R`) | none any more; refused by nginx (`evidence/broken.txt`: `alice GET /admin -> 400`) |
| alice (new), EC P-256, serial `1005`, `identities/alice/alice.cert.pem` | `identities/alice/alice.key.pem`, new key; committed as `.age` | `client` container; the 3 age recipients | 2027-02-15, 90 days | mTLS client, role admin (`api/app.py`); `evidence/fixed.txt`: `alice GET /admin -> 200` |
| bob, EC P-256, serial `1003`, `identities/bob/bob.cert.pem` | `identities/bob/bob.key.pem`; committed as `.age` | `client` container; the 3 age recipients | 2027-02-15, 90 days | mTLS client, role user |
| billing (service), EC P-256, serial `1004`, `identities/billing/billing.cert.pem`, SAN `URI:spiffe://lab.internal/billing` | `identities/billing/billing.key.pem`; committed as `.age` | `client` container; the 3 age recipients | 2027-02-15, 90 days | mTLS client, role service: `/invoices` |
| evil.example.com test, EC P-256, serial `1001`, `intermediate/newcerts/1001.pem` | `identities/evil/evil.key.pem`; committed as `.age` | `client` container; the 3 age recipients | 2027-02-15 | nameConstraints test only: signed, but refused by every validator (`permitted subtree violation`). Still `V` in `intermediate/index.txt`: it should be revoked too |
| age keys: the trainer's, the CI's, mine (`recipients.txt`) | `ci.key` (repo folder, gitignored) and the GitHub secret `AGE_KEY`; mine in `~/.config/age/keys.txt` | me; GitHub Actions; the trainer for his | no expiry | decrypt `identities/*/*.key.pem.age` |

**Lifetimes.** The root lasts 20 years, the intermediate 10, the server and client certificates 90 days.

- **Root, 20 years.** Changing a root means touching every trust store (laptops, servers, images): it is costly,
  so the root lives long. It can, because it is offline: its key is used twice a decade (sign an intermediate) and
  twice a year (CRL). Longer (30 years) would outlive P-384's expected security margin and the people who know the
  passphrase; shorter (5 years) would force a trust-store migration every 5 years.
- **Intermediate, 10 years.** Half the root's life, so it always expires before the root and can be replaced
  under the same root without touching any trust store: only the chain sent by nginx changes. Its key is online,
  so it is more exposed than the root: 10 years is the upper limit; shorter (2-5 years) would limit the impact of
  a silent compromise but means re-opening the root more often.
- **Leaves, 90 days** (`default_days = 90`, checked by `evidence/working.txt`: `www: lifetime 90 days or less`).
  Revocation is weak in practice: curl does not read CRLs for the server, a CRL can be stale. Expiry is the only
  check every client always does, so a short lifetime bounds how long a stolen key is useful. 1 year: a stolen key
  is usable up to a year, and a yearly renewal is forgotten (outages when it expires). 7 days: forces full
  automation (ACME, step-ca); with the manual `openssl ca` process of this lab, renewing 5 certificates every week
  would be error-prone. 90 days is the public web's practice (Let's Encrypt): short, but manageable by hand
  while automation is being built.

## 2. Chain

Root, intermediate, leaves, with the extensions that constrain each one (pathlen, nameConstraints, EKU, SAN).

| Certificate | Subject, issuer | Constraining extensions | What they prevent |
|---|---|---|---|
| root CA | `C=FR, O=EPITA Lab, CN=EPITA Lab Root CA`, self-signed | `basicConstraints: critical, CA:TRUE, pathlen:1`; `keyUsage: critical, keyCertSign, cRLSign` | `pathlen:1`: below the root, one CA level only; a CA signed by the intermediate is refused. `keyUsage`: the root key signs certificates and CRLs, nothing else |
| issuing CA | `C=FR, O=EPITA Lab, CN=EPITA Lab Issuing CA`, issued by the root (serial `1000`) | `basicConstraints: critical, CA:TRUE, pathlen:0`; `keyUsage: critical, digitalSignature, keyCertSign, cRLSign`; `nameConstraints: critical, Permitted: DNS:lab.internal` | `pathlen:0`: it cannot create a sub-CA. `nameConstraints`: any DNS name outside `lab.internal` is refused by validators, even if the CA signs it: `evil.example.com` gave `error 47 at 0 depth lookup: permitted subtree violation` (phase 3) |
| www.lab.internal | `CN=www.lab.internal`, issued by the issuing CA (serial `1000`) | `CA:FALSE`; `keyUsage: digitalSignature`; `EKU: TLS Web Server Authentication`; `SAN: DNS:www.lab.internal` | cannot sign certificates; cannot be used as a client: presented to nginx, it is refused (`400 The SSL certificate error`, phase 4 matrix); valid for this one name only (`evidence/working.txt`: `www valid for www.lab.internal`) |
| alice, bob | `CN=alice` / `CN=bob`, issued by the issuing CA (serials `1005`, `1003`) | `CA:FALSE`; `keyUsage: digitalSignature`; `EKU: TLS Web Client Authentication`; `SAN: email:alice@lab.internal` / `email:bob@lab.internal` | cannot act as a TLS server or a CA. The CN gives the role in `api/app.py` |
| billing | `CN=billing`, issued by the issuing CA (serial `1004`) | same as alice; `SAN: URI:spiffe://lab.internal/billing` | a service identity, not a person: client only (`evidence/working.txt`: `billing GET /invoices -> 200`, `bob GET /invoices -> 403`) |

Read from the certificates with
`openssl x509 -in <cert> -noout -subject -issuer -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName,nameConstraints`.
All signatures are `ecdsa-with-SHA384` (`default_md = sha384` in both configs: the CA keys are P-384).

The chain is checked by nginx (`ssl_client_certificate /etc/nginx/ca/ca-chain.pem`, `ssl_verify_depth 2` in
`nginx/default.conf`): a self-signed certificate with `CN=alice` is refused (`400 The SSL certificate error`).
Revocation is checked at every level (`ssl_crl /etc/nginx/crl/crl-bundle.pem`).

**Why bob was refused with `int.crl.pem` alone (phase 5).** With `ssl_crl`, nginx (OpenSSL) checks revocation of
every certificate of the chain, not only the leaf: the leaf against the intermediate's CRL, and the intermediate
against the root's CRL. `int.crl.pem` alone gives no CRL for the intermediate, so every client fails, bob too.
Reproduced in `issuing-ca`:
`openssl verify -crl_check_all -CAfile root/certs/ca.cert.pem -untrusted intermediate/certs/int.cert.pem -CRLfile intermediate/crl/int.crl.pem bob.cert.pem`
→ `error 3 at 1 depth lookup: unable to get certificate CRL` (depth 1 = the intermediate).
The fix: `intermediate/crl/crl-bundle.pem` = `int.crl.pem` + `root.crl.pem`; then alice 400, bob and billing 200
(`evidence/broken.txt`: `CRLs valid, bob not revoked`, `alice GET /admin -> 400`).

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

### Client key (alice, this lab's incident)

- How you notice: only from outside: alice reports her laptop stolen. Nothing in the build alerts; the API log
  (`docker compose logs api`) shows `user=alice` calls, but a thief's calls look exactly like alice's. Only a
  correlation (alice's calls while she says she is offline, a new source address) would reveal it.
- What becomes unsafe: the thief is alice for nginx and the API: admin on `/admin` until revocation. The other
  identities and the server are not affected (one key, one identity). Nothing stops working.
- Recovery: done in phases 5 and 6. Revoke serial `1002` with `-crl_reason keyCompromise`, publish the CRL, rebuild
  `crl-bundle.pem`, restart nginx (it reads CRLs at startup only): alice refused (`evidence/broken.txt`). Then a
  **new key** and a new certificate, serial `1005`: alice works again, the old serial stays in the CRL
  (`evidence/fixed.txt`: `alice has a new certificate (serial 1005)`, `serial 1002 is in the published CRL`).
  `intermediate/index.txt` shows `R ... 1002 ... /CN=alice` and `V ... 1005 ... /CN=alice`.
- How long: about 15 minutes of commands, once the theft is known. The real exposure is the time between the theft
  and the report, plus the nginx restart: until then, the stolen key works.

### Intermediate key (`intermediate/private/int.key.pem`)

- How you notice: nothing detects it. The key is a file in clear on the host; a copy leaves no trace. You might
  see an unknown serial (a certificate not in `intermediate/index.txt`) only if servers logged client serials and
  someone compared them.
- What becomes unsafe: everything below it. The attacker signs any client certificate (`CN=alice` → admin), any
  server certificate under `lab.internal` (impersonate `www.lab.internal`), and forges CRLs (un-revoke a stolen
  key). The nameConstraints still limit it to `lab.internal`, and `pathlen:0` stops it from creating a sub-CA.
- Recovery: bring the root back online (`docker compose start root-ca`), revoke intermediate serial `1000` in the
  root's database, publish a new root CRL. That refuses every certificate of the PKI at once: total outage. Then a
  new intermediate key (ideally non-exportable, see section 4), a new intermediate certificate, re-issue `www`,
  alice, bob, billing (new CSRs, ideally new keys), new `ca-chain.pem` and CRL bundle, restart nginx. The root and
  the trust stores stay: that is the point of the two tiers.
- How long: one to a few hours in this lab (5 certificates); in a real company, days, as every service and person
  must get a new certificate.

### Root key (`root/private/ca.key.pem`)

- How you notice: the key is encrypted: a copy of the file alone is useless without the passphrase. The danger is
  the pair file + passphrase (here both are on my laptop). Nothing would alert: you would learn it from a leak or a
  forensic investigation.
- What becomes unsafe: the whole PKI. The attacker creates a new intermediate (without nameConstraints, so any DNS
  name, for anyone who trusts the root), signs CRLs, and can revoke or un-revoke anything. A root cannot be revoked
  by itself: its CRL would be signed by the attacker too.
- Recovery: build a new root (new key, new certificate, new passphrase held differently), a new intermediate, and
  re-issue every certificate; **remove the old root from every trust store** (laptops, servers, container images,
  `ca-chain.pem` in nginx) and add the new one. Until the old root is removed everywhere, the attacker's
  certificates are accepted.
- How long: the PKI itself in an hour; the trust-store removal is the long part, days to weeks, depending on how
  the root was distributed (section 4).

## 4. Operational gaps

search answer to those questions/weaknesses

- **The root key's passphrase: where is it, who knows it?** In this build, a random passphrase in
  `~/.config/epita-lab4-root-passphrase.txt` (mode 600, outside the repository) on the same laptop as
  `root/private/ca.key.pem`: one theft of the laptop gives both. Only I have it. If I leave, the root can no longer
  sign: no new intermediate, and no new root CRL after 2027-05-16, so nginx would refuse every client. Practice:
  the root key in an offline HSM or on an air-gapped machine in a safe; the passphrase split with Shamir's Secret
  Sharing (for example 3 of 5 custodians, `ssss`, or an HSM's M-of-N quorum smart cards); a documented key ceremony
  with witnesses and logs; custodians replaced when they leave, and the shares redistributed.
- **The CRL expires after 7 days: what happens on day 8, and who regenerates it?** On 2026-11-24 (the intermediate
  CRL's Next Update), the CRL in `crl-bundle.pem` is expired: OpenSSL in nginx fails with `CRL has expired` and
  **every** client gets `400 The SSL certificate error`, not only alice: a total outage, caused by revocation
  itself. Today nobody regenerates it: it is a manual `openssl ca -gencrl` in `issuing-ca`. Fix: a scheduled job
  (cron or systemd timer) in `issuing-ca` that runs `openssl ca -gencrl` every 1-2 days, rebuilds
  `crl-bundle.pem` and reloads nginx (`nginx -s reload`), with an alert if the CRL's Next Update is less than 2 days
  away. The same applies to the root CRL every 6 months: a planned ceremony, since the root is offline. OCSP (or
  OCSP stapling) would avoid shipping full CRLs, but it needs an online responder.
- **The lab root is in no trust store: how would every laptop, server and container get it?** Laptops: the MDM
  (Intune, Jamf, a GPO on Windows) pushes `ca.cert.pem` into the system trust store (Keychain, Windows Root store).
  Linux servers: configuration management (Ansible, Puppet) copies it to `/usr/local/share/ca-certificates/` and
  runs `update-ca-certificates` (`/etc/pki/ca-trust/source/anchors/` + `update-ca-trust` on RHEL). Containers:
  baked into the company base image (`COPY ca.cert.pem ...` + `update-ca-certificates`) or mounted at runtime
  (Kubernetes ConfigMap, cert-manager trust-manager). Runtimes with their own store must get it too: Java
  (`keytool -importcert` into `cacerts`), Python `requests`/certifi (`REQUESTS_CA_BUNDLE`), Node
  (`NODE_EXTRA_CA_CERTS`), Firefox (enterprise policy). The same channel must be able to **remove** it, for a root
  compromise (section 3).
- **The intermediate's key is not encrypted, unlike the root's. How could a KMS hold it?** The idea: the key is
  generated inside a cloud KMS or HSM and never leaves it; the CA only sends hashes to sign. AWS KMS
  (`aws kms create-key --key-spec ECC_NIST_P384 --key-usage SIGN_VERIFY`), Google Cloud KMS
  (`EC_SIGN_P384_SHA384`), Azure Key Vault (EC P-384, HSM-backed) all support this. The CSR and every certificate
  are signed through the KMS `Sign` API: with OpenSSL 3 via a PKCS#11 provider (`pkcs11-provider` + AWS CloudHSM or
  `aws-kms-pkcs11`, then `openssl ca -provider pkcs11 -keyfile "pkcs11:object=int-ca"`), or with a CA software that
  supports KMS natively: smallstep `step-ca` (`awskms`, `cloudkms`, `azurekms`), HashiCorp Vault PKI with a managed
  key, or managed CAs (AWS Private CA, Google CA Service). Gains: the key cannot be copied (a stolen disk gives
  nothing), IAM restricts who may call `Sign`, and every signature is logged (CloudTrail, Cloud Audit Logs): an
  intermediate compromise becomes detectable and revocable at the IAM level. Limits: the issuing CA needs network
  access to the KMS (here `issuing-ca` has no network), and an attacker with the CA's IAM credentials can still
  sign while he has them.
