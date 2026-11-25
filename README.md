# verify-license

Independent verifier for Core0 licences.

A Core0 licence is a JSON file signed by Obsydia with an ECDSA P-256 key. Core0 checks it against a public key built into its binaries. `verify-license` lets you run the same check yourself, on your own machine: is the licence genuine, what does it allow, and when does it expire.

The `licensing` package in this repository is byte-for-byte the package Obsydia uses to issue licences. Its tests include licences issued by the earlier licence tool and a verbatim copy of the earlier verifier, so compatibility is checked in both directions.

## Obsydia licence signing key

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExvBTKh0VgaO/sVpRmYvv+pcA3vCg
5KV/KtWphKZEnvD4VmzvP9ccJscMxUFC6vvHoS39LTeDSUXs8oTtjnxs7w==
-----END PUBLIC KEY-----
```

| Fingerprint | SHA-256 |
| --- | --- |
| SubjectPublicKeyInfo (DER) | `e3b0779ac345157152648dde2df3eb83c9ddce1678a386fb56e527b93139b83f` |
| PEM file | `6a77a37e5dfbd5c247667d8c5681e07e1c7b9ae7365fad55b0f9ff021a013b34` |

This key is embedded in `verify-license`. Print it with `verify-license -show-key`, or check it yourself:

```
openssl pkey -pubin -in obsydia_license.pub -outform DER | sha256sum
```

### Revoked keys

Licences signed with these keys are not valid. Current Core0 releases do not accept them.

| Revoked | SubjectPublicKeyInfo (DER) SHA-256 | PEM file SHA-256 |
| --- | --- | --- |
| 2026-11-23 | `6552321b452262cc131c30141a93d812b426e8cbea94869a8f2556070ad01f06` | `b32e5dc5efda3a708e934ce71775c4721d5a4b0f939eace5a42913148e4a9726` |

## Install

Download the binary for your platform from [Releases](https://github.com/obsydia-tech/verify-license/releases) and check it:

```
sha256sum -c SHA256SUMS --ignore-missing
```

Or build from source (Go 1.22 or newer):

```
go install github.com/obsydia-tech/verify-license/cmd/verify-license@latest
```

To reproduce a release binary byte for byte, build it from the release tag with the toolchain and flags used for the release:

```
git clone https://github.com/obsydia-tech/verify-license.git
cd verify-license
git checkout v1.1.0
GOTOOLCHAIN=go1.25.3 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o verify-license-linux-amd64 ./cmd/verify-license
sha256sum verify-license-linux-amd64
```

The sum matches the one in `SHA256SUMS` of that release. `go version -m verify-license-linux-amd64` shows the version and the git revision it was built from.

## Usage

```
verify-license [-pubkey <PEM>] [-at <date>] <licence.json>
verify-license -show-key
```

- `-pubkey` verifies against a key file you supply instead of the embedded one.
- `-at` reports the state at a given date (`YYYY-MM-DD` or RFC 3339) instead of now.

Example output:

```
tenant:      example
tier:        pro
nodes:       6
mode:        selfhosted
issued:      2026-09-30 11:04 UTC
expires:     2027-09-30 11:04 UTC (322 days left)
grace until: 2027-10-14 11:04 UTC (14 days)
format:      v1
modules:     pii, keys, bridge, audit, export, monitoring, file_storage
key:         embedded Obsydia key (spki sha256 e3b0779a...)
signature:   valid
LICENSE VALID
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | genuine and active |
| 1 | not genuine: bad signature, wrong key or malformed file |
| 2 | usage error or a file that cannot be read |
| 3 | genuine but expired (in grace or past it) |

## Format

```
{"tenant_id":"...","tier":"pro","node_count":6,"issued_at":<unix>,"expires_at":<unix>,"features":[...],"mode":"selfhosted","signature":"<base64>"}
```

The signature is 64 bytes, R and S of 32 bytes each, over SHA-256 of the JSON encoding of every field except `signature`, in the order above. `features` holds modules (`pii`, `file_storage`, ...) and `key:value` settings (`lv:2`, `grace:<days>`, `eula:<version>`, `channel:<stable|lts>`, `telemetry:<basic|off>`); `offline` marks an air-gapped licence. Unknown entries are ignored.

After `expires_at` a licence enters a grace period of 14 days, unless the licence sets `grace:<days>`. What Core0 allows in each state is described in the [documentation](https://obsydia.tech/docs).

## Security

Report vulnerabilities as described in [SECURITY.md](https://github.com/obsydia-tech/.github/blob/main/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
