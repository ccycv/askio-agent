# Signed-index package provenance observations

This capability shows that an installed package's exact identity is published in
an official signed archive index, and that its installed files still match dpkg's
recorded checksums, using evidence already present on the host. It remains part
of the locally enabled passive inventory loop.

Verifier `signed-index-v1` replaces `cached-deb-chain-v1`. The older verifier
compared installed files with the exact cached `.deb`, but ordinary APT operation
removes cached archives: on the 2026-11-25 trial hosts no evaluated package had
one, so every origin stayed unknown. Every evaluated package there was listed in
a signed official index with intact installed files. This source change does not
promote an agent release, enable enrollment, or change the host's package state.

## Negotiation and trust boundary

Claims advertise `vulnerability.package-provenance.v1` in addition to the existing
`vulnerability.inventory.dpkg.v1`, with collector version `dpkg-passive-v2`.
The backend must explicitly request the provenance capability. An inventory-v1
request still emits collector version `dpkg-passive-v1`, no provenance report, and
unknown origin for every package. Backend support must precede deployment of the
new advertised collector version; unsupported claims remain unsupported.

The provenance capture adds `capture.provenance`. Its versioned report contains
shared source observations and exact package receipts. An official-origin row
has one reference, `provenance:<SHA256 of canonical receipt>`. A verified receipt
binds binary name, architecture, full binary version, source name/version, the
signed source (suite, codename, InRelease digest, index path/digest/size), the
selected stanza's SHA-256, the published archive digest/size, the SHA-256 of
dpkg's recorded checksum list and the number of installed files compared.

Receipts cover only installed packages whose source the backend evaluates: Nginx,
Apache, the release's distribution PHP branch, OpenSSH, OpenSSL, glibc, systemd,
sudo and curl (askio `backend/packages/vulnerabilities/src/package-scope.ts`,
batches 0 and 1). A new scope batch needs a matching agent change.

These are attributed observations from the enrolled host. The compact report
retains digests, not the signed InRelease bytes, stanza, index or checksum list:
three Ubuntu InRelease files alone exceed the 512 KiB report budget. The
InRelease digests name public files that can be checked against the archive's
history. The backend validates the report's consistency and identity binding; it
cannot independently verify signatures or index membership.

What `signed-index-v1` does not show: it does not compare installed files with
the published archive. dpkg's checksum list is local state written at unpack, so
a locally rebuilt package that reuses the exact published version, or a host that
rewrote dpkg's records, is not detected. An installed build that is no longer
listed in the current indexes (a newer update was published and the host has not
upgraded) stays unknown, even though it may be the build an advisory affects. A compromised host can lie about local
bytes or tool output. No receipt proves the historical APT installation
transaction, absence of compromise, current configuration safety or action
authority.

## Evidence chain and publisher policy

For Ubuntu 24.04 and Debian 13 amd64, the verifier:

1. Reads root-owned cached InRelease files. Ubuntu uses fixed `/usr/bin/gpgv`
   status output and an exact selected-certificate descriptor. Because
   [gpgv does not itself check key expiration or revocation](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html),
   the fixed Ubuntu archive-2018 policy first requires a non-expiring v4
   certificate profile. Any revocation packet, nonzero expiration metadata,
   future certificate date or unsupported validity encoding leaves origin
   unknown. This conservative refusal is not a general certificate-validity
   service. The exact inspected certificate bytes enter gpgv through a sealed
   anonymous Linux memory descriptor, because gpgv requires seekable keyring
   lookup. Write/grow/shrink/seal locks are verified before use; no filesystem
   pathname is created and the mutable keyring path is not reopened.
   Only direct signatures by the pinned Ubuntu primary are qualified; a signing
   subkey remains unknown until separately qualified by a versioned policy.
   Debian 13 uses fixed `/usr/bin/sqv`, with exactly one approved
   primary certificate selected from the fixed regular `.pgp` archive keyring
   and passed through an anonymous pipe. Signature packets and the exact
   canonical message are also piped; no output file is opened. A valid signature
   by that primary or its cryptographically bound subkey is required. A bad,
   expired or revoked signature confers no authority. Debian's unrelated
   cross-signatures are not counted as authorizers; an independent valid
   role-approved signature may authenticate the same message.
2. Checks the signed origin, codename and release pocket. Noble release, updates
   and security are allowed. Trixie release, updates and security are allowed;
   Debian security keys are restricted to the security pocket. Proposed,
   backports, testing, PPAs and arbitrary host-added signing keys are excluded.
3. Reads cached Packages data with fixed `/usr/lib/apt/apt-helper cat-file` and
   verifies the entire decompressed index's size and SHA-256 against InRelease.
   The selected stanza must match the installed binary/version/architecture and
   source name/version exactly. Different same-version artifact digests conflict.
4. Reads dpkg's recorded checksum list for the package from
   `/var/lib/dpkg/info/<package>.md5sums` (or `<package>:<arch>.md5sums` for
   Multi-Arch: same; both present is ambiguous). It must be root-owned, not
   group/world-writable, non-empty and well formed, with no duplicate or
   traversing path.
5. Computes the MD5 of every listed installed file and requires it to equal the
   recorded value. dpkg does not list conffiles there, so config contents are not
   claimed. Diversions, modified/unreadable files, unsafe directory/link
   traversal and files that change while read leave origin unknown. A receipt
   requires at least one compared file.

Publisher fingerprint pins are versioned with the trust policy:

| Publisher and role | Primary fingerprint |
| --- | --- |
| Ubuntu archive 2018 | `F6ECB3762474EDA9D21B7022871920D1991BC93C` |
| Debian 13 archive | `04B54C3CDCA79751B16BC6B5225629DF75B188BD` |
| Debian 13 security | `5E04A1E3223A19A20706E20F9904613D4CCE68C6` |
| Debian 13 stable release | `41587F7DB8C774BCCF131416762F67A0B2C39DE4` |

The pins come from the [Ubuntu security documentation](https://documentation.ubuntu.com/security/software-integrity/archive-verification/),
[Ubuntu archive key list](https://wiki.ubuntu.com/Security/FAQ), and
[Debian archive key list](https://ftp-master.debian.org/keys.html).
Host keyring membership alone grants no trust. Changing the pin/pocket policy
requires a source change and a new trust-policy version.

Clearsign processing follows [RFC 9580 sections 7.1–7.2](https://www.rfc-editor.org/rfc/rfc9580.html#section-7)
and [RFC 4880 section 7](https://www.rfc-editor.org/rfc/rfc4880#section-7): reverse
dash escaping, remove only the separator newline before the signature, strip
trailing spaces/tabs per line and use canonical CRLF. Only the exact bytes
verified by detached `sqv`, or corresponding to the exact gpgv-verified clearsign
message, are parsed as release facts. The fixed v4 publisher
policy additionally requires one unambiguous strong Hash header and rejects
mixed line endings, unsupported signature packets, malformed armor/CRC, multiple
messages and unsigned trailing data. LF and CRLF inputs, trailing whitespace and
a signed final empty line have distinct tests. The verifier passes no inherited
`SEQUOIA_CRYPTO_POLICY`, no `--time`/`--policy-as-of` backdating option, and an
explicit current `--not-after` bound.

InRelease dates and validity deadlines are retained. An expired cached index can
still attribute an historical published artifact when its signature is valid
under this policy. This is separate from backend inventory/source freshness and
never extends a later action deadline. Future metadata or signatures are refused.

## Fixed reads, bounds and incomplete evidence

The only roots are `/var/lib/apt/lists`, `/var/lib/dpkg/info`, and the
distribution archive keyring in `/usr/share/keyrings`. Dpkg diversions are read
from `/var/lib/dpkg/diversions` and included in the capture state fingerprint.
Installed paths come only from dpkg's checksum list for a package whose exact
identity matched a signed index. Descriptor-relative
no-follow traversal rejects symlink substitution and writable/non-root parents;
the four fixed distro `/usr` merge aliases have explicit target checks. File and
symlink identities are checked around observation. As with inventory capture,
these checks cannot rule out an adversarial change-and-restore on a compromised
host. Dpkg state is checked again after provenance collection; unstable captures
discard all official-origin classifications.

The verifier has a 45-second context inside the existing capture deadline, at
most 16 indexes, 128 MiB per decompressed index and 256 MiB in total. Directory
enumerations stop at 4,096 entries. Checksum lists are capped at 4 MiB and 8,192
files per package, installed reads at 1 GiB per capture, receipts at 128, and the
audit report at 512 KiB. On the 2026-11-25 Ubuntu 24.04 trial hosts a capture
produced 26 verified receipts in about 5 seconds with a 16 KB report. Existing inventory
page/capture limits also apply. Provenance completions have a separate
655,360-byte wire ceiling; the ordinary 262,144-byte page/response ceilings and
1,900,000-byte capture ceiling do not increase. An exceeded budget leaves affected package
origins unknown; it does not manufacture a complete verified subset.

Commands use fixed absolute executables, fixed operations and a clean
environment. There is no shell, package-manager lock, `apt update`, download,
installation, script execution, repair or fallback mutation. A missing index or
checksum list remains unknown and is not repaired.

## Qualification

Unit fixtures using an authenticated-index seam are deliberately synthetic and
do not claim official signature provenance. They verify classification, identity
binding, scope selection, same-archive pocket duplicates, negative signature
status, missing/malformed/traversing checksum lists, changed or unreadable files
and unchanged v1 behavior. A separate offline Linux corpus using real
publisher-signed cached metadata and exact artifact bytes is needed to qualify
the native command/filesystem chain. An actual deployed/enrolled agent receipt
and any production rollout are separate outcomes.

`scripts/prepare-native-provenance-corpus.py` stages the finite retained corpus
into a new task-owned directory, after verifying original archive/Release/index
hashes. It never changes those originals. The exact archive payloads and
controlled dpkg status enter disposable Linux roots without running package
scripts. The opt-in `TestNativeCachedProvenanceCorpus` then runs the real native
collector with read-only filesystems and no network. The backend's separate
native integration runner issues each real v2 request before that capture and
uses its unmodified pages/completion through admission, evaluation and
authenticated reads. It retains six unknown mutation cases and a portable
digest/count/result receipt. Its 46-archive matrix is deliberately finite: all
eight paired boundaries plus the nine PHP variants before/after on both OSes;
it does not qualify every binary the collector can discover.

For the Debian main Release, an extra opt-in native subtest uses its real three
cross-signatures to check approved/wrong-role/wrong-primary, legacy-only,
bad-only, an independent valid approved signature alongside an unrelated bad
signature, semantic-preserving signed-body tampering, unsigned trailing data
and multiple signed messages. Structural synthetic certificate fixtures cover
Ubuntu's conservative expiration/revocation refusal; the real Ubuntu retained
chain must also pass the exact inspected-certificate descriptor path.

`signed-index-v1` has been run, unenrolled and read-only as an unprivileged user,
on the two Ubuntu 24.04 trial hosts (devclash-web and devclash-api, 2026-11-25):
26/26 evaluated packages verified on each, the capture was complete and stable,
and `PrepareUpload` accepted it. The retained-corpus run below has not yet been
repeated for `signed-index-v1`; the corpus script now writes each archive's
md5sums into dpkg's info directory so it can be.

Local qualification receipts for `cached-deb-chain-v1` are retained separately:

- [Archive/capture results](qualification/passive-provenance-2026-10-26.json):
  46 unique signed-origin artifacts in 14 positive captures, all eight paired
  boundaries, 32 additional PHP artifacts, six unknown mutation captures and
  nine real Debian publisher-policy cases. The backend pipeline passed 21/21
  without skips. The accepted integration receipt binds 42 unchanged backend
  runtime/schema/fixture files before child-process start and after completion.
  A prior helper-file change was detected and that attempt was not accepted as
  current-tree qualification.
- [Updated backend cleanup receipt](qualification/passive-provenance-post-cleanup-2026-10-26.json):
  a separate 21/21, zero-skip pipeline rerun after the backend evaluation cleanup
  and fixture shutdown changes. The same native source/binary and corpus passed
  in 87.929 seconds, with 42 unchanged backend runtime/schema/fixture files
  before and after execution. Its receipt SHA256 is
  `4f565e03763571ca6537dc00d7981d367aebec7a798e6a7c9731d800af0015cd`.
  Both receipts describe their recorded backend file hashes; neither extends
  qualification to subsequent backend revisions.
- [Source/binary manifest](qualification/passive-provenance-source-2026-10-26.json):
  the exact 136 Go source-file hashes and native test-binary digest.
- [Verification boundaries](qualification/passive-provenance-verification-2026-10-26.json):
  Go 1.22.12 Linux arm64 unit results (169 top-level passes, 11 explicit skips;
  302 pass entries including parent/subtests), native Linux race checks on the
  three required packages, Linux amd64 vet/build and bounded framing fuzzing.
  Ten pre-existing optional migration/systemd tests were not run; the native
  corpus skip in the ordinary unit suite was executed separately above.

The amd64 package/tool chain ran in bounded amd64 Linux containers on an arm64
host. The complete unit and race checks ran in native Linux arm64 containers.
Earlier x86 emulation `openat2` and macOS Go 1.22 loader failures are recorded
as nonqualifying environment attempts, rather than counted as passing coverage.
No tested binary is a promoted, released or deployed agent artifact.
