#!/usr/bin/env python3
"""Stage a finite, retained public corpus. Never install or execute a package.

The originals remain read-only. A disposable root contains an explicitly
controlled dpkg observation and exact archive payloads. Runtime verification
uses the real collector in a network-disabled, read-only Linux container.
"""
import argparse
import hashlib
import json
import lzma
import pathlib
import shutil
import subprocess
import tarfile
import io
import os

CONTEXT = "colima-askio-phase1-qualification"
IMAGES = {
    "u24": "ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac",
    "d13": "debian@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad",
}
SUFFIXES = ["cli", "fpm", "common", "opcache", "readline", "curl", "mbstring", "xml", "mysql"]
CUSTODY_ROOT = None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked(path, sha, size=None):
    resolved = path.resolve(strict=True)
    if CUSTODY_ROOT is None or not resolved.is_relative_to(CUSTODY_ROOT):
        raise ValueError("retained input leaves the explicitly supplied custody root")
    if not resolved.is_file() or not (resolved.suffix in [".deb", ".xz"] or resolved.name.endswith("InRelease")):
        raise ValueError("unexpected retained public artifact type")
    limit = 64 * 1024 * 1024 if resolved.suffix == ".deb" else 128 * 1024 * 1024
    if resolved.stat().st_size > limit:
        raise ValueError("retained public input exceeds its fixed read budget")
    with resolved.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("retained public input grew beyond its fixed read budget")
    if digest(raw) != sha or (size is not None and len(raw) != size):
        raise ValueError("retained input hash/size mismatch: " + path.name)
    return raw


def fields(text):
    return dict(line.split(": ", 1) for line in text.splitlines() if line and not line[0].isspace() and ": " in line)


def archive_stream(raw, operation):
    return subprocess.check_output([
        "docker", "--context", CONTEXT, "run", "--rm", "--pull=never", "-i", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cpus", "1", "--memory", "128m", "--pids-limit", "64",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "/usr/bin/dpkg-deb",
        IMAGES["u24"], operation, "-"], input=raw, timeout=30)


def auth_entry(root, auth, url):
    item = next(i for i in auth["indexes"] if i["source_url"] == url)
    release = next(r for r in auth["releases"] if pathlib.Path(r["file"]).name == item["release_file"])
    return (root / release["file"], release["sha256"], root / "metadata" / item["file"],
            item["sha256"], item["bytes"], item["relative_path"])


def write_source_manifest(output, binary):
    repository = pathlib.Path(__file__).resolve().parent.parent
    files = []
    for file in sorted(repository.rglob("*.go")):
        relative = file.relative_to(repository)
        if ".git" in relative.parts or "vendor" in relative.parts:
            continue
        raw = file.read_bytes()
        files.append({"path": str(relative), "bytes": len(raw), "sha256": digest(raw)})
    if len(files) > 4096:
        raise ValueError("native source manifest exceeds its fixed file-count budget")
    value = {"schemaVersion": "1", "toolchain": "go1.22.12", "target": "linux/amd64",
             "nativeTestBinarySha256": digest(binary.read_bytes()), "goFiles": files}
    (output / "source-manifest.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    global CUSTODY_ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--custody", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--test-binary", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("output must be a new task-owned directory")
    args.output.mkdir(mode=0o700, parents=True)
    corpus = args.custody.resolve(strict=True)
    CUSTODY_ROOT = corpus
    cases = []
    b7 = corpus / "ASKIO-P0-B7/fixture-prep"
    auth7 = json.loads((b7 / "authentication-b7-fresh.json").read_text())
    rows7 = json.loads((b7 / "package-custody.json").read_text())["rows"]
    for role, branch, versions in [("u24", "8.3", ["8.3.6-0ubuntu0.24.04.5", "8.3.6-0ubuntu0.24.04.6"]),
                                   ("d13", "8.4", ["8.4.11-1", "8.4.16-1~deb13u1"])]:
        for side, version in zip(["before", "after"], versions):
            packages = []
            for suffix in SUFFIXES:
                identity = "php" + branch + "-" + suffix + "=" + version + ":amd64"
                row = next(r for r in rows7 if r["role"] == role and r["identity"] == identity)
                packages.append((b7.parent / row["path"], row["sha256"], row["bytes"], auth_entry(b7, auth7, row["signed_index_url"])))
            cases.append((role + "-php-" + side, role, packages))
    b3 = corpus / "ASKIO-P0-B3/fixture-prep"
    auth3 = json.loads((b3 / "authentication-fresh-supplement.json").read_text())
    rows3 = json.loads((b3 / "package-custody.json").read_text())
    for role, versions in [("u24", ["2.4.58-1ubuntu8.8", "2.4.58-1ubuntu8.11", "2.4.58-1ubuntu8.12"]),
                           ("d13", ["2.4.65-2", "2.4.66-1~deb13u1", "2.4.67-1~deb13u2"])]:
        for number, version in enumerate(versions):
            row = next(r for r in rows3 if r["os"] == role.upper() and r["identity"] == "apache2-bin=" + version + ":amd64")
            entry = auth_entry(b3, auth3, row["catalog"]["index_url"])
            cases.append((role + "-apache-" + str(number), role, [(b3 / row["retained_path"], row["sha256"], row["bytes"], entry)]))
    # The nginx witnesses predate the B3/B7 bundle. Read their exact retained
    # authentication records, then select the exact binary/version index stanza.
    for role, versions in [("u24", ["1.24.0-2ubuntu7.5", "1.24.0-2ubuntu7.6"]),
                           ("d13", ["1.26.3-3+deb13u1", "1.26.3-3+deb13u2"])]:
        base = corpus / ("ASKIO-P0-B1/reviewed-export/authenticated-inputs" if role == "u24" else "ASKIO-P0-B2/fixture-prep")
        if role == "u24":
            auth = json.loads((base / "retained-authentication-receipt.json").read_text())["releases"]
        else:
            auth = json.loads((base / "package-records.json").read_text())
        for number, version in enumerate(versions):
            if role == "u24":
                witness = auth[number]
                prefix = "pre-main" if number == 0 else "web-post-main"
                ix = witness["indexes"][0]
                entry = (base / (prefix + ".InRelease"), witness["sha256"], base / (prefix + ".Packages.xz"), ix["sha256"], ix["size"], ix["relative"])
            else:
                witness = auth[number]
                entry = (pathlib.Path(witness["release"]["path"]), witness["release"]["sha256"], pathlib.Path(witness["index"]["path"]), witness["index"]["sha256"], witness["index"]["bytes"], witness["prior_authentication"]["indexes"][0]["relative"])
            data = checked(entry[2], entry[3], entry[4])
            matching = [fields(stanza) for stanza in lzma.decompress(data).decode().split("\n\n")
                        if stanza.startswith("Package: nginx\n") and fields(stanza).get("Version") == version]
            if len(matching) != 1:
                raise ValueError("exact nginx stanza missing/ambiguous")
            stanza = matching[0]
            archives = list(base.rglob("nginx_" + version + "_amd64.deb"))
            if len(archives) != 1:
                raise ValueError("exact nginx archive missing/ambiguous")
            cases.append((role + "-nginx-" + str(number), role, [(archives[0], stanza["SHA256"], int(stanza["Size"]), entry)]))
    manifest = {"schemaVersion": "1", "mode": "retained-signed-corpus-controlled-dpkg-observation", "cases": []}
    for name, role, packages in cases:
        case = args.output / name
        fs = case / "root"
        fs.mkdir(parents=True)
        status, expected, artifacts = [], [], []
        for path, sha, size, entry in packages:
            raw = checked(path, sha, size)
            payload = archive_stream(raw, "--fsys-tarfile")
            # Retained publisher bytes only, but still refuse escaping archive paths.
            with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                for member in archive.getmembers():
                    candidate = pathlib.PurePosixPath(member.name)
                    if candidate.is_absolute() or ".." in candidate.parts or member.isdev() or member.isfifo():
                        raise ValueError("unsafe retained payload")
                # Python 3.9 is available on the qualification host, so perform
                # the extraction policy explicitly rather than relying on a
                # newer tarfile filter keyword.
                for member in archive.getmembers():
                    target = fs / member.name
                    if target.resolve() == fs.resolve() and member.isdir():
                        continue
                    if not target.parent.resolve().is_relative_to(fs.resolve()):
                        raise ValueError("escaping retained payload parent")
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        if target.is_symlink():
                            raise ValueError("retained payload file crosses symlink")
                        with target.open("wb") as output:
                            shutil.copyfileobj(archive.extractfile(member), output)
                        target.chmod(member.mode & 0o777)
                    elif member.issym():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        if target.exists() or target.is_symlink():
                            if not target.is_symlink() or os.readlink(target) != member.linkname:
                                raise ValueError("conflicting retained payload link")
                        else:
                            target.symlink_to(member.linkname)
                    else:
                        raise ValueError("unsupported retained payload member")
            control_tar = archive_stream(raw, "--ctrl-tarfile")
            with tarfile.open(fileobj=io.BytesIO(control_tar)) as archive:
                control = archive.extractfile("./control").read().decode()
            identity = fields(control)
            status.append(control.replace("Package: " + identity["Package"] + "\n", "Package: " + identity["Package"] + "\nStatus: install ok installed\n", 1))
            expected.append({"binaryName": identity["Package"], "architecture": identity["Architecture"], "version": identity["Version"], "origin": "official"})
            release_path, release_sha, index_path, index_sha, index_size, relative = entry
            release_raw = checked(release_path, release_sha)
            checked(index_path, index_sha, index_size)
            suite = fields(release_raw.decode())["Suite"]
            lists = fs / "var/lib/apt/lists"
            lists.mkdir(parents=True, exist_ok=True)
            # Different retained snapshots of one suite are independent cache
            # sources. Never pair January's universe index with March's Release.
            prefix = "fixture_" + role + "_" + release_sha[:16] + "_dists_" + suite
            shutil.copyfile(release_path, lists / (prefix + "_InRelease"))
            shutil.copyfile(index_path, lists / (prefix + "_" + relative.replace("/", "_")))
            cache = fs / "var/cache/apt/archives"
            cache.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, cache / path.name)
            artifacts.append({"binaryName": identity["Package"], "source": identity.get("Source", identity["Package"]), "architecture": identity["Architecture"], "version": identity["Version"], "archiveSha256": sha, "archiveBytes": size, "releaseSha256": release_sha, "compressedIndexSha256": index_sha})
        dpkg = fs / "var/lib/dpkg"
        (dpkg / "updates").mkdir(parents=True, exist_ok=True)
        (dpkg / "status").write_text("\n\n".join(s.strip() for s in status) + "\n\n")
        proof = fs / "proof"
        proof.mkdir()
        shutil.copyfile(args.test_binary, proof / "provenance.test")
        (proof / "provenance.test").chmod(0o755)
        (proof / "expected.json").write_text(json.dumps(expected))
        (case / "Dockerfile").write_text("FROM " + IMAGES[role] + '\nCOPY root/ /\nENTRYPOINT ["/proof/provenance.test"]\nCMD ["-test.v","-test.run","^TestNativeCachedProvenanceCorpus$"]\n')
        manifest["cases"].append({"id": name, "role": role, "image": IMAGES[role], "artifacts": artifacts})
        print(json.dumps({"case": name, "artifacts": len(artifacts), "retainedHashesVerified": True}), flush=True)
    if len(cases) != 14 or sum(len(c[2]) for c in cases) != 46:
        raise ValueError("qualification denominator changed")
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    write_source_manifest(args.output, args.test_binary)


if __name__ == "__main__":
    main()
