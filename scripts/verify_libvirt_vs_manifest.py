#!/usr/bin/env python3
"""Simple checker: compare libvirt domain UUIDs from `virsh list --uuid` with manifest instance UUIDs."""
import pathlib, re, sys
manifest = pathlib.Path(sys.argv[1]).read_text()
virsh = pathlib.Path(sys.argv[2]).read_text()
manifest_uuids = set(re.findall(r"uuid:\s*['\"]?([0-9a-fA-F-]{36})", manifest))
virsh_uuids = {x.strip() for x in virsh.splitlines() if re.match(r"^[0-9a-fA-F-]{36}$", x.strip())}
missing_in_libvirt = manifest_uuids - virsh_uuids
unknown_in_manifest = virsh_uuids - manifest_uuids
print("manifest UUIDs:", len(manifest_uuids))
print("libvirt UUIDs:", len(virsh_uuids))
if missing_in_libvirt:
    print("Missing in libvirt:", sorted(missing_in_libvirt))
if unknown_in_manifest:
    print("Unknown in manifest:", sorted(unknown_in_manifest))
sys.exit(1 if missing_in_libvirt or unknown_in_manifest else 0)
