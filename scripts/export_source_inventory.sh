#!/usr/bin/env bash
set -euo pipefail

SRC_CLOUD=${1:?source cloud}
TGT_CLOUD=${2:?target cloud}
HOST=${3:?host}
OUT=${4:?out dir}
mkdir -p "$OUT"

export OS_CLOUD="$SRC_CLOUD"
openstack server list --all-projects --host "$HOST" --long -f json > "$OUT/source_servers.json"
openstack compute service list --host "$HOST" -f json > "$OUT/source_compute_service.json" || true
openstack hypervisor list --long -f json > "$OUT/source_hypervisors.json" || true
openstack port list --host "$HOST" --long -f json > "$OUT/source_ports_by_host.json" || true

python3 - "$OUT" <<'PY'
import json, pathlib, subprocess, sys, shlex, os
out=pathlib.Path(sys.argv[1])
servers=json.loads((out/'source_servers.json').read_text())
manifest={'rehome_instances': []}
for s in servers:
    uuid=s.get('ID') or s.get('ID'.lower()) or s.get('id')
    if not uuid: continue
    def run(cmd):
        return subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ss=run(f"openstack server show {shlex.quote(uuid)} -f json")
    server_show=json.loads(ss.stdout) if ss.returncode == 0 and ss.stdout.strip() else {}
    ports=[]
    ps=run(f"openstack port list --server {shlex.quote(uuid)} --long -f json")
    if ps.returncode == 0 and ps.stdout.strip():
        for p in json.loads(ps.stdout):
            pid=p.get('ID') or p.get('id')
            pshow=run(f"openstack port show {shlex.quote(pid)} -f json")
            pobj=json.loads(pshow.stdout) if pshow.returncode == 0 and pshow.stdout.strip() else p
            ports.append({
                'id': pid,
                'mac_address': pobj.get('mac_address') or pobj.get('MAC Address') or p.get('MAC Address'),
                'fixed_ips': pobj.get('fixed_ips') or pobj.get('Fixed IP Addresses') or p.get('Fixed IP Addresses'),
                'network_id': pobj.get('network_id'),
                'device_id': pobj.get('device_id'),
                'device_owner': pobj.get('device_owner'),
                'binding_host_id': pobj.get('binding_host_id') or pobj.get('binding:host_id'),
                'binding_profile': pobj.get('binding_profile') or pobj.get('binding:profile') or {},
            })
    volumes=[]
    # Server show usually includes volumes_attached in OSC JSON.
    va=server_show.get('volumes_attached') or server_show.get('os-extended-volumes:volumes_attached') or []
    if isinstance(va, str):
        # leave as raw string if OSC formatter changed
        volumes.append({'raw': va})
    else:
        for v in va:
            if isinstance(v, dict): volumes.append(v)
    manifest['rehome_instances'].append({
        'uuid': uuid,
        'name': s.get('Name') or server_show.get('name'),
        'status': s.get('Status') or server_show.get('status'),
        'host': server_show.get('OS-EXT-SRV-ATTR:host'),
        'instance_name': server_show.get('OS-EXT-SRV-ATTR:instance_name'),
        'hypervisor_hostname': server_show.get('OS-EXT-SRV-ATTR:hypervisor_hostname'),
        'ports': ports,
        'volumes': volumes,
    })

# simple YAML without requiring PyYAML
with open(out/'rehome_manifest.yml','w') as f:
    def emit(obj, indent=0):
        sp='  '*indent
        if isinstance(obj, dict):
            for k,v in obj.items():
                if isinstance(v,(dict,list)):
                    f.write(f"{sp}{k}:\n"); emit(v, indent+1)
                else:
                    f.write(f"{sp}{k}: {json.dumps(v, ensure_ascii=False)}\n")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item,(dict,list)):
                    f.write(f"{sp}- ")
                    if isinstance(item, dict) and item:
                        # print first scalar inline if possible, then rest nested
                        f.write("\n"); emit(item, indent+1)
                    else:
                        f.write("\n"); emit(item, indent+1)
                else:
                    f.write(f"{sp}- {json.dumps(item, ensure_ascii=False)}\n")
    emit(manifest)
print(out/'rehome_manifest.yml')
PY

export OS_CLOUD="$TGT_CLOUD"
openstack compute service list --host "$HOST" -f json > "$OUT/target_compute_service_pre.json" || true
openstack hypervisor list --long -f json > "$OUT/target_hypervisors_pre.json" || true
