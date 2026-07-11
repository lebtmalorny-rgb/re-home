from copy import deepcopy
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

from .contract import CheckResult, CollectorResult, DependencyEdge, ResourceNode
from .runner import CommandEvidence, ProbeFailed


_VOLUME_ID = re.compile(r"(?:^|[/_.:-])(volume-[A-Za-z0-9-]+)(?:$|[/_.:-])")
_PORT_PREFIXES = ("tap", "qvo", "qvb", "qr-", "qg-", "vhu")


def _ovs_atom(value: object) -> object:
    if not isinstance(value, list) or len(value) != 2:
        return value
    kind, payload = value
    if kind == "map" and isinstance(payload, list):
        return {str(key): _ovs_atom(item) for key, item in payload}
    if kind == "set" and isinstance(payload, list):
        return [_ovs_atom(item) for item in payload]
    if kind == "uuid":
        return payload
    return value


def _parse_ovs_table(stdout: str) -> List[Dict[str, object]]:
    try:
        payload = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(payload, Mapping):
        return []
    headings = payload.get("headings")
    data = payload.get("data")
    if not isinstance(headings, list) or not isinstance(data, list):
        return []
    rows = []
    for values in data:
        if not isinstance(values, list) or len(values) != len(headings):
            continue
        rows.append(
            {
                str(key): _ovs_atom(value)
                for key, value in zip(headings, values)
            }
        )
    return rows


def _redact_xml_secrets(xml_text: str) -> str:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "[REDACTED INVALID DOMAIN XML]"
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "secret":
            continue
        element.attrib.clear()
        element.text = "[REDACTED]"
        for child in list(element):
            element.remove(child)
    return ET.tostring(root, encoding="unicode")


def _evidence_dict(
    evidence: CommandEvidence,
    *,
    stdout: Optional[str] = None,
) -> Dict[str, object]:
    payload = evidence.to_dict()
    if stdout is not None:
        payload["stdout"] = stdout
    return payload


def _volume_id(source: object, serial: object = None) -> Optional[str]:
    for candidate in (serial, source):
        if not isinstance(candidate, str):
            continue
        match = _VOLUME_ID.search(f"/{candidate}/")
        if match:
            return match.group(1)
    return None


def _port_id(target: str, external_ids: Mapping[str, object]) -> Optional[str]:
    for key in ("iface-id", "neutron:port_id", "port_id"):
        value = external_ids.get(key)
        if isinstance(value, str) and value:
            return value
    for prefix in _PORT_PREFIXES:
        if target.startswith(prefix) and len(target) > len(prefix):
            return target[len(prefix):].lstrip("-_")
    return None


def _xml_facts(xml_text: str) -> Dict[str, object]:
    root = ET.fromstring(xml_text)
    domain_uuid = root.findtext("uuid")
    name = root.findtext("name")
    instance_uuid = domain_uuid
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name in {"instance_uuid", "uuid"} and element is not root.find("uuid"):
            if element.text and element.text.strip():
                instance_uuid = element.text.strip()
                break
        if local_name == "instance":
            metadata_uuid = element.attrib.get("uuid")
            if metadata_uuid:
                instance_uuid = metadata_uuid
                break

    machine = root.find("./os/type")
    machine_type = machine.attrib.get("machine") if machine is not None else None
    disks: Dict[str, Dict[str, object]] = {}
    for disk in root.findall("./devices/disk"):
        target = disk.find("target")
        source = disk.find("source")
        if target is None:
            continue
        target_name = target.attrib.get("dev")
        if not target_name:
            continue
        source_value = None
        if source is not None:
            for attribute in ("dev", "file", "name", "volume"):
                if source.attrib.get(attribute):
                    source_value = source.attrib[attribute]
                    break
        disks[target_name] = {
            "bus": target.attrib.get("bus"),
            "source": source_value,
            "serial": disk.findtext("serial"),
        }
    return {
        "name": name,
        "domain_uuid": domain_uuid,
        "instance_uuid": instance_uuid,
        "machine_type": machine_type,
        "disks": disks,
    }


def _parse_domain_list(stdout: str) -> List[str]:
    names = []
    for line in stdout.splitlines():
        values = line.split()
        if not values:
            continue
        names.append(values[-1])
    return names


def _parse_dominfo(stdout: str) -> Dict[str, str]:
    facts = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        facts[key.strip().lower().replace(" ", "_")] = value.strip()
    return facts


def _parse_domblklist(stdout: str) -> List[Dict[str, Optional[str]]]:
    rows = []
    for line in stdout.splitlines():
        values = line.split(None, 3)
        if len(values) != 4 or values[0].lower() in {"type", "----"}:
            continue
        if set(values[0]) == {"-"}:
            continue
        rows.append(
            {
                "type": values[0],
                "device": values[1],
                "target": values[2],
                "source": None if values[3] == "-" else values[3],
            }
        )
    return rows


def _parse_domiflist(stdout: str) -> List[Dict[str, Optional[str]]]:
    rows = []
    for line in stdout.splitlines():
        values = line.split()
        if len(values) < 5 or values[0].lower() == "interface":
            continue
        if set(values[0]) == {"-"}:
            continue
        rows.append(
            {
                "target": values[0],
                "type": values[1],
                "source": values[2],
                "model": values[3],
                "mac": values[4],
            }
        )
    return rows


def _run(
    runner,
    argv: Sequence[object],
    evidence_id: str,
    result: CollectorResult,
    *,
    redact_xml: bool = False,
) -> Optional[str]:
    try:
        evidence = runner.run(argv, evidence_id)
    except ProbeFailed as error:
        evidence = error.evidence
        result.blockers.append(f"runtime probe failed: {evidence_id}")
    persisted_stdout = (
        _redact_xml_secrets(evidence.stdout) if redact_xml else evidence.stdout
    )
    result.evidence.append(_evidence_dict(evidence, stdout=persisted_stdout))
    return evidence.stdout if evidence.returncode == 0 else None


def collect_runtime(runner, virsh_argv, network_backend) -> CollectorResult:
    side = str(getattr(runner, "side", "source"))
    result = CollectorResult(service="runtime", side=side)
    virsh = [str(item) for item in virsh_argv]
    listed = _run(
        runner,
        [*virsh, "list", "--uuid", "--name"],
        f"runtime-{side}-virsh-list",
        result,
    )
    if listed is None:
        return result

    ovs_interfaces: Dict[str, Mapping[str, object]] = {}
    ovs_ports: List[Mapping[str, object]] = []
    ovn_bindings: List[Mapping[str, object]] = []
    if network_backend == "ovs":
        interface_stdout = _run(
            runner,
            ["ovs-vsctl", "--format=json", "list", "Interface"],
            f"runtime-{side}-ovs-interface-list",
            result,
        )
        port_stdout = _run(
            runner,
            ["ovs-vsctl", "--format=json", "list", "Port"],
            f"runtime-{side}-ovs-port-list",
            result,
        )
        for row in _parse_ovs_table(interface_stdout or ""):
            name = row.get("name")
            if isinstance(name, str):
                ovs_interfaces[name] = row
        ovs_ports = _parse_ovs_table(port_stdout or "")
    elif network_backend == "ovn":
        binding_stdout = _run(
            runner,
            ["ovn-sbctl", "--format=json", "list", "Port_Binding"],
            f"runtime-{side}-ovn-port-binding-list",
            result,
        )
        ovn_bindings = _parse_ovs_table(binding_stdout or "")
    else:
        result.unknowns.append(f"unsupported network backend: {network_backend}")

    edge_keys = set()

    def add_edge(source: str, target: str, relation: str, required: bool = True) -> None:
        key = (source, target, relation, required)
        if key not in edge_keys:
            edge_keys.add(key)
            result.edges.append(DependencyEdge(source, target, relation, required))

    for domain_name in _parse_domain_list(listed):
        dominfo = _run(
            runner,
            [*virsh, "dominfo", domain_name],
            f"runtime-{side}-dominfo-{domain_name}",
            result,
        )
        xml = _run(
            runner,
            [*virsh, "dumpxml", domain_name, "--security-info"],
            f"runtime-{side}-dumpxml-{domain_name}",
            result,
            redact_xml=True,
        )
        block_list = _run(
            runner,
            [*virsh, "domblklist", domain_name, "--details"],
            f"runtime-{side}-domblklist-{domain_name}",
            result,
        )
        interface_list = _run(
            runner,
            [*virsh, "domiflist", domain_name],
            f"runtime-{side}-domiflist-{domain_name}",
            result,
        )
        if xml is None:
            continue
        try:
            xml_facts = _xml_facts(xml)
        except ET.ParseError:
            result.blockers.append(f"invalid domain XML: {domain_name}")
            continue
        info = _parse_dominfo(dominfo or "")
        domain = ResourceNode(
            "libvirt_domain",
            domain_name,
            side,
            {
                "domain_uuid": xml_facts.get("domain_uuid"),
                "instance_uuid": xml_facts.get("instance_uuid"),
                "state": info.get("state"),
                "machine_type": xml_facts.get("machine_type"),
            },
        )
        result.nodes.append(domain)
        xml_disks = xml_facts.get("disks", {})
        for disk in _parse_domblklist(block_list or ""):
            target = disk["target"]
            if not target:
                continue
            xml_disk = xml_disks.get(target, {}) if isinstance(xml_disks, Mapping) else {}
            source = disk.get("source") or xml_disk.get("source")
            volume_id = _volume_id(source, xml_disk.get("serial"))
            disk_node = ResourceNode(
                "runtime_disk",
                f"{domain_name}/{target}",
                side,
                {
                    **disk,
                    "source": source,
                    "bus": xml_disk.get("bus"),
                    "volume_id": volume_id,
                },
            )
            result.nodes.append(disk_node)
            add_edge(domain.key, disk_node.key, "has_runtime_disk")
            if volume_id:
                add_edge(domain.key, f"volume:{volume_id}", "uses_volume")
                add_edge(disk_node.key, f"volume:{volume_id}", "maps_to_volume")
            elif disk.get("device") == "disk":
                result.blockers.append(
                    f"unmapped runtime disk: {domain_name}/{target}"
                )

        for interface in _parse_domiflist(interface_list or ""):
            target = interface.get("target")
            if not target:
                continue
            ovs_row = ovs_interfaces.get(target, {})
            external_ids = ovs_row.get("external_ids", {})
            if not isinstance(external_ids, Mapping):
                external_ids = {}
            port_id = _port_id(target, external_ids)
            interface_node = ResourceNode(
                "runtime_interface",
                target,
                side,
                {**interface, "port_id": port_id},
            )
            result.nodes.append(interface_node)
            add_edge(domain.key, interface_node.key, "has_runtime_interface")
            if port_id:
                add_edge(interface_node.key, f"port:{port_id}", "maps_to_port")
            else:
                result.blockers.append(
                    f"unmapped runtime interface: {domain_name}/{target}"
                )

    for row in ovs_ports:
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        node = ResourceNode("ovs_port", name, side, deepcopy(dict(row)))
        result.nodes.append(node)
        interface_row = ovs_interfaces.get(name, {})
        external_ids = interface_row.get("external_ids", {})
        if not isinstance(external_ids, Mapping):
            external_ids = {}
        port_id = _port_id(name, external_ids)
        if port_id:
            add_edge(node.key, f"port:{port_id}", "maps_to_port")

    for row in ovn_bindings:
        logical_port = row.get("logical_port")
        if not isinstance(logical_port, str) or not logical_port:
            continue
        node = ResourceNode("ovn_binding", logical_port, side, deepcopy(dict(row)))
        result.nodes.append(node)
        add_edge(node.key, f"port:{logical_port}", "maps_to_port")
    return result


def compare_machine_types(
    source_types: Iterable[str],
    target_types: Iterable[str],
) -> List[CheckResult]:
    supported = set(target_types)
    checks = []
    for machine_type in dict.fromkeys(source_types):
        present = machine_type in supported
        checks.append(
            CheckResult(
                f"runtime.machine-type.{machine_type}",
                "PASS" if present else "BLOCKED",
                (
                    f"target supports machine type: {machine_type}"
                    if present
                    else f"target missing machine type: {machine_type}"
                ),
            )
        )
    return checks


def compare_disk_buses(
    source_buses: Iterable[str],
    target_buses: Iterable[str],
) -> List[CheckResult]:
    supported = set(target_buses)
    checks = []
    for disk_bus in dict.fromkeys(source_buses):
        present = disk_bus in supported
        checks.append(
            CheckResult(
                f"runtime.disk-bus.{disk_bus}",
                "PASS" if present else "BLOCKED",
                (
                    f"target supports disk bus: {disk_bus}"
                    if present
                    else f"target missing disk bus: {disk_bus}"
                ),
            )
        )
    return checks


def compare_runtime_to_nova(
    runtime_result: CollectorResult,
    nova_result: CollectorResult,
) -> List[CheckResult]:
    nova_instances = {
        node.id for node in nova_result.nodes if node.kind == "instance"
    }
    checks = []
    runtime_instance_ids = set()
    for domain in (
        node for node in runtime_result.nodes if node.kind == "libvirt_domain"
    ):
        instance_uuid = domain.facts.get("instance_uuid")
        if isinstance(instance_uuid, str) and instance_uuid:
            runtime_instance_ids.add(instance_uuid)
        present = isinstance(instance_uuid, str) and instance_uuid in nova_instances
        checks.append(
            CheckResult(
                f"runtime.nova-domain.{domain.id}",
                "PASS" if present else "BLOCKED",
                (
                    f"runtime domain maps to Nova instance: {instance_uuid}"
                    if present
                    else f"runtime domain missing from Nova: {domain.id}"
                ),
                resource_ids=[domain.key]
                + ([f"instance:{instance_uuid}"] if present else []),
            )
        )
    for instance_uuid in sorted(nova_instances - runtime_instance_ids):
        checks.append(
            CheckResult(
                f"runtime.nova-instance.{instance_uuid}",
                "BLOCKED",
                f"Nova instance missing runtime domain: {instance_uuid}",
                resource_ids=[f"instance:{instance_uuid}"],
            )
        )
    return checks


def _machine_types(stdout: str) -> List[str]:
    machine_types = []
    for line in stdout.splitlines():
        values = line.split()
        if not values or values[0].lower() in {"supported", "name"}:
            continue
        candidate = values[0]
        if candidate.startswith("pc") or candidate.startswith("q35"):
            machine_types.append(candidate)
    return list(dict.fromkeys(machine_types))


def _disk_buses(domcapabilities_xml: str) -> List[str]:
    try:
        root = ET.fromstring(domcapabilities_xml)
    except ET.ParseError:
        return []
    buses = []
    for enum in root.iter("enum"):
        if enum.attrib.get("name") != "bus":
            continue
        buses.extend(
            value.text.strip()
            for value in enum.findall("value")
            if value.text and value.text.strip()
        )
    return list(dict.fromkeys(buses))


def collect_target_capabilities(runner, virsh_argv, qemu_argv) -> CollectorResult:
    result = CollectorResult(service="runtime-capabilities", side="target")
    virsh = [str(item) for item in virsh_argv]
    qemu = [str(item) for item in qemu_argv]
    _run(
        runner,
        [*virsh, "version"],
        "runtime-target-virsh-version",
        result,
    )
    domcapabilities = _run(
        runner,
        [*virsh, "domcapabilities"],
        "runtime-target-domcapabilities",
        result,
    )
    machine_help = _run(
        runner,
        [*qemu, "-machine", "help"],
        "runtime-target-qemu-machine-help",
        result,
    )
    machine_types = _machine_types(machine_help or "")
    disk_buses = _disk_buses(domcapabilities or "")
    if not machine_types:
        result.blockers.append("target machine type capabilities missing")
    if not disk_buses:
        result.blockers.append("target disk bus capabilities missing")
    result.checks.extend(
        [
            CheckResult(
                "runtime.target.machine-types",
                "PASS" if machine_types else "BLOCKED",
                "target machine types collected" if machine_types else "target machine types missing",
                resource_ids=machine_types,
            ),
            CheckResult(
                "runtime.target.disk-buses",
                "PASS" if disk_buses else "BLOCKED",
                "target disk buses collected" if disk_buses else "target disk buses missing",
                resource_ids=disk_buses,
            ),
        ]
    )
    return result


class FixtureRuntimeRunner:
    """Render realistic command output from a structured runtime fixture."""

    def __init__(self, fixture: Mapping[str, object]) -> None:
        self.fixture = deepcopy(dict(fixture))
        self.side = str(self.fixture.get("side", "source"))
        self.commands: List[List[str]] = []

    def run(self, argv, evidence_id, sensitive_stdout=False):
        del sensitive_stdout
        values = [str(item) for item in argv]
        self.commands.append(values)
        stdout = self._stdout(values)
        return CommandEvidence(evidence_id, values, 0, stdout, "")

    def _domain(self, name: str) -> Mapping[str, object]:
        domains = self.fixture.get("domains", [])
        for domain in domains if isinstance(domains, list) else []:
            if isinstance(domain, Mapping) and domain.get("name") == name:
                return domain
        raise AssertionError(f"unexpected fixture domain: {name}")

    def _stdout(self, argv: List[str]) -> str:
        domains = self.fixture.get("domains", [])
        domain_rows = domains if isinstance(domains, list) else []
        if argv[-3:] == ["list", "--uuid", "--name"]:
            return "".join(
                f"{item['uuid']} {item['name']}\n"
                for item in domain_rows
                if isinstance(item, Mapping)
            )
        if len(argv) >= 2 and argv[-2] == "dominfo":
            domain = self._domain(argv[-1])
            return (
                f"Id: 7\nName: {domain['name']}\nUUID: {domain['uuid']}\n"
                f"State: {domain.get('state', 'running')}\n"
            )
        if len(argv) >= 3 and argv[-3] == "dumpxml":
            return self._domain_xml(self._domain(argv[-2]))
        if len(argv) >= 3 and argv[-3] == "domblklist":
            domain = self._domain(argv[-2])
            lines = [
                "Type Device Target Source",
                "---------------------------------------------",
            ]
            disks = domain.get("disks", [])
            for disk in disks if isinstance(disks, list) else []:
                if isinstance(disk, Mapping):
                    lines.append(
                        f"{disk.get('type', 'file')} {disk.get('device', 'disk')} "
                        f"{disk.get('target', '-')} {disk.get('source', '-')}"
                    )
            return "\n".join(lines) + "\n"
        if len(argv) >= 2 and argv[-2] == "domiflist":
            domain = self._domain(argv[-1])
            lines = [
                "Interface Type Source Model MAC",
                "-------------------------------------------------------",
            ]
            interfaces = domain.get("interfaces", [])
            for interface in interfaces if isinstance(interfaces, list) else []:
                if isinstance(interface, Mapping):
                    lines.append(
                        f"{interface.get('target', '-')} {interface.get('type', '-')} "
                        f"{interface.get('source', '-')} {interface.get('model', '-')} "
                        f"{interface.get('mac', '-')}"
                    )
            return "\n".join(lines) + "\n"
        if argv == ["ovs-vsctl", "--format=json", "list", "Interface"]:
            return self._ovs_json(self.fixture.get("ovs_interfaces", []))
        if argv == ["ovs-vsctl", "--format=json", "list", "Port"]:
            return self._ovs_json(self.fixture.get("ovs_ports", []))
        if argv == ["ovn-sbctl", "--format=json", "list", "Port_Binding"]:
            return self._ovs_json(self.fixture.get("ovn_bindings", []))
        if argv[-1:] == ["version"]:
            return str(self.fixture.get("virsh_version", ""))
        if argv[-1:] == ["domcapabilities"]:
            buses = self.fixture.get("target_disk_buses", [])
            root = ET.Element("domainCapabilities")
            devices = ET.SubElement(root, "devices")
            disk = ET.SubElement(devices, "disk", {"supported": "yes"})
            enum = ET.SubElement(disk, "enum", {"name": "bus"})
            for bus in buses if isinstance(buses, list) else []:
                ET.SubElement(enum, "value").text = str(bus)
            return ET.tostring(root, encoding="unicode")
        if argv[-2:] == ["-machine", "help"]:
            machines = self.fixture.get("target_machine_types", [])
            return "Supported machines are:\n" + "".join(
                f"{machine} fixture machine\n"
                for machine in machines if isinstance(machine, str)
            )
        raise AssertionError(f"unexpected fixture command: {argv}")

    @staticmethod
    def _ovs_value(value: object) -> object:
        if isinstance(value, Mapping):
            return ["map", [[key, item] for key, item in value.items()]]
        if isinstance(value, list):
            return ["set", value]
        return value

    def _ovs_json(self, rows: object) -> str:
        values = rows if isinstance(rows, list) else []
        headings = sorted(
            {
                str(key)
                for row in values if isinstance(row, Mapping)
                for key in row
            }
        )
        return json.dumps(
            {
                "headings": headings,
                "data": [
                    [self._ovs_value(row.get(key)) for key in headings]
                    for row in values if isinstance(row, Mapping)
                ],
            }
        )

    @staticmethod
    def _domain_xml(domain: Mapping[str, object]) -> str:
        root = ET.Element("domain", {"type": "kvm"})
        ET.SubElement(root, "name").text = str(domain["name"])
        ET.SubElement(root, "uuid").text = str(domain["uuid"])
        metadata = ET.SubElement(root, "metadata")
        instance = ET.SubElement(metadata, "instance")
        instance.set("uuid", str(domain["uuid"]))
        os_element = ET.SubElement(root, "os")
        type_element = ET.SubElement(
            os_element,
            "type",
            {"machine": str(domain.get("machine_type", ""))},
        )
        type_element.text = "hvm"
        devices = ET.SubElement(root, "devices")
        disks = domain.get("disks", [])
        for disk in disks if isinstance(disks, list) else []:
            if not isinstance(disk, Mapping):
                continue
            disk_element = ET.SubElement(
                devices,
                "disk",
                {
                    "type": str(disk.get("type", "file")),
                    "device": str(disk.get("device", "disk")),
                },
            )
            source_attribute = "dev" if disk.get("type") == "block" else "file"
            ET.SubElement(
                disk_element,
                "source",
                {source_attribute: str(disk.get("source", ""))},
            )
            ET.SubElement(
                disk_element,
                "target",
                {
                    "dev": str(disk.get("target", "")),
                    "bus": str(disk.get("bus", "")),
                },
            )
            if disk.get("serial"):
                ET.SubElement(disk_element, "serial").text = str(disk["serial"])
            for secret in domain.get("secrets", []):
                secret_element = ET.SubElement(disk_element, "secret", {"uuid": "secret-uuid"})
                secret_element.text = str(secret)
        interfaces = domain.get("interfaces", [])
        for interface in interfaces if isinstance(interfaces, list) else []:
            if not isinstance(interface, Mapping):
                continue
            item = ET.SubElement(devices, "interface", {"type": str(interface.get("type", "bridge"))})
            ET.SubElement(item, "mac", {"address": str(interface.get("mac", ""))})
            ET.SubElement(item, "source", {"bridge": str(interface.get("source", ""))})
            ET.SubElement(item, "target", {"dev": str(interface.get("target", ""))})
            ET.SubElement(item, "model", {"type": str(interface.get("model", "virtio"))})
        return ET.tostring(root, encoding="unicode")
