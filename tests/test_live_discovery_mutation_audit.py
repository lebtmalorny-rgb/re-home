import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PACKAGE = SCRIPTS / "live_discovery"
PLAYBOOK = ROOT / "playbooks/02b-discover-live-resource-graph.yml"
sys.path.insert(0, str(SCRIPTS))

from live_discovery.argv_policy import (  # noqa: E402
    validate_inventory_commands,
    validate_mysql_argv,
)
from live_discovery.runner import (  # noqa: E402
    MutationRejected,
    ReadOnlyRunner,
    classify_mutation,
)


ENTRYPOINTS = (
    SCRIPTS / "collect_live_control.py",
    SCRIPTS / "collect_live_runtime.py",
    SCRIPTS / "assemble_live_discovery.py",
)
TASK11_HELPERS = {
    "argv_policy.py",
    "capability_input.py",
    "probe_plan.py",
    "protected_input.py",
    "run_owner.py",
}
INVENTORIES = (ROOT / "inventory/hosts.yml", ROOT / "inventory/lab-os1-to-os2.yml")

_INCLUDE = re.compile(
    r"(?m)^\s*(?:ansible\.builtin\.)?(?:include_tasks|import_tasks|import_playbook):"
    r"\s*([^\s#]+)"
)
_INCLUDE_MODULE = re.compile(
    r"(?m)^\s*(?:ansible\.builtin\.)?(?:include_tasks|import_tasks|import_playbook):"
)
_MODULE = re.compile(
    r"^(\s*)(?:(?:[A-Za-z_][A-Za-z0-9_-]*\.)+)?"
    r"(command|shell|raw):(?:\s*(.*))?$"
)
_DYNAMIC_ARGV = re.compile(r"\blive_discovery_[a-z0-9_]*argv(?:_prefix)?\b")
_ALLOWED_DYNAMIC_ARGV = {
    "live_discovery_cinder_db_version_argv",
    "live_discovery_container_inspect_argv_prefix",
    "live_discovery_mysql_json_argv",
    "live_discovery_neutron_db_version_argv",
    "live_discovery_nova_api_db_version_argv",
    "live_discovery_nova_cell_db_version_argv",
    "live_discovery_source_virsh_argv",
    "live_discovery_target_qemu_argv",
    "live_discovery_target_virsh_argv",
}
_FORBIDDEN_COMMAND_PATTERNS = (
    re.compile(r"\bonline_data_migrations\b", re.IGNORECASE),
    re.compile(
        r"\b(?:INSERT\s+INTO|UPDATE\s+[A-Za-z`]|DELETE\s+FROM|REPLACE\s+INTO|"
        r"ALTER\s+TABLE|CREATE\s+(?:TABLE|DATABASE)|DROP\s+(?:TABLE|DATABASE)|"
        r"TRUNCATE\s+TABLE|GRANT\s+|REVOKE\s+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bopenstack\b[^\n]*(?:\bcreate\b|\bset\b|\bdelete\b|\bsave\b|"
        r"\bmap\b|\bmount\b|\bactivate\b|\block\b|\bunlock\b|\brestore\b|"
        r"\bmanage\b|\bextend\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:nova-manage|cinder-manage|neutron-db-manage)\b[^\n]*"
        r"(?:\bsync\b|\bmigrate\b|\bupgrade\b|\bstamp\b|\bdiscover_hosts\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:docker|systemctl|service)\b[^\n]*(?:\bstop\b|\brestart\b|"
        r"\bstart\b|\bkill\b|\bdisable\b|\benable\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bvirsh\b[^\n]*(?:\bdestroy\b|\bsave\b|\bmanagedsave\b|\bstart\b|"
        r"\bshutdown\b|\breboot\b|\bsuspend\b|\bresume\b|\bdefine\b|"
        r"\bundefine\b|\bmigrate\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\brbd\b[^\n]*(?:\bcreate\b|\brm\b|\bmap\b|\bunmap\b|\bmv\b|"
        r"\bimport\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:ovs-vsctl|ovs-ofctl|ovn-nbctl|ovn-sbctl)\b[^\n]*"
        r"(?:\bset\b|\bcreate\b|\bdestroy\b|\bclear\b|\bremove\b|"
        r"\badd-(?:br|port|flow)\b|\bdel-(?:br|port|flows?)\b|\bmod-flows?\b)",
        re.IGNORECASE,
    ),
)


def _production_python_paths():
    package_paths = sorted(PACKAGE.glob("*.py"))
    return [*package_paths, *ENTRYPOINTS]


def _import_aliases(tree):
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _call_name(call, aliases):
    value = call.func
    parts = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    if not parts:
        return ""
    parts.reverse()
    head = aliases.get(parts[0], parts[0])
    return ".".join([head, *parts[1:]])


def _expression_name(value, aliases):
    parts = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    if not parts:
        return ""
    parts.reverse()
    return ".".join([aliases.get(parts[0], parts[0]), *parts[1:]])


def _assert_python_source_safe(source, label, *, allow_subprocess):
    tree = ast.parse(source, filename=str(label))
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    aliases = _import_aliases(tree)
    imported_modules = {target.split(".", 1)[0] for target in aliases.values()}
    forbidden_imports = {"commands", "ctypes", "importlib", "multiprocessing", "pexpect", "pty", "runpy"}
    if imported_modules & forbidden_imports:
        raise AssertionError(f"alternate execution module imported by {label}")
    if not allow_subprocess and "subprocess" in imported_modules:
        raise AssertionError(f"subprocess imported outside runner: {label}")

    bypass_prefixes = (
        "os.exec", "os.fork", "os.popen", "os.posix_spawn", "os.spawn", "os.system",
        "posix.system", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
        "subprocess.check_output", "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell", "asyncio.subprocess.create_subprocess_exec",
        "asyncio.subprocess.create_subprocess_shell", "commands.getoutput",
        "commands.getstatusoutput", "pty.spawn",
    )
    dynamic_execution = {"eval", "exec", "compile", "__import__"}
    subprocess_calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        name = _expression_name(node, aliases)
        if name == "subprocess.run":
            parent = parents.get(node)
            if not isinstance(parent, ast.Call) or parent.func is not node:
                raise AssertionError(f"indirect subprocess.run in {label}:{node.lineno}")
        if name.startswith(("os.exec", "os.spawn", "os.posix_spawn", "os.fork")):
            raise AssertionError(f"indirect process API in {label}:{node.lineno}: {name}")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node, aliases)
        if name in dynamic_execution or name.startswith(bypass_prefixes):
            raise AssertionError(f"command execution bypass in {label}:{node.lineno}: {name}")
        if name == "getattr" and node.args:
            owner = _expression_name(node.args[0], aliases)
            attribute = (
                node.args[1].value
                if len(node.args) > 1
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                else ""
            )
            dangerous_attribute = (
                attribute in {"run", "Popen", "call", "check_call", "check_output", "system", "popen"}
                or attribute.startswith(("exec", "spawn", "posix_spawn", "create_subprocess"))
            )
            if owner.split(".", 1)[0] in {"asyncio", "os", "posix", "subprocess"} and dangerous_attribute:
                raise AssertionError(f"dynamic process API in {label}:{node.lineno}")
        if name == "vars" and node.args:
            owner = _expression_name(node.args[0], aliases)
            if owner.split(".", 1)[0] in {"asyncio", "os", "posix", "subprocess"}:
                raise AssertionError(f"dynamic process namespace in {label}:{node.lineno}")
        if name.startswith("subprocess."):
            if not allow_subprocess or name != "subprocess.run":
                raise AssertionError(f"subprocess bypass in {label}:{node.lineno}: {name}")
            subprocess_calls.append(node)
    return subprocess_calls


def _reachable_playbook_paths():
    playbooks_root = (ROOT / "playbooks").resolve()
    pending = [PLAYBOOK.resolve()]
    seen = set()
    while pending:
        owner = pending.pop()
        if owner in seen:
            continue
        seen.add(owner)
        text = owner.read_text(encoding="utf-8")
        includes = _INCLUDE.findall(text)
        if len(includes) != len(_INCLUDE_MODULE.findall(text)):
            raise AssertionError(f"non-scalar include cannot be audited: {owner}")
        if re.search(r"(?m)^\s*(?:ansible\.builtin\.)?(?:include_role|import_role):", text):
            raise AssertionError(f"role include cannot be audited: {owner}")
        for raw in includes:
            if "{{" in raw or "}}" in raw:
                raise AssertionError(f"dynamic include cannot be audited: {owner}: {raw}")
            candidate = (owner.parent / raw).resolve()
            if not candidate.is_file():
                candidate = (playbooks_root / raw).resolve()
            if not candidate.is_file() or playbooks_root not in candidate.parents:
                raise AssertionError(f"invalid reachable include: {owner}: {raw}")
            pending.append(candidate)
    return sorted(seen)


def _module_blocks_from_text(text):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = _MODULE.match(line)
        if match is None:
            continue
        indent = len(match.group(1))
        task_start = None
        task_indent = None
        for candidate_index in range(index, -1, -1):
            candidate = lines[candidate_index]
            task = re.match(r"^(\s*)-\s+(?:name:|(?:(?:[A-Za-z_][A-Za-z0-9_-]*\.)+)?(?:command|shell|raw):)", candidate)
            if task is not None and len(task.group(1)) < indent:
                task_start = candidate_index
                task_indent = len(task.group(1))
                break
        if task_start is None or indent != task_indent + 2:
            continue
        end = task_start + 1
        while end < len(lines):
            candidate = lines[end]
            if (
                end > task_start
                and candidate.strip()
                and re.match(rf"^\s{{{task_indent}}}-\s+", candidate)
            ):
                break
            end += 1
        yield match.group(2), match.group(3) or "", "\n".join(lines[task_start:end])


def _module_blocks(path):
    yield from _module_blocks_from_text(path.read_text(encoding="utf-8"))


def _static_argv(block):
    match = re.search(r"(?m)^[ \t]+argv:[ \t]*(.*)$", block)
    if match is None:
        return None
    value = match.group(1).strip()
    if value.startswith("[") and value.endswith("]"):
        tokens = [item.strip().strip("'\"") for item in value[1:-1].split(",")]
        return tokens if tokens and all(tokens) and not any("{{" in item for item in tokens) else None
    if value:
        return None
    lines = block[match.end():].splitlines()
    tokens = []
    for line in lines:
        item = re.match(r"^\s+-\s+(.+?)\s*$", line)
        if item is None:
            if tokens and line.strip():
                break
            continue
        token = item.group(1).strip().strip("'\"")
        if "{{" in token or not token:
            return None
        tokens.append(token)
    return tokens or None


def _argv_shape_is_reviewed(block):
    match = re.search(r"(?m)^[ \t]+argv:[ \t]*(.*)$", block)
    if match is None:
        return False
    value = match.group(1).strip().strip("'\"")
    if _static_argv(block):
        return True
    if "{{" not in block[match.start():]:
        return True
    if value.startswith("{{") or value in {">-", "|"}:
        dynamic = set(_DYNAMIC_ARGV.findall(block))
        if dynamic - _ALLOWED_DYNAMIC_ARGV:
            return False
        if "item.argv" in block:
            return all(name in block for name in (
                "live_discovery_nova_api_db_version_argv",
                "live_discovery_nova_cell_db_version_argv",
                "live_discovery_neutron_db_version_argv",
                "live_discovery_cinder_db_version_argv",
            ))
        if "['python3'" in block or '["python3"' in block:
            return True
        if dynamic:
            exact_suffixes = (
                "['version']", "['domcapabilities']", "['-machine', 'help']",
                "['--execute'", "[item]",
            )
            return any(suffix in block for suffix in exact_suffixes)
        return False
    first_item = re.search(r"(?m)^[ \t]+-\s+([^\n]+)$", block[match.end():])
    if first_item is None:
        return False
    executable = first_item.group(1).strip().strip("'\"")
    return "{{" not in executable and executable in {"python3", "mkdir", "/usr/bin/true"}


def _audit_command_text(text, label):
    command_count = 0
    dynamic_argv = set()
    for module, inline, block in _module_blocks_from_text(text):
        if module != "command":
            raise AssertionError(f"{label}: {module} bypasses argv audit")
        if inline.strip():
            raise AssertionError(f"{label}: free-form command is forbidden")
        if not _argv_shape_is_reviewed(block):
            raise AssertionError(f"{label}: argv shape is not reviewed")
        static = _static_argv(block)
        if static and static[0] in {
            "openstack", "nova-manage", "neutron-db-manage", "cinder-manage",
            "virsh", "ovs-vsctl", "ovs-ofctl", "ovn-nbctl", "ovn-sbctl",
            "rbd", "lvs", "stat", "docker", "qemu-system-x86_64",
        }:
            rejection = classify_mutation(static)
            if rejection is not None:
                raise AssertionError(f"{label}: mutating argv: {rejection}")
        normalized = re.sub(r"\s+", " ", block)
        for pattern in _FORBIDDEN_COMMAND_PATTERNS:
            if pattern.search(normalized):
                raise AssertionError(f"{label}: {pattern.pattern}")
        command_count += 1
        dynamic_argv.update(_DYNAMIC_ARGV.findall(block))
    return command_count, dynamic_argv


def _inventory_payload(path):
    executable = shutil.which("ansible-inventory")
    if executable is None:
        raise AssertionError("ansible-inventory is required for the mutation audit")
    with tempfile.TemporaryDirectory() as temporary:
        completed = subprocess.run(
            [executable, "-i", str(path), "--list"],
            cwd=ROOT,
            env={**os.environ, "ANSIBLE_LOCAL_TEMP": temporary},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return json.loads(completed.stdout)


def _concrete_mysql_argv(argv):
    concrete = []
    for value in argv:
        if "{{" not in value:
            concrete.append(value)
        elif value.startswith("MYSQL_PWD="):
            concrete.append("MYSQL_PWD=audit-secret")
        elif value.startswith("-u"):
            concrete.append("-uaudit")
        else:
            concrete.append("db.internal")
    return concrete


class LiveDiscoveryMutationAuditTests(unittest.TestCase):
    def test_ansible_audit_rejects_alternate_modules_templates_and_multiline_mutation(self):
        unsafe = (
            "---\n- name: bare\n  command:\n    argv:\n      - openstack\n      - server\n      - lock\n      - server-1\n",
            "---\n- name: legacy\n  ansible.legacy.shell: openstack server lock server-1\n",
            "---\n- name: fqcn\n  ansible.builtin.command:\n    argv: [openstack, server, lock, server-1]\n",
            "---\n- name: raw\n  ansible.builtin.raw: docker stop nova_compute\n",
            "---\n- name: template\n  ansible.builtin.command:\n    argv: \"{{ arbitrary_inventory_argv }}\"\n",
        )
        for source in unsafe:
            with self.subTest(source=source):
                with self.assertRaises(AssertionError):
                    _audit_command_text(source, "synthetic")

    def test_python_ast_audit_rejects_alias_getattr_spawn_exec_and_dynamic_import(self):
        unsafe = (
            ("import asyncio.subprocess as asp\nasp.create_subprocess_exec('id')\n", False),
            ("from asyncio.subprocess import create_subprocess_shell as launch\nlaunch('id')\n", False),
            ("import os\nos.spawnv(os.P_WAIT, '/bin/id', ['id'])\n", False),
            ("import os\nos.execve('/bin/id', ['id'], {})\n", False),
            ("import subprocess\ngetattr(subprocess, 'run')(['id'])\n", False),
            ("import os\ngetattr(os, 'system')('id')\n", False),
            ("import importlib\nimportlib.import_module('subprocess').run(['id'])\n", False),
            ("import multiprocessing\nmultiprocessing.Process(target=lambda: None).start()\n", False),
            ("import subprocess\nvars(subprocess)['run'](['id'])\n", True),
            ("import subprocess\nlaunch = subprocess.run\nlaunch(['id'])\n", True),
        )
        for source, allow_subprocess in unsafe:
            with self.subTest(source=source):
                with self.assertRaises(AssertionError):
                    _assert_python_source_safe(
                        source, "synthetic.py", allow_subprocess=allow_subprocess
                    )

    def test_python_command_execution_has_one_argv_only_boundary(self):
        paths = _production_python_paths()
        self.assertEqual(3, len(ENTRYPOINTS))
        self.assertTrue(TASK11_HELPERS.issubset({path.name for path in paths}))
        self.assertEqual(len(paths), len(set(paths)))

        runner_calls = []
        for path in paths:
            calls = _assert_python_source_safe(
                path.read_text(encoding="utf-8"),
                path,
                allow_subprocess=path == PACKAGE / "runner.py",
            )
            runner_calls.extend(calls)

        self.assertEqual(2, len(runner_calls))
        for call in runner_calls:
            keywords = {item.arg: item.value for item in call.keywords if item.arg}
            self.assertNotIn("shell", keywords)
            self.assertNotIn("executable", keywords)
            self.assertIsInstance(keywords.get("check"), ast.Constant)
            self.assertIs(False, keywords["check"].value)
            self.assertIsInstance(keywords.get("text"), ast.Constant)
            self.assertIs(True, keywords["text"].value)

    def test_reachable_playbook_command_graph_is_read_only(self):
        paths = _reachable_playbook_paths()
        self.assertEqual(8, len(paths), [str(path.relative_to(ROOT)) for path in paths])
        combined = []
        dynamic_argv = set()
        command_count = 0
        for path in paths:
            text = path.read_text(encoding="utf-8")
            combined.append(text)
            count, variables = _audit_command_text(text, path)
            command_count += count
            dynamic_argv.update(variables)

        self.assertGreaterEqual(command_count, 30)
        self.assertLessEqual(dynamic_argv, _ALLOWED_DYNAMIC_ARGV)
        source = "\n".join(combined)
        self.assertIn("--config-json", source)
        self.assertGreaterEqual(source.count("--mysql-json"), 2)
        self.assertNotRegex(source, r"(?m)^\s*(?:ansible\.builtin\.)?(?:shell|raw):")

    def test_generic_and_lab_inventory_argv_pass_exact_policy(self):
        for inventory in INVENTORIES:
            payload = _inventory_payload(inventory)
            hostvars = payload["_meta"]["hostvars"]
            self.assertTrue(hostvars, str(inventory))
            checked = set()
            for values in hostvars.values():
                fingerprint = json.dumps(
                    {
                        key: values[key]
                        for key in (
                            "live_discovery_nova_api_db_version_argv",
                            "live_discovery_nova_cell_db_version_argv",
                            "live_discovery_neutron_db_version_argv",
                            "live_discovery_cinder_db_version_argv",
                            "live_discovery_container_inspect_argv_prefix",
                            "live_discovery_source_virsh_argv",
                            "live_discovery_target_virsh_argv",
                            "live_discovery_target_qemu_argv",
                            "openstack_cli_container",
                            "live_discovery_mysql_json_argv",
                        )
                    },
                    sort_keys=True,
                )
                if fingerprint in checked:
                    continue
                checked.add(fingerprint)
                validate_inventory_commands(
                    {
                        "nova_api": values["live_discovery_nova_api_db_version_argv"],
                        "nova_cell": values["live_discovery_nova_cell_db_version_argv"],
                        "neutron": values["live_discovery_neutron_db_version_argv"],
                        "cinder": values["live_discovery_cinder_db_version_argv"],
                        "inspect": values["live_discovery_container_inspect_argv_prefix"],
                        "source_virsh": values["live_discovery_source_virsh_argv"],
                        "target_virsh": values["live_discovery_target_virsh_argv"],
                        "target_qemu": values["live_discovery_target_qemu_argv"],
                        "openstack_container": values["openstack_cli_container"],
                    }
                )
                validate_mysql_argv(
                    _concrete_mysql_argv(values["live_discovery_mysql_json_argv"])
                )
            self.assertTrue(checked, str(inventory))

    def test_runner_denies_every_external_mutation_class(self):
        commands = (
            ["openstack", "server", "create", "server-1"],
            ["openstack", "server", "set", "server-1"],
            ["openstack", "server", "delete", "server-1"],
            ["openstack", "image", "save", "image-1"],
            ["openstack", "server", "add", "network", "server-1", "network-1"],
            ["openstack", "server", "shelve", "server-1"],
            ["nova-manage", "db", "online_data_migrations"],
            ["nova-manage", "db", "sync"],
            ["cinder-manage", "db", "sync"],
            ["neutron-db-manage", "upgrade", "heads"],
            ["docker", "stop", "nova_compute"],
            ["docker", "exec", "ceph", "rbd", "map", "pool/volume-1"],
            ["rbd", "create", "pool/volume-1"],
            ["rbd", "unmap", "/dev/rbd0"],
            ["virsh", "destroy", "instance-1"],
            ["virsh", "managedsave", "instance-1"],
            ["virsh", "shutdown", "instance-1"],
            ["ovs-vsctl", "add-br", "br-test"],
            ["ovs-ofctl", "mod-flows", "br-int"],
            ["ovn-nbctl", "lsp-set-addresses", "port-1", "dynamic"],
            ["mount", "server:/volume", "/mnt/volume"],
        )
        runner = ReadOnlyRunner()
        with mock.patch("live_discovery.runner.subprocess.run") as execute:
            for command in commands:
                with self.subTest(command=command):
                    with self.assertRaises(MutationRejected):
                        runner.run(command, "mutation-audit")
            execute.assert_not_called()

    def test_runner_uses_contextual_read_only_grammars_not_a_blacklist(self):
        rejected = (
            ["rbd", "rm", "pool/volume-1"],
            ["rbd", "mv", "pool/volume-1", "pool/volume-2"],
            ["virsh", "undefine", "instance-1"],
            ["openstack", "server", "lock", "server-1"],
            ["openstack", "server", "unlock", "server-1"],
            ["openstack", "volume", "backup", "restore", "backup-1", "volume-1"],
            ["openstack", "volume", "snapshot", "manage", "host@backend#pool", "ref"],
            ["openstack", "volume", "extend", "volume-1", "20"],
            ["nova-manage", "cell_v2", "discover_hosts"],
            ["neutron-db-manage", "stamp", "heads"],
        )
        allowed = (
            ["rbd", "info", "--format", "json", "pool/archive"],
            ["virsh", "dominfo", "shutdown"],
            ["openstack", "server", "show", "archive"],
            ["openstack", "resource", "provider", "show", "set"],
        )
        runner = ReadOnlyRunner()
        completed = mock.Mock(returncode=0, stdout="{}", stderr="")
        with mock.patch(
            "live_discovery.runner.subprocess.run", return_value=completed
        ) as execute:
            for command in rejected:
                with self.subTest(rejected=command):
                    with self.assertRaises(MutationRejected):
                        runner.run(command, "contextual-reject")
            for command in allowed:
                with self.subTest(allowed=command):
                    runner.run(command, "contextual-allow")
        self.assertEqual(len(allowed), execute.call_count)

    def test_runner_contextual_grammar_preserves_every_live_probe_family(self):
        commands = (
            ["nova-manage", "api_db", "version"],
            ["nova-manage", "db", "version"],
            ["neutron-db-manage", "current", "--verbose"],
            ["cinder-manage", "db", "version"],
            ["virsh", "list", "--uuid", "--name"],
            ["virsh", "dominfo", "instance-1"],
            ["virsh", "dumpxml", "instance-1", "--security-info"],
            ["virsh", "domblklist", "instance-1", "--details"],
            ["virsh", "domiflist", "instance-1"],
            ["virsh", "version"],
            ["virsh", "domcapabilities"],
            ["ovs-vsctl", "--format=json", "list", "Interface"],
            ["ovs-vsctl", "--format=json", "list", "Port"],
            ["ovn-sbctl", "--format=json", "list", "Port_Binding"],
            ["rbd", "info", "--format", "json", "pool/volume-1"],
            ["lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "vg/lv"],
            ["stat", "--format", "%s", "/srv/volume-1"],
            ["qemu-system-x86_64", "-machine", "help"],
            ["openstack", "server", "list", "--all-projects", "--host", "compute-1"],
            ["openstack", "server", "show", "instance-1", "-f", "json"],
            ["openstack", "resource", "provider", "allocation", "show", "instance-1"],
            ["openstack", "port", "list", "--server", "instance-1"],
            ["openstack", "server", "volume", "list", "instance-1"],
            ["openstack", "network", "qos", "policy", "show", "policy-1"],
            ["openstack", "volume", "group", "snapshot", "show", "snapshot-1"],
            ["openstack", "image", "member", "list", "image-1"],
            ["openstack", "image", "stores", "info"],
            ["openstack", "catalog", "show", "glance"],
            ["docker", "exec", "nova_api", "nova-manage", "api_db", "version"],
            ["docker", "exec", "kolla_toolbox", "openstack", "--os-cloud", "source", "server", "show", "archive"],
        )
        completed = mock.Mock(returncode=0, stdout="{}", stderr="")
        with mock.patch(
            "live_discovery.runner.subprocess.run", return_value=completed
        ) as execute:
            for command in commands:
                with self.subTest(command=command):
                    ReadOnlyRunner().run(command, "read-only-probe")
        self.assertEqual(len(commands), execute.call_count)

    def test_runner_rejects_sql_dml_ddl_and_exfiltration(self):
        statements = (
            "INSERT INTO nova.instances (uuid) VALUES ('x');",
            "UPDATE nova.instances SET host = 'x';",
            "DELETE FROM nova.instances;",
            "REPLACE INTO nova.instances (uuid) VALUES ('x');",
            "ALTER TABLE nova.instances ADD COLUMN x INT;",
            "CREATE TABLE nova.audit (id INT);",
            "DROP TABLE nova.instances;",
            "TRUNCATE TABLE nova.instances;",
            "GRANT SELECT ON nova.* TO audit;",
            "REVOKE SELECT ON nova.* FROM audit;",
            "SELECT * FROM nova.instances INTO OUTFILE '/tmp/instances';",
        )
        runner = ReadOnlyRunner()
        with mock.patch("live_discovery.runner.subprocess.run") as execute:
            for statement in statements:
                with self.subTest(statement=statement):
                    with self.assertRaises(MutationRejected):
                        runner.run_sql(["mysql", "--batch"], statement, "sql-audit")
            execute.assert_not_called()

    def test_compound_mutation_words_in_read_only_resource_id_do_not_false_positive(self):
        runner = ReadOnlyRunner()
        completed = mock.Mock(returncode=0, stdout='{"size": 1}', stderr="")
        command = ["rbd", "info", "--format", "json", "pool/my-set-volume"]
        with mock.patch(
            "live_discovery.runner.subprocess.run", return_value=completed
        ) as execute:
            evidence = runner.run(command, "read-only-resource-name")
        self.assertEqual(0, evidence.returncode)
        execute.assert_called_once()

    def test_inventory_policy_rejects_mutating_suffixes_and_shell_syntax(self):
        valid = {
            "nova_api": ["nova-manage", "api_db", "version"],
            "nova_cell": ["nova-manage", "db", "version"],
            "neutron": ["neutron-db-manage", "current", "--verbose"],
            "cinder": ["cinder-manage", "db", "version"],
            "inspect": ["docker", "inspect"],
            "source_virsh": ["virsh"],
            "target_virsh": ["virsh"],
            "target_qemu": ["qemu-system-x86_64"],
            "openstack_container": "kolla_toolbox",
        }
        validate_inventory_commands(valid)
        mutations = (
            ("nova_api", ["nova-manage", "api_db", "sync"]),
            ("nova_cell", ["nova-manage", "db", "online_data_migrations"]),
            ("neutron", ["neutron-db-manage", "upgrade", "heads"]),
            ("cinder", ["cinder-manage", "db", "sync"]),
            ("inspect", ["docker", "stop"]),
            ("source_virsh", ["virsh", "destroy"]),
            ("target_virsh", ["virsh", "managedsave"]),
            ("target_qemu", ["qemu-system-x86_64", "-machine", "help;reboot"]),
            ("openstack_container", "kolla_toolbox;docker stop nova_compute"),
        )
        for key, value in mutations:
            candidate = dict(valid)
            candidate[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    validate_inventory_commands(candidate)
        for argv in (
            ["mysql", "--batch", "--raw", "--skip-column-names", "--execute", "DELETE FROM nova.instances"],
            ["docker", "exec", "mariadb", "mysql", "--execute", "DROP TABLE nova.instances"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    validate_mysql_argv(argv)

    def test_no_masakari_or_drs_runtime_surface_exists(self):
        forbidden = re.compile(r"(?:^|[^a-z0-9_])(?:masakari|drs)(?:$|[^a-z0-9_])", re.IGNORECASE)
        for path in _production_python_paths():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self.assertIsNone(forbidden.search(ast.unparse(node)), str(path))
                elif isinstance(node, ast.Call):
                    name = _call_name(node, _import_aliases(tree))
                    if name.endswith("CollectorResult"):
                        for keyword in node.keywords:
                            if (
                                keyword.arg == "service"
                                and isinstance(keyword.value, ast.Constant)
                                and isinstance(keyword.value.value, str)
                            ):
                                self.assertIsNone(
                                    forbidden.search(keyword.value.value),
                                    f"{path}:{node.lineno}",
                                )
        for path in _reachable_playbook_paths():
            self.assertIsNone(forbidden.search(path.read_text(encoding="utf-8")), str(path))


if __name__ == "__main__":
    unittest.main()
