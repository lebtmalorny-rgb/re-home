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
from live_discovery.runner import MutationRejected, ReadOnlyRunner  # noqa: E402


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
    r"^(\s*)ansible\.builtin\.(command|shell|raw):(?:\s*(.*))?$"
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
        r"\bmap\b|\bmount\b|\bactivate\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:nova-manage|cinder-manage|neutron-db-manage)\b[^\n]*"
        r"(?:\bsync\b|\bmigrate\b|\bupgrade\b)",
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


def _module_blocks(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        match = _MODULE.match(line)
        if match is None:
            continue
        indent = len(match.group(1))
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                break
            end += 1
        yield match.group(2), match.group(3) or "", "\n".join(lines[index:end])


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
    def test_python_command_execution_has_one_argv_only_boundary(self):
        paths = _production_python_paths()
        self.assertEqual(3, len(ENTRYPOINTS))
        self.assertTrue(TASK11_HELPERS.issubset({path.name for path in paths}))
        self.assertEqual(len(paths), len(set(paths)))

        bypass_prefixes = (
            "os.system", "os.popen", "posix.system", "subprocess.Popen",
            "subprocess.call", "subprocess.check_call", "subprocess.check_output",
            "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
            "commands.getoutput", "commands.getstatusoutput", "pty.spawn",
        )
        dynamic_execution = {"eval", "exec", "compile", "__import__", "runpy.run_path"}
        runner_calls = []
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            aliases = _import_aliases(tree)
            imported_modules = {
                target.split(".", 1)[0]
                for target in aliases.values()
            }
            if path == PACKAGE / "runner.py":
                self.assertIn("subprocess", imported_modules)
            else:
                self.assertNotIn("subprocess", imported_modules, str(path))
            self.assertFalse(
                imported_modules & {"commands", "pexpect", "pty"},
                f"alternate command-execution module imported by {path}",
            )
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _call_name(node, aliases)
                self.assertNotIn(name, dynamic_execution, f"{path}:{node.lineno}")
                self.assertFalse(
                    name.startswith(bypass_prefixes),
                    f"command execution bypass in {path}:{node.lineno}: {name}",
                )
                if name.startswith("subprocess."):
                    self.assertEqual(PACKAGE / "runner.py", path, f"{path}:{node.lineno}")
                    self.assertEqual("subprocess.run", name, f"{path}:{node.lineno}")
                    runner_calls.append(node)

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
            for module, inline, block in _module_blocks(path):
                self.assertEqual("command", module, f"{path}: {module} bypasses argv audit")
                self.assertEqual("", inline.strip(), f"{path}: free-form command is forbidden")
                self.assertRegex(block, r"(?m)^\s+argv:")
                command_count += 1
                dynamic_argv.update(_DYNAMIC_ARGV.findall(block))
                for pattern in _FORBIDDEN_COMMAND_PATTERNS:
                    self.assertIsNone(pattern.search(block), f"{path}: {pattern.pattern}")

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
