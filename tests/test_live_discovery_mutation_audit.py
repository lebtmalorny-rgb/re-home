import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
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
_TRUSTED_PYTHON_PATHS = {
    "{{ playbook_dir }}/../scripts/assemble_live_discovery.py",
    "{{ playbook_dir }}/../scripts/validate_live_runtime.py",
    "{{ playbook_dir }}/../scripts/live_discovery/argv_policy.py",
    "{{ playbook_dir }}/../scripts/live_discovery/probe_plan.py",
    "{{ playbook_dir }}/../scripts/live_discovery/protected_input.py",
    "{{ playbook_dir }}/../scripts/live_discovery/run_owner.py",
    "{{ live_discovery_side_remote_dir }}/scripts/collect_live_control.py",
    "{{ live_discovery_source_probe_dir }}/scripts/collect_live_control.py",
    "{{ live_discovery_target_probe_dir }}/scripts/collect_live_control.py",
}
_TRUSTED_WHOLE_SOURCE_SHA256 = {
    "e3d702108207f5c6217e3d4f89338f733f5856b4467c39dc85dd0396a9d54a04",  # orchestrator
    "e841188b95cfd71b9a58d15b157726b84f91b92685408d3da1da728259be1194",  # DB JSONL
    "32e7bdfcc23377182771a0b7928003773749410d8283e686d6bf26cc28c69305",  # runtime
    "a3e93469ff29e1fa95cf0a805d7519d6afb1a804351e327094eaf5f036212021",  # schema
    "5214db099f4f003b5215ea3d75843e7558fa5579d94770c4b3c851e3cd8e5528",  # capability
    "57e80b3a8b9879555a86c5416d3dc2837e47cbfddf8fef3f28c808b1db0935b3",  # initialization
}
_TRUSTED_FILE_TASK_SET_SHA256 = {
    "5d283b6b3bfe167cd712ecc43d8fbaad36ac6795d48e10b71206c5899e264865",
    "db63529b32fee1260c32030104243969d7b7c7108fa704ffb9e71ef6f249f7cc",
    "aa120867c81335fb45d3b291f0b8ca2a2e766d3cb885ce4246c0aadc2487a3df",
    "476b1831cf8c9f5b5ba10af09552845fe1abfbe1bbf7ade7571649ed4aa5320c",
    "3da83260df7c9bccb1cf9086b88175b07e8f35f4faf28aebc92113010c47c0dd",
    "0125ee4396c60b7bdb886bcaacdcdfa4e5a64069ac51e645b4722b0f72570bc7",
}
_SAFE_PROCESS_ATTRIBUTES = {
    "os.O_CREAT", "os.O_EXCL", "os.O_NOFOLLOW", "os.O_RDONLY", "os.O_WRONLY",
    "os.chmod", "os.close", "os.environ", "os.environ.get", "os.fdopen",
    "os.fstat", "os.fsync", "os.geteuid", "os.getpid", "os.open", "os.read",
    "os.replace", "os.urandom", "subprocess.PIPE", "subprocess.run",
    "sys.path", "sys.path.insert", "sys.stderr", "sys.stdin", "sys.stdin.read",
}


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


def _assigned_names(target):
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.List, ast.Tuple)):
        return {
            name
            for child in target.elts
            for name in _assigned_names(child)
        }
    return set()


def _is_process_module_object(value, aliases, tainted_names):
    if isinstance(value, ast.Name):
        resolved = aliases.get(value.id, value.id)
        return value.id in tainted_names or resolved in {
            "asyncio", "os", "posix", "subprocess", "sys",
        }
    if isinstance(value, ast.IfExp):
        return _is_process_module_object(value.body, aliases, tainted_names) or (
            _is_process_module_object(value.orelse, aliases, tainted_names)
        )
    if isinstance(value, (ast.List, ast.Set, ast.Tuple)):
        return any(
            _is_process_module_object(child, aliases, tainted_names)
            for child in value.elts
        )
    if isinstance(value, ast.Subscript):
        owner = _expression_name(value.value, aliases)
        key = value.slice.value if isinstance(value.slice, ast.Constant) else None
        return owner == "sys.modules" and key in {
            "asyncio", "os", "posix", "subprocess",
        }
    return False


def _assert_python_source_safe(source, label, *, allow_subprocess):
    tree = ast.parse(source, filename=str(label))
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    aliases = _import_aliases(tree)
    imported_modules = {target.split(".", 1)[0] for target in aliases.values()}
    forbidden_imports = {
        "builtins", "commands", "ctypes", "importlib", "multiprocessing",
        "pexpect", "pty", "runpy",
    }
    if imported_modules & forbidden_imports:
        raise AssertionError(f"alternate execution module imported by {label}")
    if not allow_subprocess and "subprocess" in imported_modules:
        raise AssertionError(f"subprocess imported outside runner: {label}")

    process_modules = {"asyncio", "os", "posix", "subprocess", "sys"}
    tainted_names = {
        name for name, target in aliases.items()
        if target.split(".", 1)[0] in process_modules
    }
    assignments = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assignments.append((node, targets, value))
    changed = True
    while changed:
        changed = False
        for _, targets, value in assignments:
            if not _is_process_module_object(value, aliases, tainted_names):
                continue
            for target in targets:
                new_names = _assigned_names(target) - tainted_names
                if new_names:
                    tainted_names.update(new_names)
                    changed = True
    for node, _, value in assignments:
        if _is_process_module_object(value, aliases, tainted_names):
            raise AssertionError(f"process module alias in {label}:{node.lineno}")
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef, ast.Lambda)):
            defaults = [*node.args.defaults, *node.args.kw_defaults]
            if any(
                default is not None
                and _is_process_module_object(default, aliases, tainted_names)
                for default in defaults
            ):
                raise AssertionError(f"process module default in {label}:{node.lineno}")

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
    def dangerous_reference(name):
        return (
            name in {
                "os.system", "os.popen", "subprocess.run", "subprocess.Popen",
                "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
                "asyncio.subprocess.create_subprocess_exec",
                "asyncio.subprocess.create_subprocess_shell", "posix.system", "pty.spawn",
            }
            or name.startswith(("os.exec", "os.spawn", "os.posix_spawn", "os.fork"))
        )
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            name = _expression_name(node, aliases)
            if name in {
                "asyncio.__dict__", "os.__dict__", "posix.__dict__", "subprocess.__dict__",
            }:
                raise AssertionError(f"process namespace reference in {label}:{node.lineno}")
            if name == "sys.modules":
                raise AssertionError(f"dynamic module registry in {label}:{node.lineno}")
            if name.split(".", 1)[0] in process_modules and name not in _SAFE_PROCESS_ATTRIBUTES:
                raise AssertionError(f"unreviewed process attribute in {label}:{node.lineno}: {name}")
            if dangerous_reference(name):
                parent = parents.get(node)
                direct_runner_call = (
                    allow_subprocess
                    and name == "subprocess.run"
                    and isinstance(parent, ast.Call)
                    and parent.func is node
                )
                if not direct_runner_call:
                    raise AssertionError(f"process API reference in {label}:{node.lineno}: {name}")
        elif isinstance(node, ast.Subscript):
            owner = _expression_name(node.value, aliases)
            if owner in {"asyncio.__dict__", "os.__dict__", "posix.__dict__", "subprocess.__dict__"}:
                raise AssertionError(f"dynamic process namespace in {label}:{node.lineno}")
            if owner == "sys.modules":
                raise AssertionError(f"dynamic module registry in {label}:{node.lineno}")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id == "__builtins__":
                raise AssertionError(f"dynamic builtins registry in {label}:{node.lineno}")
            if node.id in {"__import__", "compile", "eval", "exec", "getattr", "vars"}:
                parent = parents.get(node)
                if not isinstance(parent, ast.Call) or parent.func is not node:
                    raise AssertionError(
                        f"dynamic lookup reference in {label}:{node.lineno}: {node.id}"
                    )
            parent = parents.get(node)
            target = aliases.get(node.id, "")
            resolved = target or node.id
            reviewed_optional_flag = (
                resolved == "os"
                and isinstance(parent, ast.Call)
                and parent.args[0] is node
                and (
                    (
                        _call_name(parent, aliases) == "getattr"
                        and len(parent.args) == 3
                        and isinstance(parent.args[1], ast.Constant)
                        and parent.args[1].value == "O_NOFOLLOW"
                        and isinstance(parent.args[2], ast.Constant)
                        and parent.args[2].value == 0
                    )
                    or (
                        _call_name(parent, aliases) == "hasattr"
                        and len(parent.args) == 2
                        and isinstance(parent.args[1], ast.Constant)
                        and parent.args[1].value in {"O_NOFOLLOW", "geteuid"}
                    )
                )
            )
            if resolved in process_modules and (
                not isinstance(parent, ast.Attribute) or parent.value is not node
            ) and not reviewed_optional_flag:
                raise AssertionError(f"process module object in {label}:{node.lineno}")
            if target.split(".", 1)[0] in process_modules and target not in process_modules:
                raise AssertionError(f"process API import alias in {label}:{node.lineno}: {target}")
            if dangerous_reference(target):
                raise AssertionError(f"process API alias reference in {label}:{node.lineno}")
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
            if owner.split(".", 1)[0] in {"asyncio", "os", "posix", "subprocess"} and (
                dangerous_attribute or not attribute
            ):
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


def _yaml_python():
    executable = shutil.which("ansible-playbook")
    if executable is None:
        raise AssertionError("ansible-playbook runtime is required for structural YAML audit")
    lines = Path(executable).read_text(encoding="utf-8").splitlines()
    first_line = lines[0] if lines else ""
    if not first_line.startswith("#!"):
        raise AssertionError("ansible-playbook shebang is invalid")
    try:
        shebang = shlex.split(first_line[2:])
    except ValueError as error:
        raise AssertionError("ansible-playbook shebang is invalid") from error
    if not shebang:
        raise AssertionError("ansible-playbook shebang is invalid")
    interpreter, *arguments = shebang
    if Path(interpreter).name == "env":
        if arguments[:1] in (["-S"], ["--split-string"]):
            arguments = arguments[1:]
        elif arguments and arguments[0].startswith("--split-string="):
            split_value = arguments.pop(0).split("=", 1)[1]
            arguments = [*shlex.split(split_value), *arguments]
        elif arguments and arguments[0].startswith("-"):
            raise AssertionError("unsupported ansible-playbook env options")
        if not arguments or "=" in arguments[0]:
            raise AssertionError("unsupported ansible-playbook env command")
        command, *arguments = arguments
        interpreter = shutil.which(command)
        if interpreter is None:
            raise AssertionError("Ansible Python runtime is unavailable")
    path = Path(interpreter)
    if "python" not in path.name.lower() or not path.is_file():
        raise AssertionError("unsupported ansible-playbook shebang")
    if any(argument not in {"-B", "-E", "-I", "-P", "-S", "-s", "-u"} for argument in arguments):
        raise AssertionError("unsupported ansible-playbook Python options")
    return [str(path), *arguments]


def _yaml_load(text, label):
    program = (
        "import json,sys,yaml; "
        "payload=yaml.safe_load(sys.stdin.read()); "
        "json.dump(payload,sys.stdout,ensure_ascii=False)"
    )
    completed = subprocess.run(
        [*_yaml_python(), "-c", program],
        input=text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"YAML parse failed for {label}: {completed.stderr}")
    return json.loads(completed.stdout)


def _key_base(key):
    return key.rsplit(".", 1)[-1] if isinstance(key, str) else ""


def _walk_mappings(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def _include_paths(payload, owner):
    paths = []
    for mapping in _walk_mappings(payload):
        for key, value in mapping.items():
            base = _key_base(key)
            if base in {"role", "roles"}:
                raise AssertionError(f"role execution is forbidden in {owner}: {key}")
            execution_family = (
                base in {"action", "include", "import", "local_action"}
                or base.startswith(("include_", "import_"))
            )
            if not execution_family:
                continue
            if base not in {"include_tasks", "import_tasks", "import_playbook"}:
                raise AssertionError(f"unknown include/action/role form in {owner}: {key}")
            if isinstance(value, dict):
                if set(value) != {"file"}:
                    raise AssertionError(f"unreviewed include mapping in {owner}: {key}")
                value = value["file"]
            if not isinstance(value, str) or not value or "{{" in value or "}}" in value:
                raise AssertionError(f"dynamic include cannot be audited: {owner}: {value}")
            paths.append(value)
    return paths


def _reachable_playbook_paths(entry=PLAYBOOK):
    entry = Path(entry).resolve()
    playbooks_root = (ROOT / "playbooks").resolve()
    pending = [entry]
    seen = set()
    while pending:
        owner = pending.pop()
        if owner in seen:
            continue
        seen.add(owner)
        text = owner.read_text(encoding="utf-8")
        payload = _yaml_load(text, owner)
        for raw in _include_paths(payload, owner):
            candidate = (owner.parent / raw).resolve()
            if not candidate.is_file():
                candidate = (playbooks_root / raw).resolve()
            allowed_root = owner.parent if playbooks_root not in owner.parents else playbooks_root
            if not candidate.is_file() or (
                allowed_root != candidate.parent and allowed_root not in candidate.parents
            ):
                raise AssertionError(f"invalid reachable include: {owner}: {raw}")
            pending.append(candidate)
    return sorted(seen)


_TASK_LIST_KEYS = {"always", "block", "handlers", "post_tasks", "pre_tasks", "rescue", "tasks"}
_TASK_META_KEYS = {
    "always", "block", "changed_when", "delegate_facts", "delegate_to",
    "environment", "failed_when", "loop", "loop_control", "name", "no_log",
    "register", "rescue", "run_once", "vars", "when",
}
_ALLOWED_MODULES = {
    "assert", "command", "copy", "debug", "fail", "fetch", "file",
    "include_tasks", "set_fact", "slurp", "stat",
}
_FILE_MODULES = {"copy", "fetch", "file", "slurp", "stat"}
_LOOKUP_START = re.compile(r"\b(?:lookup|q|query)\s*\(")
_LOOKUP_CALL = re.compile(
    r"\b(?P<function>lookup|q|query)\s*\(\s*"
    r"(?P<quote>['\"])(?P<family>[^'\"]+)(?P=quote)\s*,\s*"
    r"(?P<argument>.*?)\s*\)",
    re.DOTALL,
)
_SAFE_FILE_LOOKUP_ARGUMENTS = {
    "live_discovery_kolla_passwords_file_local",
    "live_discovery_frozen_protected_paths['source-probe-config.json']",
    "live_discovery_frozen_protected_paths['target-probe-config.json']",
    "hostvars['localhost'].live_discovery_source_kolla_passwords_file_local",
    "hostvars['localhost'].live_discovery_target_kolla_passwords_file_local",
    "live_discovery_source_glance_token_file_local",
    "live_discovery_target_glance_token_file_local",
}
_SAFE_PASSWORD_LOOKUP_ARGUMENTS = {
    "'/dev/null length=16 chars=ascii_lowercase,digits'",
    "'/dev/null length=32 chars=ascii_lowercase,digits'",
    '"/dev/null length=16 chars=ascii_lowercase,digits"',
    '"/dev/null length=32 chars=ascii_lowercase,digits"',
}
_SAFE_DISCOVERY_PATH_ROOTS = {
    "live_discovery_compute_remote_dir",
    "live_discovery_frozen_protected_dir",
    "live_discovery_frozen_protected_paths",
    "live_discovery_local_dir",
    "live_discovery_local_run_dir",
    "live_discovery_run_control_dir",
    "live_discovery_side_remote_dir",
    "live_discovery_source_controller_dir",
    "live_discovery_source_probe_dir",
    "live_discovery_target_controller_dir",
    "live_discovery_target_probe_dir",
}


def _iter_task_mappings(payload, *, task_file=False):
    if not isinstance(payload, list):
        raise AssertionError("Ansible document must be a list")
    for item in payload:
        if not isinstance(item, dict):
            raise AssertionError("Ansible play/task item must be a mapping")
        is_play = not task_file and (
            "hosts" in item
            or any(_key_base(key) == "import_playbook" for key in item)
        )
        if is_play:
            for key, value in item.items():
                if _key_base(key) in _TASK_LIST_KEYS:
                    yield from _iter_task_mappings(value, task_file=True)
            continue
        yield item
        for key, value in item.items():
            if _key_base(key) in {"always", "block", "rescue"}:
                yield from _iter_task_mappings(value, task_file=True)


def _valid_item_argv(task):
    expected = [
        {"name": "nova-api-db", "argv": "{{ live_discovery_nova_api_db_version_argv }}"},
        {"name": "nova-cell-db", "argv": "{{ live_discovery_nova_cell_db_version_argv }}"},
        {"name": "neutron-db", "argv": "{{ live_discovery_neutron_db_version_argv }}"},
        {"name": "cinder-db", "argv": "{{ live_discovery_cinder_db_version_argv }}"},
    ]
    return task.get("loop") == expected


def _audit_python_argv(argv):
    if len(argv) < 2 or argv[0] != "python3":
        return False
    if argv[1] == "-m":
        exact_source_helpers = (
            [
                "python3", "-m", "live_discovery.source_profile",
                "--records-stdin", "--out",
                "{{ live_discovery_side_remote_dir }}/protected/source-capability-input.json",
            ],
            [
                "python3", "-m", "live_discovery.cell_mapping", "query",
                "--host", "{{ rehome_host }}",
            ],
            [
                "python3", "-m", "live_discovery.cell_mapping", "normalize",
                "--host", "{{ rehome_host }}", "--out",
                "{{ live_discovery_side_remote_dir }}/protected/source-cell-mapping.json",
            ],
        )
        if len(argv) >= 3 and argv[2] in {
            "live_discovery.source_profile", "live_discovery.cell_mapping",
        }:
            return argv in exact_source_helpers
        return len(argv) >= 3 and argv[2] in {
            "live_discovery.argv_policy", "live_discovery.mysql_json",
            "live_discovery.schema_query",
        }
    return argv[1] in _TRUSTED_PYTHON_PATHS


def _source_digest(payload, label):
    try:
        source = Path(label).resolve(strict=False)
        relative = source.relative_to(ROOT.resolve())
    except (OSError, TypeError, ValueError):
        return None
    canonical = json.dumps(
        [str(relative), payload],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _audit_argv(argv, task, label, source_digest):
    if isinstance(argv, str):
        if source_digest not in _TRUSTED_WHOLE_SOURCE_SHA256:
            raise AssertionError(f"{label}: whole-expression source is not exact-reviewed")
        normalized = " ".join(argv.split())
        if normalized == "{{ item.argv }}" and not _valid_item_argv(task):
            raise AssertionError(f"{label}: item.argv loop is not exact-reviewed")
        return set(_DYNAMIC_ARGV.findall(argv))
    if not isinstance(argv, list) or not argv or not all(
        isinstance(value, str) and value for value in argv
    ):
        raise AssertionError(f"{label}: argv must be a non-empty string list")
    if "{{" in argv[0] or "}}" in argv[0]:
        raise AssertionError(f"{label}: dynamic executable is forbidden")
    if argv[0] == "python3":
        if not _audit_python_argv(argv):
            raise AssertionError(f"{label}: Python entrypoint is not exact-reviewed")
    elif argv[0] == "mkdir":
        if argv != ["mkdir", "--", "{{ live_discovery_local_run_dir }}"]:
            raise AssertionError(f"{label}: mkdir argv is not exact-reviewed")
    elif argv == ["/usr/bin/true"]:
        pass
    elif any("{{" in value or "}}" in value for value in argv):
        raise AssertionError(f"{label}: templated external argv is forbidden")
    else:
        rejection = classify_mutation(argv)
        if rejection is not None:
            raise AssertionError(f"{label}: external argv rejected: {rejection}")
    return set(_DYNAMIC_ARGV.findall(" ".join(argv)))


def _audit_lookups(task, label):
    text = json.dumps(task, ensure_ascii=False)
    starts = list(_LOOKUP_START.finditer(text))
    calls = list(_LOOKUP_CALL.finditer(text))
    if len(starts) != len(calls):
        raise AssertionError(f"{label}: lookup call shape is not exact-reviewed")
    for call in calls:
        if call.group("function") != "lookup":
            raise AssertionError(f"{label}: lookup function is not exact-reviewed")
        family = call.group("family")
        argument = call.group("argument").strip()
        if family == "file" and argument in _SAFE_FILE_LOOKUP_ARGUMENTS:
            continue
        if family == "password" and argument in _SAFE_PASSWORD_LOOKUP_ARGUMENTS:
            continue
        raise AssertionError(f"{label}: lookup family or argument is not exact-reviewed: {family}")


def _direct_discovery_path(value):
    if not isinstance(value, str) or not value:
        return False
    normalized = value.strip()
    return (
        normalized.startswith("{{")
        and "}}" in normalized
        and "\\" not in normalized
        and ".." not in normalized.split("/")
        and any(root in normalized for root in _SAFE_DISCOVERY_PATH_ROOTS)
    )


def _item_paths_are_discovery_scoped(task, field):
    loop = task.get("loop")
    if not isinstance(loop, list) or not loop:
        return False
    for item in loop:
        value = item.get(field) if isinstance(item, dict) else item
        if not _direct_discovery_path(value):
            return False
    return True


def _discovery_path(value, task, *, item_field=None):
    if not isinstance(value, str) or not value:
        return False
    if _direct_discovery_path(value):
        return True
    if value in {"{{ item }}", "{{ item.path }}"}:
        return _item_paths_are_discovery_scoped(task, item_field or "path")
    return False


def _audit_safe_module(
    module, module_args, task, label, file_task_set_digest, source_digest
):
    if module in {"assert", "debug", "fail", "include_tasks", "set_fact"}:
        return
    if module in _FILE_MODULES and (
        file_task_set_digest not in _TRUSTED_FILE_TASK_SET_SHA256
        or source_digest not in _TRUSTED_WHOLE_SOURCE_SHA256
    ):
        raise AssertionError(f"{label}: file task set is not exact-reviewed")
    if not isinstance(module_args, dict):
        raise AssertionError(f"{label}: {module} arguments must be a mapping")
    if module == "file":
        if set(module_args) - {"mode", "path", "state"}:
            raise AssertionError(f"{label}: file arguments are not reviewed")
        if module_args.get("state") not in {"absent", "directory"}:
            raise AssertionError(f"{label}: file state is not reviewed")
        if not _discovery_path(module_args.get("path"), task):
            raise AssertionError(f"{label}: file path escapes discovery scope")
        return
    if module == "copy":
        if set(module_args) - {"content", "dest", "mode", "src"}:
            raise AssertionError(f"{label}: copy arguments are not reviewed")
        if not _discovery_path(module_args.get("dest"), task, item_field="dest"):
            raise AssertionError(f"{label}: copy destination escapes discovery scope")
        if set(module_args) & {"content", "src"} == set():
            raise AssertionError(f"{label}: copy requires one reviewed source")
        if set(module_args) >= {"content", "src"}:
            raise AssertionError(f"{label}: copy source shape is not reviewed")
        return
    if module == "fetch":
        if set(module_args) != {"dest", "flat", "src"} or module_args["flat"] is not True:
            raise AssertionError(f"{label}: fetch arguments are not reviewed")
        if not _discovery_path(module_args["src"], task) or not _discovery_path(
            module_args["dest"], task
        ):
            raise AssertionError(f"{label}: fetch path escapes discovery scope")
        return
    if module == "slurp":
        if set(module_args) != {"src"} or not _discovery_path(module_args["src"], task):
            raise AssertionError(f"{label}: slurp path escapes discovery scope")
        return
    if module == "stat":
        if set(module_args) - {"checksum_algorithm", "path"}:
            raise AssertionError(f"{label}: stat arguments are not reviewed")
        if not _discovery_path(module_args.get("path"), task):
            raise AssertionError(f"{label}: stat path escapes discovery scope")
        return
    raise AssertionError(f"{label}: unreviewed module: {module}")


def _audit_command_text(text, label):
    payload = _yaml_load(text, label)
    source_digest = _source_digest(payload, label)
    task_file = not any(
        isinstance(item, dict) and (
            "hosts" in item or any(_key_base(key) == "import_playbook" for key in item)
        )
        for item in payload if isinstance(item, dict)
    ) if isinstance(payload, list) else True
    tasks = list(_iter_task_mappings(payload, task_file=task_file))
    file_tasks = [
        task for task in tasks
        if any(_key_base(key) in _FILE_MODULES for key in task)
    ]
    file_task_set_digest = _source_digest(file_tasks, label)
    command_count = 0
    dynamic_argv = set()
    for task in tasks:
        _audit_lookups(task, label)
        actions = [
            (key, value) for key, value in task.items()
            if _key_base(key) not in _TASK_META_KEYS
        ]
        if not actions:
            continue
        if len(actions) != 1:
            raise AssertionError(f"{label}: multiple or unknown modules in one task")
        key, module_args = actions[0]
        module = _key_base(key)
        if module not in _ALLOWED_MODULES:
            raise AssertionError(f"{label}: {module} module is not exact-reviewed")
        prefix = key[: -(len(module) + 1)] if key != module else ""
        if prefix not in {"", "ansible.builtin", "ansible.legacy"} and module != "include_tasks":
            raise AssertionError(f"{label}: custom module collection is forbidden: {key}")
        if module != "command":
            _audit_safe_module(
                module, module_args, task, label, file_task_set_digest, source_digest
            )
            continue
        if not isinstance(module_args, dict) or set(module_args) - {
            "argv", "chdir", "stdin", "stdin_add_newline",
        } or "argv" not in module_args:
            raise AssertionError(f"{label}: command must use reviewed argv mapping")
        variables = _audit_argv(module_args["argv"], task, label, source_digest)
        dynamic_argv.update(variables)
        command_count += 1
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
    def test_source_profile_and_cell_mapping_argv_shapes_are_exact_bound(self):
        exact = (
            [
                "python3", "-m", "live_discovery.source_profile",
                "--records-stdin", "--out",
                "{{ live_discovery_side_remote_dir }}/protected/source-capability-input.json",
            ],
            [
                "python3", "-m", "live_discovery.cell_mapping", "query",
                "--host", "{{ rehome_host }}",
            ],
            [
                "python3", "-m", "live_discovery.cell_mapping", "normalize",
                "--host", "{{ rehome_host }}", "--out",
                "{{ live_discovery_side_remote_dir }}/protected/source-cell-mapping.json",
            ],
        )
        for argv in exact:
            self.assertTrue(_audit_python_argv(argv), argv)
        for argv in (
            [*exact[0][:-1], "/etc/nova/nova.conf"],
            [*exact[1], "--execute", "DROP TABLE nova.instances"],
            [*exact[2][:-1], "{{ arbitrary_path }}"],
            ["python3", "-m", "live_discovery.cell_mapping", "delete"],
        ):
            self.assertFalse(_audit_python_argv(argv), argv)

    def test_structural_task_audit_rejects_unknown_modules_unsafe_paths_and_lookups(self):
        unsafe = (
            "---\n- name: system mutation\n  ansible.builtin.systemd:\n    name: nova-compute\n    state: restarted\n",
            "---\n- name: service mutation\n  service:\n    name: neutron-server\n    state: stopped\n",
            "---\n- name: OpenStack module mutation\n  openstack.cloud.server:\n    name: server-1\n    state: absent\n",
            "---\n- name: unsafe delete\n  ansible.builtin.file:\n    path: /etc/nova/nova.conf\n    state: absent\n",
            "---\n- name: pipe lookup\n  ansible.builtin.set_fact:\n    value: \"{{ lookup('pipe', 'id') }}\"\n",
            "---\n- name: unknown lookup\n  ansible.builtin.debug:\n    msg: \"{{ lookup('community.general.random_string') }}\"\n",
            "---\n- name: traversal delete\n  ansible.builtin.file:\n    path: '{{ live_discovery_local_run_dir }}/../../etc/nova/nova.conf'\n    state: absent\n",
            "---\n- name: prefixed delete\n  ansible.builtin.file:\n    path: '/etc/nova/{{ live_discovery_run_id }}'\n    state: absent\n",
            "---\n- name: traversal copy\n  ansible.builtin.copy:\n    content: unsafe\n    dest: '{{ live_discovery_local_run_dir }}/../../etc/nova/nova.conf'\n",
            "---\n- name: traversal loop\n  ansible.builtin.file:\n    path: '{{ item }}'\n    state: absent\n  loop:\n    - '{{ live_discovery_local_run_dir }}/../../etc/nova/nova.conf'\n",
            "---\n- name: templated traversal\n  ansible.builtin.file:\n    path: \"{{ live_discovery_local_run_dir }}/{{ '..' }}/etc/nova/nova.conf\"\n    state: absent\n",
            "---\n- name: dirname escape\n  ansible.builtin.file:\n    path: '{{ live_discovery_local_run_dir | dirname }}/etc/nova/nova.conf'\n    state: absent\n",
            "---\n- name: lookalike root\n  ansible.builtin.file:\n    path: '{{ arbitrary_live_discovery_local_run_dir }}/etc/nova/nova.conf'\n    state: absent\n",
            "---\n- name: conditional root\n  ansible.builtin.file:\n    path: \"{{ '/etc/nova' if true else live_discovery_local_run_dir }}/nova.conf\"\n    state: absent\n",
        )
        for source in unsafe:
            with self.subTest(source=source):
                with self.assertRaises(AssertionError):
                    _audit_command_text(source, "synthetic")

    def test_dynamic_sql_argv_signature_binds_exact_loop_vars_and_source_path(self):
        path = ROOT / "playbooks/tasks/collect-live-db-jsonl-service.yml"
        payload = _yaml_load(path.read_text(encoding="utf-8"), path)
        target = next(
            task for task in _iter_task_mappings(payload, task_file=True)
            if task.get("name") == "Live DB JSONL | execute reviewed SELECT through argv transport"
        )
        target["loop"] = [{"sql": "DROP TABLE nova.instances;"}]
        with self.assertRaises(AssertionError):
            _audit_command_text(json.dumps(payload), path)
        pristine = path.read_text(encoding="utf-8")
        with self.assertRaises(AssertionError):
            _audit_command_text(pristine, ROOT / "playbooks/tasks/unreviewed-copy.yml")

        pristine_payload = _yaml_load(pristine, path)
        exact_task = next(
            task for task in _iter_task_mappings(pristine_payload, task_file=True)
            if task.get("name") == "Live DB JSONL | execute reviewed SELECT through argv transport"
        )
        compromised_source = [
            {
                "name": "replace reviewed query plan",
                "ansible.builtin.set_fact": {
                    "live_discovery_db_query_plan": {
                        "queries": [{"sql": "DROP TABLE nova.instances;"}],
                    },
                },
            },
            exact_task,
        ]
        with self.assertRaises(AssertionError):
            _audit_command_text(json.dumps(compromised_source), path)

        initialization = ROOT / "playbooks/tasks/initialize-live-run.yml"
        initialization_payload = _yaml_load(
            initialization.read_text(encoding="utf-8"), initialization
        )
        redirected_roots = [
            {
                "name": "redirect trusted discovery roots",
                "ansible.builtin.set_fact": {
                    "live_discovery_local_dir": "/etc/nova",
                    "live_discovery_local_run_dir": "/etc/nova/run",
                    "live_discovery_frozen_protected_dir": "/etc/nova/protected",
                },
            },
            *initialization_payload,
        ]
        with self.assertRaises(AssertionError):
            _audit_command_text(json.dumps(redirected_roots), initialization)
        initialization_payload.append(
            {
                "name": "conditional path injection",
                "ansible.builtin.file": {
                    "path": "{{ '/etc/nova' if true else live_discovery_local_dir }}",
                    "state": "absent",
                },
            }
        )
        with self.assertRaises(AssertionError):
            _audit_command_text(json.dumps(initialization_payload), initialization)

    def test_ansible_yaml_runtime_supports_env_shebang_and_rejects_wrappers(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "ansible-playbook"
            executable.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            def which(name):
                return str(executable) if name == "ansible-playbook" else sys.executable

            with mock.patch("shutil.which", side_effect=which):
                self.assertEqual([sys.executable], _yaml_python())

            executable.write_text("#!/usr/bin/env -S python3 -I\n", encoding="utf-8")
            with mock.patch("shutil.which", side_effect=which):
                self.assertEqual([sys.executable, "-I"], _yaml_python())

            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            with mock.patch("shutil.which", side_effect=which):
                with self.assertRaisesRegex(AssertionError, "unsupported"):
                    _yaml_python()

    def test_structural_include_graph_audits_fqcn_quoted_and_mapping_forms(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "child.yml"
            child.write_text(
                "---\n- name: mutation\n  command:\n    argv: [rm, -rf, /srv/data]\n",
                encoding="utf-8",
            )
            owners = (
                "---\n- name: play\n  hosts: localhost\n  tasks:\n"
                "    - name: quoted legacy\n"
                "      'ansible.legacy.include_tasks': child.yml\n",
                "---\n- name: play\n  hosts: localhost\n  tasks:\n"
                "    - name: collection mapping\n"
                "      example.collection.include_tasks:\n"
                "        file: child.yml\n",
            )
            for index, source in enumerate(owners):
                owner = root / f"owner-{index}.yml"
                owner.write_text(source, encoding="utf-8")
                with self.subTest(source=source):
                    paths = _reachable_playbook_paths(owner)
                    self.assertEqual({owner.resolve(), child.resolve()}, set(paths))
                    with self.assertRaises(AssertionError):
                        for path in paths:
                            _audit_command_text(
                                path.read_text(encoding="utf-8"), path
                            )

    def test_structural_include_graph_rejects_unknown_include_and_role_forms(self):
        unsafe = (
            "---\n- name: play\n  hosts: localhost\n  roles:\n    - unsafe\n",
            "---\n- name: play\n  hosts: localhost\n  tasks:\n    - include: child.yml\n",
            "---\n- name: play\n  hosts: localhost\n  tasks:\n    - ansible.legacy.include_role:\n        name: unsafe\n",
            "---\n- name: play\n  hosts: localhost\n  tasks:\n    - 'vendor.collection.import_role':\n        name: unsafe\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, source in enumerate(unsafe):
                owner = root / f"unsafe-{index}.yml"
                owner.write_text(source, encoding="utf-8")
                with self.subTest(source=source):
                    with self.assertRaises(AssertionError):
                        _reachable_playbook_paths(owner)

    def test_ansible_audit_rejects_alternate_modules_templates_and_multiline_mutation(self):
        unsafe = (
            "---\n- name: bare\n  command:\n    argv:\n      - openstack\n      - server\n      - lock\n      - server-1\n",
            "---\n- name: legacy\n  ansible.legacy.shell: openstack server lock server-1\n",
            "---\n- name: fqcn\n  ansible.builtin.command:\n    argv: [openstack, server, lock, server-1]\n",
            "---\n- name: raw\n  ansible.builtin.raw: docker stop nova_compute\n",
            "---\n- name: template\n  ansible.builtin.command:\n    argv: \"{{ arbitrary_inventory_argv }}\"\n",
            "---\n- when: true\n  command:\n    argv: [rm, -rf, /srv/data]\n",
            "---\n- name: unknown static\n  ansible.builtin.command:\n    argv: [rm, -rf, /srv/data]\n",
            "---\n- name: dynamic code\n  ansible.builtin.command:\n    argv:\n      - python3\n      - -c\n      - \"{{ arbitrary_python }}\"\n",
            "---\n- name: comment spoof\n  ansible.builtin.command:\n    argv: \"{{ arbitrary_inventory_argv }}\"\n    # ['python3'] live_discovery_mysql_json_argv ['version']\n",
            "---\n- name: inline comment spoof\n  ansible.builtin.command:\n    argv: \"{{ arbitrary_inventory_argv }}\" # ['python3'] live_discovery_mysql_json_argv ['version']\n",
            "---\n- name: action bypass\n  action: command openstack server lock server-1\n",
            "---\n- name: local action bypass\n  local_action: shell docker stop nova_compute\n",
            "---\n- name: dynamic helper path\n  command:\n    argv:\n      - python3\n      - \"{{ arbitrary_directory }}/run_owner.py\"\n      - verify\n",
            "---\n- name: whole expression helper spoof\n  command:\n    argv: \"{{ ['python3', arbitrary_directory + '/run_owner.py', 'verify'] }}\"\n",
        )
        for source in unsafe:
            with self.subTest(source=source):
                with self.assertRaises(AssertionError):
                    _audit_command_text(source, "synthetic")

    def test_schema_query_helper_module_is_exact_reviewed(self):
        self.assertTrue(_audit_python_argv([
            "python3", "-m", "live_discovery.schema_query",
            "--databases-json", '["nova"]',
        ]))
        self.assertFalse(_audit_python_argv([
            "python3", "-m", "live_discovery.schema_query_unreviewed",
            "--databases-json", '["nova"]',
        ]))

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
            ("import os\nlaunch = os.system\n", False),
            ("import os\nname = 'system'\nlaunch = getattr(os, name)\n", False),
            ("import os\nlaunch = os.__dict__['system']\n", False),
            ("import subprocess\nlaunch = subprocess.__dict__['run']\n", True),
            ("from subprocess import run as launch\nreference = launch\n", True),
            ("import os\nnamespace = os.__dict__\nlaunch = namespace['system']\n", False),
            ("import os\nlookup = getattr\nlaunch = lookup(os, 'system')\n", False),
            ("import os\nmodule = os\nlaunch = module.system\n", False),
            ("import os\na = os\nb = a\nlaunch = b.system\n", False),
            ("import subprocess\nmodule = subprocess\nlaunch = module.run\n", True),
            ("import os\ndef launch(module=os):\n    module.system('id')\n", False),
            ("import os\nmodule = os if True else None\nmodule.system('id')\n", False),
            ("import os\nmodule, other = os, None\nmodule.system('id')\n", False),
            ("import sys\nsys.modules['os'].system('id')\n", False),
            ("import os\nmodule = os or None\nmodule.system('id')\n", False),
            ("import os\nmodule = {'x': os}['x']\nmodule.system('id')\n", False),
            ("import sys\nmodule = sys.modules.get('os')\nmodule.system('id')\n", False),
            ("loader = __import__\nloader('os').system('id')\n", False),
            ("import builtins\nbuiltins.__import__('os').system('id')\n", False),
            ("__builtins__['__import__']('os').system('id')\n", False),
            ("import sys\ngetattr(sys, 'modules')['os'].system('id')\n", False),
            ("import sys\nvars(sys)['modules']['os'].system('id')\n", False),
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
        self.assertIn(PLAYBOOK.resolve(), paths)
        self.assertGreater(len(paths), 1)
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

    def test_runner_allows_barbican_metadata_get_but_never_secret_payload(self):
        secret_id = "11111111-1111-4111-8111-111111111111"
        allowed = (
            ["openstack", "secret", "get", secret_id, "-f", "json"],
            [
                "docker", "exec", "kolla_toolbox", "openstack",
                "--os-cloud", "source", "--os-client-config", "/run/clouds.yaml",
                "secret", "get", secret_id, "-f", "json",
            ],
        )
        rejected = (
            ["openstack", "secret", "get", secret_id],
            ["openstack", "secret", "get", secret_id, "--payload"],
            ["openstack", "secret", "get", secret_id, "-f", "json", "--payload"],
        )
        completed = mock.Mock(returncode=0, stdout='{"status":"ACTIVE"}', stderr="")
        with mock.patch(
            "live_discovery.runner.subprocess.run", return_value=completed
        ) as execute:
            for command in allowed:
                with self.subTest(allowed=command):
                    ReadOnlyRunner().run(command, "barbican-metadata")
            for command in rejected:
                with self.subTest(rejected=command):
                    with self.assertRaises(MutationRejected):
                        ReadOnlyRunner().run(command, "barbican-payload")
        self.assertEqual(len(allowed), execute.call_count)

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
