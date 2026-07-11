from dataclasses import asdict, dataclass
import json
import re
import subprocess
from typing import Any, Dict, List, Optional, Sequence


MUTATING_TOKENS = {
    "create", "delete", "set", "unset", "update", "sync", "migrate",
    "heal", "rebind", "stop", "start", "restart", "enable", "disable",
    "attach", "detach", "upload", "save", "import", "purge", "archive",
}

READ_ONLY_EXECUTABLES = {
    "openstack", "nova-manage", "neutron-db-manage", "cinder-manage",
    "mysql", "mariadb", "virsh", "ovs-vsctl", "ovs-ofctl", "ovn-nbctl",
    "ovn-sbctl", "rbd", "lvs", "stat", "test", "docker", "printf", "false",
}

_DOCKER_EXEC_OPTIONS_WITH_VALUE = {
    "--detach-keys", "--env", "--env-file", "--user", "--workdir",
    "-e", "-u", "-w",
}
_SQL_BEARING_MYSQL_OPTIONS = {
    "--execute", "--init-command", "--init-command-add",
}
_MYSQL_SHORT_OPTIONS_WITH_VALUE = {"D", "h", "p", "P", "S", "u"}
_SENSITIVE_MARKER = re.compile(
    r"password|passwd|(?:^|[_-])pwd(?:$|[_-])|token|secret|"
    r"connection[_-]?(?:info|data)|chap|credential|connector",
    flags=re.IGNORECASE,
)
_FORBIDDEN_SQL = (
    (r"\bINSERT\b", "INSERT"),
    (r"\bUPDATE\b", "UPDATE"),
    (r"\bDELETE\b", "DELETE"),
    (r"\bREPLACE\b", "REPLACE"),
    (r"\bALTER\b", "ALTER"),
    (r"\bCREATE\b", "CREATE"),
    (r"\bDROP\b", "DROP"),
    (r"\bTRUNCATE\b", "TRUNCATE"),
    (r"\bGRANT\b", "GRANT"),
    (r"\bREVOKE\b", "REVOKE"),
    (r"\bCALL\b", "CALL"),
    (r"\bDO\b", "DO"),
    (r"\bSET\b", "SET"),
    (r"\bINTO\s+OUTFILE\b", "INTO OUTFILE"),
    (r"\bLOAD_FILE\b", "LOAD_FILE"),
)


class MutationRejected(RuntimeError):
    pass


class ProbeFailed(RuntimeError):
    def __init__(self, evidence: "CommandEvidence") -> None:
        self.evidence = evidence
        super().__init__(
            f"probe {evidence.evidence_id!r} failed with return code {evidence.returncode}"
        )


@dataclass
class CommandEvidence:
    evidence_id: str
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def unwrap_docker_exec(argv: Sequence[object]) -> List[str]:
    values = [str(value) for value in argv]
    if len(values) < 2 or values[0].lower() != "docker":
        return values
    if values[1].lower() != "exec":
        return values

    index = 2
    while index < len(values) and values[index].startswith("-"):
        option = values[index]
        index += 1
        if "=" not in option and option in _DOCKER_EXEC_OPTIONS_WITH_VALUE:
            index += 1
    if index >= len(values):
        return []
    return values[index + 1:]


def classify_mutation(argv: Sequence[object]) -> Optional[str]:
    lowered = [str(value).lower() for value in unwrap_docker_exec(argv)]
    phrase = " ".join(lowered)
    if "online_data_migrations" in phrase:
        return "online_data_migrations"
    if lowered and lowered[0] in {"mysql", "mariadb"}:
        return "mysql requires run_sql"
    if lowered:
        for index, token in enumerate(lowered[1:], start=1):
            if token in MUTATING_TOKENS:
                if lowered[0] == "openstack":
                    return " ".join(lowered[1:3])
                start = max(1, index - 1)
                return " ".join(lowered[start:index + 1])
    return None


def validate_select_only_sql(sql: str) -> str:
    statement = sql.strip()
    if any(marker in statement for marker in ("--", "#", "/*", "*/")):
        raise MutationRejected("SQL comments are not allowed")
    for pattern, label in _FORBIDDEN_SQL:
        if re.search(pattern, statement, flags=re.IGNORECASE):
            raise MutationRejected(f"SQL token {label} is not allowed")
    semicolons = []
    quote = None
    parentheses = 0
    index = 0
    while index < len(statement):
        character = statement[index]
        if quote is not None:
            if character == "\\":
                index += 2
                continue
            if character == quote:
                if index + 1 < len(statement) and statement[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif character in {"'", '"', "`"}:
            quote = character
        elif character == "(":
            parentheses += 1
        elif character == ")":
            parentheses -= 1
            if parentheses < 0:
                raise MutationRejected("malformed SELECT statement")
        elif character == ";":
            semicolons.append(index)
        index += 1
    if quote is not None or parentheses != 0:
        raise MutationRejected("malformed SELECT statement")
    if semicolons != [len(statement) - 1] or not re.fullmatch(
        r"SELECT\b[\s\S]*;", statement, flags=re.IGNORECASE
    ):
        raise MutationRejected("run_sql accepts one SELECT statement ending with ';'")
    body = statement[:-1]
    if re.fullmatch(r"SELECT\s*", body, flags=re.IGNORECASE) or re.match(
        r"SELECT\s+FROM\b", body, flags=re.IGNORECASE
    ):
        raise MutationRejected("malformed SELECT statement")
    return statement


# Compatibility for Task 1 callers that may have imported the private helper.
_validate_select_only_sql = validate_select_only_sql


def _reject_sql_bearing_argv(argv: Sequence[str]) -> None:
    for value in argv[1:]:
        lowered = value.lower()
        option = lowered.split("=", 1)[0]
        short_execute = _has_short_execute_option(value)
        long_sql_option = len(option) > 2 and any(
            candidate.startswith(option) for candidate in _SQL_BEARING_MYSQL_OPTIONS
        )
        if short_execute or long_sql_option:
            label = "-e" if short_execute else option
            raise MutationRejected(f"SQL-bearing client option is not allowed: {label}")


def _has_short_execute_option(value: str) -> bool:
    if not value.startswith("-") or value.startswith("--"):
        return False
    for option in value[1:]:
        if option == "e":
            return True
        if option in _MYSQL_SHORT_OPTIONS_WITH_VALUE:
            return False
    return False


def _redact_evidence_argv(argv: Sequence[str]) -> List[str]:
    redacted: List[str] = []
    redact_next = False
    for index, value in enumerate(argv):
        if index == 0:
            redacted.append(value)
            continue
        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
            continue

        if value.startswith("-p") and not value.startswith("--") and len(value) > 2:
            redacted.append("-p[REDACTED]")
            continue
        if "=" in value:
            key, _unused = value.split("=", 1)
            if _SENSITIVE_MARKER.search(key):
                redacted.append(f"{key}=[REDACTED]")
                continue
        if value.startswith("-") and _SENSITIVE_MARKER.search(value):
            redacted.append(value)
            redact_next = True
            continue
        if _is_cinder_connection_payload(value) or _SENSITIVE_MARKER.search(value):
            redacted.append("[REDACTED]")
            continue
        redacted.append(value)
    return redacted


def _is_cinder_connection_payload(value: str) -> bool:
    try:
        payload = json.loads(value)
    except (TypeError, ValueError):
        return False
    return (
        isinstance(payload, dict)
        and "driver_volume_type" in payload
        and isinstance(payload.get("data"), dict)
    )


def _redact_evidence_stderr(stderr: str, sensitive: bool) -> str:
    if not stderr:
        return stderr
    if sensitive or _SENSITIVE_MARKER.search(stderr):
        return "[REDACTED]"
    return stderr


class ReadOnlyRunner:
    def run(
        self,
        argv: Sequence[object],
        evidence_id: str,
        sensitive_stdout: bool = False,
    ) -> CommandEvidence:
        values = self._validated_argv(argv, allow_sql=False)
        mutation = classify_mutation(values)
        if mutation is not None:
            raise MutationRejected(f"mutating command rejected: {mutation}")

        completed = subprocess.run(
            values,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        evidence = CommandEvidence(
            evidence_id=evidence_id,
            argv=_redact_evidence_argv(values),
            returncode=completed.returncode,
            stdout="[REDACTED]" if sensitive_stdout else completed.stdout,
            stderr=_redact_evidence_stderr(completed.stderr, sensitive_stdout),
        )
        if completed.returncode != 0:
            raise ProbeFailed(evidence)
        return evidence

    def run_sql(
        self,
        argv: Sequence[object],
        sql: str,
        evidence_id: str,
    ) -> CommandEvidence:
        values = self._validated_argv(argv, allow_sql=True)
        nested = unwrap_docker_exec(values)
        if not nested or nested[0].lower() not in {"mysql", "mariadb"}:
            raise MutationRejected("run_sql requires mysql or mariadb")
        _reject_sql_bearing_argv(nested)
        validate_select_only_sql(sql)

        completed = subprocess.run(
            values,
            input=sql,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        evidence = CommandEvidence(
            evidence_id=evidence_id,
            argv=_redact_evidence_argv(values),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=_redact_evidence_stderr(completed.stderr, sensitive=False),
        )
        if completed.returncode != 0:
            raise ProbeFailed(evidence)
        return evidence

    @staticmethod
    def _validated_argv(argv: Sequence[object], allow_sql: bool) -> List[str]:
        values = [str(value) for value in argv]
        if not values:
            raise MutationRejected("empty command rejected")
        executable = values[0].lower()
        if executable not in READ_ONLY_EXECUTABLES:
            raise MutationRejected(f"unknown executable rejected: {executable}")

        nested = unwrap_docker_exec(values)
        if executable == "docker":
            if len(values) < 2 or values[1].lower() != "exec" or not nested:
                raise MutationRejected("only docker exec is allowed")
            nested_executable = nested[0].lower()
            if nested_executable not in READ_ONLY_EXECUTABLES - {"docker"}:
                raise MutationRejected(f"unknown executable rejected: {nested_executable}")
        else:
            nested_executable = executable

        if not allow_sql and nested_executable in {"mysql", "mariadb"}:
            raise MutationRejected("mysql requires run_sql")
        return values
