from dataclasses import asdict, dataclass
import json
import re
import subprocess
from typing import Any, Dict, List, Optional, Sequence


MUTATING_TOKENS = {
    "activate", "add", "archive", "attach", "clear", "create", "deactivate",
    "define", "delete", "destroy", "detach", "disable", "enable", "evacuate",
    "heal", "import", "managedsave", "map", "migrate", "pause", "promote",
    "purge", "rebind", "reboot", "rebuild", "remove", "rescue", "resize",
    "restart", "resume", "save", "set", "shelve", "shutdown", "start", "stop",
    "suspend", "sync", "unmap", "unpause", "unrescue", "unshelve", "unset",
    "update", "upgrade", "upload",
}

READ_ONLY_EXECUTABLES = {
    "openstack", "nova-manage", "neutron-db-manage", "cinder-manage",
    "mysql", "mariadb", "virsh", "ovs-vsctl", "ovs-ofctl", "ovn-nbctl",
    "ovn-sbctl", "rbd", "lvs", "stat", "test", "docker", "printf", "false",
    "qemu-system-x86_64",
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
    (r"\bINTO\s+DUMPFILE\b", "INTO DUMPFILE"),
    (r"\bLOAD_FILE\b", "LOAD_FILE"),
)
_MUTATING_COMPOUND_TOKEN = re.compile(
    r"(?:^|[-_])(?:activate|add|clear|create|deactivate|delete|destroy|insert|"
    r"map|mod|mutate|remove|set|unmap|update)(?:$|[-_])",
    flags=re.IGNORECASE,
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
        command_index = next(
            (
                index
                for index, token in enumerate(lowered[1:], start=1)
                if token != "--" and not token.startswith("-")
            ),
            None,
        )
        for index, token in enumerate(lowered[1:], start=1):
            if token in MUTATING_TOKENS or (
                index == command_index and _MUTATING_COMPOUND_TOKEN.search(token)
            ):
                if lowered[0] == "openstack":
                    return " ".join(lowered[1:3])
                start = max(1, index - 1)
                return " ".join(lowered[start:index + 1])
    return None


@dataclass(frozen=True)
class _SqlToken:
    kind: str
    value: str


_SQL_RESERVED_WORDS = {
    "AND", "AS", "ASC", "BY", "DESC", "FALSE", "FROM", "IN", "IS",
    "LIKE", "NOT", "NULL", "OR", "ORDER", "SELECT", "TRUE", "WHERE",
}


def _malformed_sql() -> MutationRejected:
    return MutationRejected("malformed SELECT statement")


def _tokenize_select_sql(statement: str) -> List[_SqlToken]:
    tokens: List[_SqlToken] = []
    index = 0
    while index < len(statement):
        character = statement[index]
        if character.isspace():
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            kind = "IDENT" if quote == "`" else "STRING"
            index += 1
            start = index
            closed = False
            while index < len(statement):
                current = statement[index]
                if current == "\\":
                    index += 2
                    continue
                if current == quote:
                    if index + 1 < len(statement) and statement[index + 1] == quote:
                        index += 2
                        continue
                    closed = True
                    break
                index += 1
            if not closed or (kind == "IDENT" and index == start):
                raise _malformed_sql()
            tokens.append(_SqlToken(kind, statement[start:index]))
            index += 1
            continue
        word = re.match(r"[A-Za-z_][A-Za-z0-9_]*", statement[index:])
        if word:
            value = word.group(0)
            tokens.append(_SqlToken("WORD", value))
            index += len(value)
            continue
        number = re.match(r"\d+(?:\.\d+)?", statement[index:])
        if number:
            value = number.group(0)
            tokens.append(_SqlToken("NUMBER", value))
            index += len(value)
            continue
        two_character = statement[index:index + 2]
        if two_character in {"!=", "<=", ">=", "<>"}:
            tokens.append(_SqlToken("OP", two_character))
            index += 2
            continue
        if character in "=<>+-/":
            tokens.append(_SqlToken("OP", character))
            index += 1
            continue
        if character in "(),.*;":
            tokens.append(_SqlToken("SYMBOL", character))
            index += 1
            continue
        raise _malformed_sql()
    return tokens


class _SelectParser:
    """Parse scalar SELECT or SELECT-list FROM table [WHERE] [ORDER BY]."""

    def __init__(self, tokens: Sequence[_SqlToken]) -> None:
        self.tokens = list(tokens)
        self.index = 0

    def parse(self) -> None:
        self._expect_keyword("SELECT")
        item_kinds = [self._parse_select_item()]
        while self._accept_symbol(","):
            item_kinds.append(self._parse_select_item())

        if self._accept_keyword("FROM"):
            self._parse_table_reference()
            if self._accept_keyword("WHERE"):
                self._parse_predicate()
            if self._accept_keyword("ORDER"):
                self._expect_keyword("BY")
                self._parse_order_list()
        elif len(item_kinds) != 1 or item_kinds[0] not in {
            "function", "group", "literal",
        }:
            raise _malformed_sql()

        if self._peek() is not None:
            raise _malformed_sql()

    def _peek(self) -> Optional[_SqlToken]:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def _advance(self) -> _SqlToken:
        token = self._peek()
        if token is None:
            raise _malformed_sql()
        self.index += 1
        return token

    def _is_keyword(self, token: Optional[_SqlToken], keyword: str) -> bool:
        return (
            token is not None
            and token.kind == "WORD"
            and token.value.upper() == keyword
        )

    def _accept_keyword(self, keyword: str) -> bool:
        if not self._is_keyword(self._peek(), keyword):
            return False
        self.index += 1
        return True

    def _expect_keyword(self, keyword: str) -> None:
        if not self._accept_keyword(keyword):
            raise _malformed_sql()

    def _accept_symbol(self, value: str) -> bool:
        token = self._peek()
        if token is None or token.kind != "SYMBOL" or token.value != value:
            return False
        self.index += 1
        return True

    def _expect_symbol(self, value: str) -> None:
        if not self._accept_symbol(value):
            raise _malformed_sql()

    def _parse_identifier(self) -> None:
        token = self._peek()
        if token is None:
            raise _malformed_sql()
        if token.kind == "IDENT" or (
            token.kind == "WORD"
            and token.value.upper() not in _SQL_RESERVED_WORDS
        ):
            self.index += 1
            return
        raise _malformed_sql()

    def _parse_select_item(self) -> str:
        if self._accept_symbol("*"):
            kind = "star"
        else:
            kind = self._parse_expression()
        if self._accept_keyword("AS"):
            self._parse_identifier()
        return kind

    def _parse_expression(self) -> str:
        token = self._peek()
        if token is None:
            raise _malformed_sql()
        if token.kind == "OP" and token.value in {"+", "-"}:
            self._advance()
            return self._parse_expression()
        if (
            token.kind in {"NUMBER", "STRING"}
            or self._is_keyword(token, "NULL")
            or self._is_keyword(token, "TRUE")
            or self._is_keyword(token, "FALSE")
        ):
            self._advance()
            return "literal"
        if self._accept_symbol("("):
            self._parse_expression()
            self._expect_symbol(")")
            return "group"
        if token.kind not in {"IDENT", "WORD"}:
            raise _malformed_sql()

        self._parse_identifier()
        if self._accept_symbol("("):
            if self._accept_symbol(")"):
                return "function"
            if self._accept_symbol("*"):
                self._expect_symbol(")")
                return "function"
            self._parse_expression()
            while self._accept_symbol(","):
                self._parse_expression()
            self._expect_symbol(")")
            return "function"
        while self._accept_symbol("."):
            self._parse_identifier()
        return "column"

    def _parse_table_reference(self) -> None:
        self._parse_identifier()
        if self._accept_symbol("."):
            self._parse_identifier()

    def _parse_predicate(self) -> None:
        self._parse_and_predicate()
        while self._accept_keyword("OR"):
            self._parse_and_predicate()

    def _parse_and_predicate(self) -> None:
        self._parse_comparison()
        while self._accept_keyword("AND"):
            self._parse_comparison()

    def _parse_comparison(self) -> None:
        if self._accept_symbol("("):
            self._parse_predicate()
            self._expect_symbol(")")
            return

        self._parse_expression()
        token = self._peek()
        if token is not None and token.kind == "OP" and token.value in {
            "=", "!=", "<", "<=", "<>", ">", ">=",
        }:
            self._advance()
            self._parse_expression()
            return
        if self._accept_keyword("LIKE"):
            self._parse_expression()
            return
        if self._accept_keyword("IS"):
            self._accept_keyword("NOT")
            self._expect_keyword("NULL")
            return

        self._accept_keyword("NOT")
        if self._accept_keyword("IN"):
            self._expect_symbol("(")
            self._parse_expression()
            while self._accept_symbol(","):
                self._parse_expression()
            self._expect_symbol(")")
            return
        raise _malformed_sql()

    def _parse_order_list(self) -> None:
        self._parse_order_item()
        while self._accept_symbol(","):
            self._parse_order_item()

    def _parse_order_item(self) -> None:
        self._parse_identifier()
        while self._accept_symbol("."):
            self._parse_identifier()
        if not self._accept_keyword("ASC"):
            self._accept_keyword("DESC")


def validate_select_only_sql(sql: str) -> str:
    statement = sql.strip()
    if any(marker in statement for marker in ("--", "#", "/*", "*/")):
        raise MutationRejected("SQL comments are not allowed")
    for pattern, label in _FORBIDDEN_SQL:
        if re.search(pattern, statement, flags=re.IGNORECASE):
            raise MutationRejected(f"SQL token {label} is not allowed")
    tokens = _tokenize_select_sql(statement)
    semicolons = [
        index for index, token in enumerate(tokens)
        if token.kind == "SYMBOL" and token.value == ";"
    ]
    if semicolons != [len(tokens) - 1]:
        raise MutationRejected("run_sql accepts one SELECT statement ending with ';'")
    _SelectParser(tokens[:-1]).parse()
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

        if nested_executable == "qemu-system-x86_64" and nested[1:] != [
            "-machine", "help",
        ]:
            raise MutationRejected("only qemu -machine help is allowed")

        if not allow_sql and nested_executable in {"mysql", "mariadb"}:
            raise MutationRejected("mysql requires run_sql")
        return values
