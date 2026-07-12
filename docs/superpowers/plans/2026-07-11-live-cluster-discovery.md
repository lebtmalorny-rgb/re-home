# План реализации live discovery кластера

> **Для исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: применяйте superpowers:subagent-driven-development (рекомендуется) или superpowers:executing-plans и выполняйте план по задачам. Для отслеживания используются флажки (`- [ ]`).

**Цель:** Построить полностью read-only live discovery pipeline, который собирает resource graph ВМ на re-home compute host, направленно сравнивает vendor Keystack source с vanilla OpenStack 2025.1 Epoxy target и выдаёт fail-closed readiness verdict для Nova, Neutron, Cinder, Glance и runtime.

**Архитектура:** Ansible запускает изолированные collectors на source/target control plane и re-home compute, а локальный assembler объединяет их versioned artifacts. Collectors используют общий stdlib-only контракт, безопасный argv runner и service-specific модули; target `information_schema` является canonical schema, а source-only vendor fields проходят только через явную policy. Никакие API/SQL mutations, data copies, service restarts, online data migrations или Masakari/DRS operations не выполняются.

**Технологии:** Python 3 standard library, `unittest`, Ansible Core 2.18+, OpenStackClient внутри Kolla `kolla_toolbox`, MariaDB read-only queries, libvirt CLI, OVS/OVN read-only CLI, JSON/YAML/Markdown artifacts.

## Общие ограничения

- Target profile: `vanilla-openstack-2025.1-epoxy`; live target schema и runtime являются canonical.
- Source profile: vendor-modified Keystack; source-only semantics не отбрасываются молча.
- Production facts собираются только с живых source/target кластеров; schema dumps допустимы только как sanitized test fixtures.
- Masakari и DRS полностью исключены из collectors, graph и readiness verdict.
- Collector не выполняет команды классов `create`, `set`, `update`, `delete`, `sync`, `migrate`, `heal`, `rebind`, `stop`, `restart` и не выполняет SQL DML/DDL.
- `UNKNOWN` и `BLOCKED` возвращают ненулевой exit code; failed probe никогда не превращается в пустой успешный результат.
- `nova-manage db online_data_migrations` и `cinder-manage db online_data_migrations` не запускаются.
- Полные secrets, tokens и Cinder connection info не попадают в обычные JSON/YAML/Markdown artifacts или test output.
- Runtime/generated artifacts остаются под `artifacts/` и не коммитятся.
- Реализация остаётся stdlib-only; новые Python dependencies не добавляются.
- Каждый task заканчивается отдельным commit после red-green тестового цикла.

## Планируемая структура файлов

```text
scripts/
  collect_live_control.py              # remote source/target controller entrypoint
  collect_live_runtime.py              # remote compute entrypoint
  assemble_live_discovery.py           # local graph/verdict/render entrypoint
  live_discovery/
    __init__.py                         # contract version and public exports
    contract.py                         # nodes, edges, checks, collector results
    runner.py                           # mutation-safe subprocess execution/evidence
    mysql_json.py                       # injection-safe JSONL SELECT transport
    schema.py                           # information_schema parser and directional mapping
    openstack.py                        # read-only OpenStack CLI adapter
    nova.py                             # Nova root discovery and mappings
    runtime.py                          # libvirt/OVS/OVN runtime normalization
    neutron.py                         # network dependency discovery
    cinder.py                           # volume/attachment/backend dependency discovery
    storage.py                          # NFS/RBD/LVM read-only backing probes
    glance.py                           # image/store dependency discovery
    image_data.py                       # one-byte Glance Range GET probe
    graph.py                            # merge and graph integrity validation
    verdict.py                         # per-resource and aggregate readiness
    render.py                          # JSON/YAML/Markdown artifact rendering
playbooks/
  02b-discover-live-resource-graph.yml # orchestration and fail-closed gate
  tasks/
    collect-live-schema-service.yml    # service-user information_schema JSON facts
    collect-live-db-jsonl-service.yml  # execute generated SELECT-only JSONL queries
inventory/
  live-discovery-schema-policy.json    # reviewed vendor-to-vanilla mapping policy
tests/
  fixtures/live_discovery/             # sanitized API/schema/runtime fixtures
  test_live_discovery_*.py              # focused unit/contract tests
docs/
  live-discovery-artifacts-ru.md
  live-discovery-data-flow-ru.md
cinder-rehome-readiness-ru.md
glance-rehome-readiness-ru.md
```

Существующие файлы, изменяемые по плану:

- `group_vars/all.yml` — generic live discovery variables.
- `inventory/hosts.yml` — portable example variables/groups.
- `inventory/lab-os1-to-os2.yml` — lab-specific Kolla commands and backend probes.
- `README.md` — execution order and first-read links.
- `operator-inputs-ru.md` — credentials, backend and vanilla Epoxy prerequisites.
- `playbook-logic-ru.md` — exact orchestration and mutation boundary.
- `lab-rehome-runbook-ru.md` — operator commands and verdict interpretation.
- `docs/lab-topology-ru.md` — evidence/data-flow references.
- `neutron-rehome-behavior-ru.md` — expanded Neutron dependency coverage.
- `tests/test_playbook_logic_doc.py` — new top-level playbook coverage.
- `tests/test_lab_topology_doc.py` — new documentation links.

---

### Задача 1: Версионированный контракт и fail-closed read-only runner

**Файлы:**

- Create: `scripts/live_discovery/__init__.py`
- Create: `scripts/live_discovery/contract.py`
- Create: `scripts/live_discovery/runner.py`
- Create: `tests/test_live_discovery_contract.py`
- Create: `tests/test_live_discovery_runner.py`

**Интерфейсы:**

- Produces: `CONTRACT_VERSION = "openstack-rehome-live-discovery/v1alpha1"`.
- Produces: `CheckResult`, `ResourceNode`, `DependencyEdge`, `CollectorResult`, each with `to_dict()`.
- Produces: `CommandEvidence`, `ReadOnlyRunner.run(argv, evidence_id, sensitive_stdout=False)` and `ReadOnlyRunner.run_sql(argv, sql, evidence_id)`.
- Produces: `MutationRejected`, `ProbeFailed`.
- All later tasks consume these exact names.

- [ ] **Шаг 1: Написать failing-тесты для contract tests**

```python
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.contract import CheckResult, CollectorResult, DependencyEdge, ResourceNode


class LiveDiscoveryContractTests(unittest.TestCase):
    def test_collector_result_serializes_nodes_edges_and_blockers(self):
        result = CollectorResult(service="nova", side="source")
        result.nodes.append(ResourceNode("instance", "instance-1", "source", {"host": "compute-1"}))
        result.edges.append(DependencyEdge("instance:instance-1", "port:port-1", "uses", True))
        result.checks.append(CheckResult("nova.server.show", "PASS", "server exists", ["instance-1"]))
        result.blockers.append("cell mapping missing")
        payload = result.to_dict()
        self.assertEqual("openstack-rehome-live-discovery/v1alpha1", payload["schema_version"])
        self.assertEqual("instance-1", payload["nodes"][0]["id"])
        self.assertEqual("port:port-1", payload["edges"][0]["target"])
        self.assertEqual(["cell mapping missing"], payload["blockers"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Шаг 2: Запустить contract test and verify RED**

Команда: `python3 -m unittest tests.test_live_discovery_contract -v`

Ожидается: `ModuleNotFoundError: No module named 'live_discovery'`.

- [ ] **Шаг 3: Реализовать the complete contract dataclasses**

```python
# scripts/live_discovery/contract.py
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

CONTRACT_VERSION = "openstack-rehome-live-discovery/v1alpha1"


@dataclass
class CheckResult:
    check_id: str
    status: str
    reason: str
    resource_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResourceNode:
    kind: str
    id: str
    side: str
    facts: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.id}"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["key"] = self.key
        return payload


@dataclass
class DependencyEdge:
    source: str
    target: str
    relation: str
    required: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CollectorResult:
    service: str
    side: str
    nodes: List[ResourceNode] = field(default_factory=list)
    edges: List[DependencyEdge] = field(default_factory=list)
    checks: List[CheckResult] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": CONTRACT_VERSION,
            "service": self.service,
            "side": self.side,
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "checks": [item.to_dict() for item in self.checks],
            "unknowns": list(self.unknowns),
            "blockers": list(self.blockers),
            "evidence": list(self.evidence),
        }
```

`scripts/live_discovery/__init__.py` must export the four dataclasses and `CONTRACT_VERSION`.

- [ ] **Шаг 4: Написать failing-тесты для runner tests**

```python
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.runner import MutationRejected, ProbeFailed, ReadOnlyRunner


class LiveDiscoveryRunnerTests(unittest.TestCase):
    def test_rejects_mutating_openstack_command_before_subprocess(self):
        runner = ReadOnlyRunner()
        with self.assertRaisesRegex(MutationRejected, "server set"):
            runner.run(["openstack", "server", "set", "instance-1"], "bad-command")

    def test_required_failure_raises_with_evidence(self):
        runner = ReadOnlyRunner()
        with self.assertRaises(ProbeFailed) as raised:
            runner.run(["false"], "required-failure")
        self.assertNotEqual(0, raised.exception.evidence.returncode)

    def test_sensitive_stdout_is_redacted(self):
        runner = ReadOnlyRunner()
        evidence = runner.run(["printf", "secret-token"], "token", sensitive_stdout=True)
        self.assertEqual("[REDACTED]", evidence.stdout)

    def test_rejects_mutation_nested_in_docker_exec(self):
        runner = ReadOnlyRunner()
        with self.assertRaisesRegex(MutationRejected, "server set"):
            runner.run(
                ["docker", "exec", "kolla_toolbox", "openstack", "server", "set", "instance-1"],
                "nested-mutation",
            )

    def test_mysql_requires_select_only_sql_entrypoint(self):
        runner = ReadOnlyRunner()
        with self.assertRaisesRegex(MutationRejected, "run_sql"):
            runner.run(["mysql", "--batch"], "unvalidated-mysql")
        with self.assertRaisesRegex(MutationRejected, "INSERT"):
            runner.run_sql(["mysql", "--batch"], "INSERT INTO nova.instances VALUES (1);", "insert")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Шаг 5: Запустить runner tests and verify RED**

Команда: `python3 -m unittest tests.test_live_discovery_runner -v`

Ожидается: import failure for `live_discovery.runner`.

- [ ] **Шаг 6: Реализовать argv-only runner and mutation classifier**

Реализовать `CommandEvidence.to_dict()` и `ReadOnlyRunner` со следующими точными правилами:

```python
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


def classify_mutation(argv):
    lowered = [str(value).lower() for value in unwrap_docker_exec(argv)]
    phrase = " ".join(lowered)
    if "online_data_migrations" in phrase:
        return "online_data_migrations"
    if lowered and lowered[0] == "openstack":
        for token in lowered[1:]:
            if token in MUTATING_TOKENS:
                return " ".join(lowered[1:3])
    if lowered and lowered[0] in {"mysql", "mariadb"}:
        return "mysql requires run_sql"
    return None
```

`unwrap_docker_exec(argv)` must return the nested command after Docker options/container name, so `docker exec ... openstack server set` is classified exactly like a direct command. `ReadOnlyRunner.run` must use `subprocess.run(argv, text=True, stdout=PIPE, stderr=PIPE, check=False)`, reject unknown executables, reject direct MySQL execution, raise `ProbeFailed` for non-zero required commands, and never use `shell=True`.

`run_sql` must accept only one comment-free statement matching `^SELECT\b[\s\S]*;$`, reject additional semicolons and the tokens `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `ALTER`, `CREATE`, `DROP`, `TRUNCATE`, `GRANT`, `REVOKE`, `CALL`, `DO`, `SET`, `INTO OUTFILE`, `LOAD_FILE`, and pass the SQL through `subprocess.run(..., input=sql)`. Docker-wrapped `mysql`/`mariadb` argv is allowed only through `run_sql`.

- [ ] **Шаг 7: Запустить focused and full tests**

Команда: `python3 -m unittest tests.test_live_discovery_contract tests.test_live_discovery_runner -v`

Ожидается: 6 tests, all `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: all existing and new tests `OK`.

- [ ] **Шаг 8: Зафиксировать Task 1**

```bash
git add scripts/live_discovery tests/test_live_discovery_contract.py tests/test_live_discovery_runner.py
git commit -m "feat: add live discovery contract and safe runner"
```

### Задача 2: JSONL-транспорт БД и направленное сопоставление схем

**Файлы:**

- Create: `scripts/live_discovery/mysql_json.py`
- Create: `scripts/live_discovery/schema.py`
- Create: `tests/test_live_discovery_mysql_json.py`
- Create: `tests/test_live_discovery_schema.py`
- Create: `tests/fixtures/live_discovery/source-information-schema.tsv`
- Create: `tests/fixtures/live_discovery/target-information-schema.tsv`
- Create: `tests/fixtures/live_discovery/schema-policy.json`
- Create: `inventory/live-discovery-schema-policy.json`

**Интерфейсы:**

- Consumes: `CollectorResult`, `CheckResult` from Task 1.
- Produces: `validate_identifier(value)`, `uuid_in(column, values)`, `build_json_row_query(schema, table, columns, where_sql)`.
- Produces: `validate_select_only_sql(sql)` and CLI `python3 -m live_discovery.mysql_json --validate-sql FILE`.
- Produces: `parse_information_schema(path) -> SchemaSnapshot`.
- Produces: `build_directional_mapping(source, target, used_columns, policy) -> dict`.

- [ ] **Шаг 1: Написать failing-тесты для JSON transport tests**

```python
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.mysql_json import build_json_row_query, uuid_in


class MysqlJsonTransportTests(unittest.TestCase):
    def test_json_object_transport_preserves_text_fields(self):
        sql = build_json_row_query(
            "nova", "instance_info_caches", ["instance_uuid", "network_info"],
            uuid_in("instance_uuid", ["11111111-1111-1111-1111-111111111111"]),
        )
        self.assertIn("JSON_OBJECT('instance_uuid', `instance_uuid`, 'network_info', `network_info`)", sql)
        self.assertNotIn("SELECT *", sql)

    def test_uuid_filter_rejects_non_uuid_input(self):
        with self.assertRaisesRegex(ValueError, "invalid UUID"):
            uuid_in("id", ["x' OR 1=1"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Шаг 2: Проверить JSON transport RED**

Команда: `python3 -m unittest tests.test_live_discovery_mysql_json -v`

Ожидается: import failure for `live_discovery.mysql_json`.

- [ ] **Шаг 3: Реализовать identifier validation and one-JSON-object-per-row SELECT generation**

Сгенерированный SQL должен иметь следующий вид и завершаться точкой с запятой:

```sql
SELECT JSON_OBJECT(
  '_schema', 'nova',
  '_table', 'instance_info_caches',
  'row', JSON_OBJECT('instance_uuid', `instance_uuid`, 'network_info', `network_info`)
)
FROM `nova`.`instance_info_caches`
WHERE `instance_uuid` IN ('11111111-1111-1111-1111-111111111111');
```

Для идентификаторов использовать regex `^[A-Za-z_][A-Za-z0-9_]*$` и Python
`uuid.UUID(value)` for every UUID literal. Do not use `--raw` TSV rows for live discovery.

CLI модуля должен прочитать один файл, вызвать тот же валидатор одного statement, что и `ReadOnlyRunner.run_sql`, вывести `SELECT_ONLY_OK` при успехе и вернуть ненулевой код для комментариев, скрывающих второй statement, DML/DDL, `INTO OUTFILE`, `LOAD_FILE` или некорректного SQL.

- [ ] **Шаг 4: Написать failing-тесты для directional mapping tests**

```python
def test_vendor_source_column_is_ignored_only_by_explicit_policy(self):
    mapping = build_directional_mapping(
        source_snapshot,
        target_snapshot,
        {"nova.services": ["uuid", "host", "admin_state"]},
        {"source_only_allowlist": ["nova.services.admin_state"]},
    )
    by_column = {item["column"]: item for item in mapping["tables"]["nova.services"]}
    self.assertEqual("COMMON_COMPATIBLE", by_column["uuid"]["classification"])
    self.assertEqual("SOURCE_ONLY_IGNORED", by_column["admin_state"]["classification"])


def test_target_required_column_without_default_blocks(self):
    mapping = build_directional_mapping(
        source_snapshot,
        target_snapshot,
        {"cinder.volumes": ["id", "service_uuid"]},
        {"source_only_allowlist": []},
    )
    self.assertIn("cinder.volumes.target_required", mapping["blockers"])
```

- [ ] **Шаг 5: Проверить schema mapping RED**

Команда: `python3 -m unittest tests.test_live_discovery_schema -v`

Ожидается: import failure or missing `build_directional_mapping`.

- [ ] **Шаг 6: Реализовать exact mapping classifications**

`build_directional_mapping` must emit only:

```python
CLASSIFICATIONS = {
    "COMMON_COMPATIBLE",
    "NORMALIZATION_REQUIRED",
    "SOURCE_ONLY_IGNORED",
    "TARGET_DEFAULT",
    "TARGET_VALUE_REQUIRED",
    "SEMANTIC_MISMATCH",
    "BLOCKED",
}
```

Сравнение типов должно нормализовать `integer -> int`, игнорировать display width вроде `int(11)` и сохранять signedness, длину строки, nullability, default и auto_increment. `cell_id`, `compute_id`, `service_uuid`, `volume_type_id` и настроенные идентификаторы backend классифицируются как `NORMALIZATION_REQUIRED`, даже если SQL-типы совпадают.

Создать первоначальную reviewed policy без table-wide ignores и только с двумя известными non-runtime колонками сервиса Nova Keystack из примерной схемы:

```json
{
  "schema_version": "openstack-rehome-schema-policy/v1alpha1",
  "source_profile": "keystack-2025.1",
  "target_profile": "vanilla-openstack-2025.1-epoxy",
  "source_only_allowlist": [
    "nova.services.admin_state",
    "nova.services.error_details"
  ],
  "normalization_columns": [
    "nova_api.host_mappings.cell_id",
    "nova_api.instance_mappings.cell_id",
    "nova.instances.compute_id",
    "cinder.volumes.service_uuid",
    "cinder.volumes.volume_type_id",
    "cinder.volumes.host",
    "cinder.volumes.cluster_name"
  ]
}
```

Любая другая используемая только на source колонка остаётся `BLOCKED`, пока policy не проверена и не зафиксирована.

- [ ] **Шаг 7: Запустить focused and full tests**

Команда: `python3 -m unittest tests.test_live_discovery_mysql_json tests.test_live_discovery_schema -v`

Ожидается: all focused tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

- [ ] **Шаг 8: Зафиксировать Task 2**

```bash
git add scripts/live_discovery/mysql_json.py scripts/live_discovery/schema.py inventory/live-discovery-schema-policy.json tests/test_live_discovery_mysql_json.py tests/test_live_discovery_schema.py tests/fixtures/live_discovery
git commit -m "feat: add directional live schema mapping"
```

### Задача 3: Read-only адаптер OpenStack и канонический профиль Epoxy

**Файлы:**

- Create: `scripts/live_discovery/openstack.py`
- Create: `tests/test_live_discovery_openstack.py`
- Create: `tests/fixtures/live_discovery/openstack-command-results.json`

**Интерфейсы:**

- Consumes: `ReadOnlyRunner` from Task 1.
- Produces: `OpenStackClient(runner, cloud, container, clouds_path)`.
- Produces: `OpenStackClient.json(command, evidence_id, required=True)`.
- Produces: `collect_target_profile(client, manage_outputs, image_inspects) -> CollectorResult`.

- [ ] **Шаг 1: Написать failing-тесты для adapter tests**

```python
class FakeRunner:
    def __init__(self):
        self.commands = []

    def run(self, argv, evidence_id, sensitive_stdout=False):
        self.commands.append(list(argv))
        return type("Evidence", (), {"stdout": '{"id":"server-1"}', "to_dict": lambda self: {"id": evidence_id}})()


def test_kolla_client_builds_argv_without_shell():
    runner = FakeRunner()
    client = OpenStackClient(runner, "kolla-admin", "kolla_toolbox", "/tmp/clouds.yaml")
    payload, evidence = client.json(["server", "show", "server-1", "-f", "json"], "server-show")
    assert payload["id"] == "server-1"
    assert runner.commands[0][:7] == [
        "docker", "exec", "-e", "OS_CLIENT_CONFIG_FILE=/tmp/clouds.yaml",
        "kolla_toolbox", "openstack", "--os-cloud",
    ]
```

- [ ] **Шаг 2: Проверить adapter RED**

Команда: `python3 -m unittest tests.test_live_discovery_openstack -v`

Ожидается: import failure for `live_discovery.openstack`.

- [ ] **Шаг 3: Реализовать JSON parsing without silent defaults**

`OpenStackClient.json` must:

1. append `-f json` only when absent;
2. call `ReadOnlyRunner.run` with argv;
3. raise `ProbeFailed` on command failure;
4. raise `ProbeFailed` with reason `invalid-json` on parse failure;
5. return `(payload, evidence_dict)`; never return `{}` or `[]` after an error.

- [ ] **Шаг 4: Добавить target profile fixture test**

Fixture должна покрывать:

```json
{
  "release": "2025.1",
  "distribution": "vanilla",
  "nova_api_db_version": "b30f573d3377",
  "nova_cell_db_version": "b30f573d3377",
  "neutron_heads": ["2025.1-expand", "2025.1-contract"],
  "cinder_db_version": "2025.1",
  "glance_db_version": "2025.1",
  "container_images": {
    "nova_api": "quay.io/openstack.kolla/nova-api:2025.1-ubuntu-noble"
  }
}
```

Проверить, что distribution, отличная от `vanilla`, или release, отличная от `2025.1`, добавляет blocker в результат target profile.

Fixture и результат также должны содержать `online_migration_evidence` для Nova и Cinder. Это предоставленный оператором timestamped artifact, доказывающий, что соответствующая команда ранее завершилась с кодом `0`; collector эту команду никогда не запускает. Отсутствующее или устаревшее evidence даёт `UNKNOWN`, а evidence с ненулевым кодом — `BLOCKED`.

- [ ] **Шаг 5: Запустить focused and full tests**

Команда: `python3 -m unittest tests.test_live_discovery_openstack -v`

Ожидается: adapter and profile tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

- [ ] **Шаг 6: Зафиксировать Task 3**

```bash
git add scripts/live_discovery/openstack.py tests/test_live_discovery_openstack.py tests/fixtures/live_discovery/openstack-command-results.json
git commit -m "feat: collect canonical epoxy target profile"
```

### Задача 4: Поиск корневых объектов Nova

**Файлы:**

- Create: `scripts/live_discovery/nova.py`
- Create: `tests/test_live_discovery_nova.py`
- Create: `tests/fixtures/live_discovery/nova-source.json`
- Create: `tests/fixtures/live_discovery/nova-target.json`

**Интерфейсы:**

- Consumes: `OpenStackClient`, contract types.
- Produces: `NovaCollector(client, side).collect(rehome_host) -> CollectorResult`.
- Produces node kinds: `compute_host`, `nova_service`, `compute_node`, `instance`, `project`, `user`, `flavor`, `image_ref`, `cell_mapping`, `request_spec`, `placement_provider`.
- Produces required edges used by Neutron/Cinder/Glance collectors.

- [ ] **Шаг 1: Написать failing-тесты для Nova fixture test**

```python
def test_nova_collector_roots_graph_at_exact_rehome_host(self):
    result = collect_from_fixture(self.fixture, "compute-023", "source")
    instances = [node for node in result.nodes if node.kind == "instance"]
    self.assertEqual(["11111111-1111-1111-1111-111111111111"], [node.id for node in instances])
    self.assertEqual("compute-023", instances[0].facts["host"])
    required_targets = {edge.target for edge in result.edges if edge.required}
    self.assertIn("cell_mapping:cell-source", required_targets)
    self.assertIn("flavor:flavor-1", required_targets)


def test_missing_instance_mapping_is_blocker(self):
    fixture = dict(self.fixture)
    fixture["instance_mappings"] = []
    result = collect_from_fixture(fixture, "compute-023", "source")
    self.assertIn("instance mapping missing: 11111111-1111-1111-1111-111111111111", result.blockers)
```

- [ ] **Шаг 2: Проверить Nova RED**

Команда: `python3 -m unittest tests.test_live_discovery_nova -v`

Ожидается: import failure for `live_discovery.nova`.

- [ ] **Шаг 3: Реализовать exact host and UUID validation**

Collector должен использовать следующие read-only команды:

```text
openstack server list --all-projects --host <rehome_host> --long -f json
openstack server show <instance_uuid> -f json
openstack compute service list --host <rehome_host> -f json
openstack hypervisor show <rehome_host> -f json
openstack flavor show <flavor_id> -f json
openstack resource provider list --name <rehome_host> -f json
openstack resource provider allocation show <consumer_uuid> -f json
```

DB facts для `host_mappings`, `instance_mappings`, `request_specs`, `instances`, `block_device_mapping`, `instance_info_caches`, `compute_nodes` и `services` должны поступать как JSONL records, созданные запросами задачи 2. Несовпадение host, дублирование canonical service, отсутствие cell mapping или строки instance в БД является blocker.

- [ ] **Шаг 4: Запустить focused and full tests**

Команда: `python3 -m unittest tests.test_live_discovery_nova -v`

Ожидается: Nova tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

- [ ] **Шаг 5: Зафиксировать Task 4**

```bash
git add scripts/live_discovery/nova.py tests/test_live_discovery_nova.py tests/fixtures/live_discovery/nova-source.json tests/fixtures/live_discovery/nova-target.json
git commit -m "feat: discover nova rehome roots"
```

### Задача 5: Нормализация runtime-доменов, дисков и dataplane

**Файлы:**

- Create: `scripts/live_discovery/runtime.py`
- Create: `scripts/collect_live_runtime.py`
- Create: `tests/test_live_discovery_runtime.py`
- Create: `tests/fixtures/live_discovery/runtime-source.json`

**Интерфейсы:**

- Consumes: contract and runner types.
- Produces: `collect_runtime(runner, virsh_argv, network_backend) -> CollectorResult`.
- Produces: `collect_target_capabilities(runner, virsh_argv, qemu_argv) -> CollectorResult`.
- Produces: `compare_machine_types(source_types, target_types) -> list[CheckResult]`.
- Produces: `compare_runtime_to_nova(runtime_result, nova_result) -> list[CheckResult]`.
- Produces node kinds: `libvirt_domain`, `runtime_disk`, `runtime_interface`, `ovs_port`, `ovn_binding`.

- [ ] **Шаг 1: Написать failing-тесты для runtime comparison tests**

```python
def test_runtime_maps_domain_disk_and_interface_to_openstack_ids(self):
    result = collect_from_fixture(self.fixture)
    edge_pairs = {(edge.source, edge.target) for edge in result.edges}
    self.assertIn(("libvirt_domain:instance-0000002a", "volume:volume-1"), edge_pairs)
    self.assertIn(("runtime_interface:tap-port-1", "port:port-1"), edge_pairs)


def test_unmapped_running_disk_is_blocker(self):
    fixture = dict(self.fixture)
    fixture["domains"][0]["disks"].append({"target": "vdb", "source": "/unknown/disk"})
    result = collect_from_fixture(fixture)
    self.assertIn("unmapped runtime disk: instance-0000002a/vdb", result.blockers)


def test_source_machine_type_missing_on_target_is_blocker(self):
    checks = compare_machine_types(["pc-i440fx-rhel7.6.0"], ["pc-q35-9.0", "pc-i440fx-9.0"])
    self.assertTrue(any(item.status == "BLOCKED" for item in checks))
```

- [ ] **Шаг 2: Проверить runtime RED**

Команда: `python3 -m unittest tests.test_live_discovery_runtime -v`

Ожидается: import failure for `live_discovery.runtime`.

- [ ] **Шаг 3: Реализовать read-only runtime command set**

Использовать только команды в формате argv:

```text
<virsh_argv> list --uuid --name
<virsh_argv> dominfo <domain>
<virsh_argv> dumpxml <domain> --security-info
<virsh_argv> domblklist <domain> --details
<virsh_argv> domiflist <domain>
ovs-vsctl --format=json list Interface
ovs-vsctl --format=json list Port
ovn-sbctl --format=json list Port_Binding
<target_virsh_argv> version
<target_virsh_argv> domcapabilities
<target_qemu_argv> -machine help
```

Перед сохранением evidence редактировать XML-элементы `<secret>`. UUID instance извлекать из libvirt metadata/name, UUID port — из target dev/OVS external IDs. Не вызывать `virsh shutdown`, `destroy`, `detach-*` и другие lifecycle-команды.

Target capability probes запускать на `target_reference_compute`, не стартуя domain. Отсутствие поддержки machine type или disk bus любого запущенного source domain является blocker.

- [ ] **Шаг 4: Добавить CLI fixture-mode smoke test**

Команда:

```bash
python3 scripts/collect_live_runtime.py \
  --fixture tests/fixtures/live_discovery/runtime-source.json \
  --side source \
  --out /tmp/live-runtime-result.json
```

Ожидается: exit `0`; output JSON has schema version `openstack-rehome-live-discovery/v1alpha1` and at least one `libvirt_domain` node.

- [ ] **Шаг 5: Запустить full tests and commit**

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

```bash
git add scripts/live_discovery/runtime.py scripts/collect_live_runtime.py tests/test_live_discovery_runtime.py tests/fixtures/live_discovery/runtime-source.json
git commit -m "feat: collect rehome runtime graph"
```

### Задача 6: Коллектор зависимостей Neutron и готовности OVS/OVN

**Файлы:**

- Create: `scripts/live_discovery/neutron.py`
- Create: `tests/test_live_discovery_neutron.py`
- Create: `tests/fixtures/live_discovery/neutron-ovs-source.json`
- Create: `tests/fixtures/live_discovery/neutron-ovs-target.json`
- Create: `tests/fixtures/live_discovery/neutron-ovn-target.json`

**Интерфейсы:**

- Consumes: Nova instance IDs, port IDs and network IDs; runtime nodes; schema capabilities.
- Produces: `NeutronCollector(client, side, schema).collect(port_ids) -> CollectorResult`.
- Produces node kinds: `port`, `network`, `subnet`, `segment`, `ml2_binding`, `binding_level`, `security_group`, `qos_policy`, `trunk`, `router`, `floating_ip`, `address_group`, `network_agent`.

- [ ] **Шаг 1: Написать failing-тесты для OVS dependency tests**

```python
def test_ovs_port_requires_binding_level_and_matching_segment(self):
    result = collect_from_fixture(self.source_fixture, ["port-1"])
    required = {(edge.source, edge.target, edge.relation) for edge in result.edges if edge.required}
    self.assertIn(("port:port-1", "binding_level:port-1:compute-023:0", "has_binding_level"), required)
    self.assertIn(("binding_level:port-1:compute-023:0", "segment:segment-1", "uses_segment"), required)


def test_missing_target_segment_blocks(self):
    result = compare_source_target(self.source_fixture, self.target_without_segment)
    self.assertIn("target segment missing for port port-1", result.blockers)
```

- [ ] **Шаг 2: Проверить Neutron RED**

Команда: `python3 -m unittest tests.test_live_discovery_neutron -v`

Ожидается: import failure for `live_discovery.neutron`.

- [ ] **Шаг 3: Реализовать capability-driven dependency expansion**

Для каждого выбранного port собрать API fields и включать DB family только если таблица существует, а строки ссылаются на выбранные UUID. Точный набор families:

```python
OPTIONAL_TABLE_FAMILIES = {
    "allowed_address_pairs": ["allowedaddresspairs"],
    "dns_dhcp": ["portdnses", "dnsnameservers", "extradhcpopts"],
    "qos": ["qos_port_policy_bindings", "qos_network_policy_bindings", "qos_fip_policy_bindings", "qos_policies"],
    "trunk": ["trunks", "subports"],
    "l3": ["routers", "routerports", "routerroutes", "floatingips", "portforwardings"],
    "address_groups": ["address_groups", "address_associations", "addressgrouprbacs"],
}
```

Основные таблицы всегда проверяются для выбранных UUID: `ports`, `ipallocations`, `networks`, `subnets`, `networksegments`, `ml2_port_bindings`, `ml2_distributed_port_bindings`, `ml2_port_binding_levels`, `securitygroups`, `securitygrouprules`, `securitygroupportbindings`.

- [ ] **Шаг 4: Реализовать target compatibility checks**

Сравнение target должно требовать точные UUID port/network, если metadata уже существует, и единственный target segment, соответствующий `(network_type, physical_network, segmentation_id)`. Для `network_backend=ovs` сравниваются OVS bridges/ports, а для `network_backend=ovn` — OVN chassis/logical bindings. Неподдерживаемый backend возвращает `UNKNOWN`, а не пустой результат.

- [ ] **Шаг 5: Запустить OVS and OVN fixture tests**

Команда: `python3 -m unittest tests.test_live_discovery_neutron -v`

Ожидается: OVS/OVN dependency and missing-segment tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

- [ ] **Шаг 6: Зафиксировать Task 6**

```bash
git add scripts/live_discovery/neutron.py tests/test_live_discovery_neutron.py tests/fixtures/live_discovery/neutron-*.json
git commit -m "feat: discover neutron rehome dependencies"
```

### Задача 7: Метаданные Cinder и готовность backing storage

**Файлы:**

- Create: `scripts/live_discovery/cinder.py`
- Create: `scripts/live_discovery/storage.py`
- Create: `tests/test_live_discovery_cinder.py`
- Create: `tests/test_live_discovery_storage.py`
- Create: `tests/fixtures/live_discovery/cinder-source.json`
- Create: `tests/fixtures/live_discovery/cinder-target.json`

**Интерфейсы:**

- Consumes: Nova BDM volume IDs, Cinder API/DB facts, schema capabilities and storage probe config.
- Produces: `CinderCollector(client, side, schema).collect(volume_ids) -> CollectorResult`.
- Produces: `probe_storage(kind, resource, runner) -> CheckResult` for `nfs`, `rbd`, `lvm`.
- Produces node kinds: `volume`, `volume_attachment`, `volume_type`, `cinder_service`, `storage_backend`, `encryption_key_ref`, `snapshot`.

- [ ] **Шаг 1: Написать failing-тесты для Cinder graph tests**

```python
def test_encrypted_volume_requires_type_service_attachment_and_key(self):
    result = collect_from_fixture(self.source_fixture, ["volume-1"])
    targets = {edge.target for edge in result.edges if edge.source == "volume:volume-1" and edge.required}
    self.assertEqual(
        {"volume_attachment:attachment-1", "volume_type:type-1", "cinder_service:service-1", "encryption_key_ref:key-1", "storage_backend:nfs-1"},
        targets,
    )


def test_missing_encryption_key_is_blocker(self):
    fixture = dict(self.source_fixture)
    fixture["volumes"][0]["encryption_key_id"] = None
    result = collect_from_fixture(fixture, ["volume-1"])
    self.assertIn("encrypted volume volume-1 has no key UUID", result.blockers)
```

- [ ] **Шаг 2: Проверить Cinder RED**

Команда: `python3 -m unittest tests.test_live_discovery_cinder -v`

Ожидается: import failure for `live_discovery.cinder`.

- [ ] **Шаг 3: Реализовать Cinder API and DB dependency collection**

Использовать read-only API команды:

```text
openstack volume show <volume_uuid> -f json
openstack volume attachment show <attachment_uuid> -f json
openstack volume type show <volume_type_uuid> -f json
openstack volume service list --long -f json
openstack volume snapshot show <snapshot_uuid> -f json
openstack secret get <encryption_key_uuid> -f json
```

Вызов Barbican читает только metadata; нельзя добавлять `--payload`. Ответ 404/403 для обязательного encryption key даёт `BLOCKED`, а отсутствие endpoint key service — `UNKNOWN`.

Собрать DB rows для `volumes`, `volume_attachment`, `volume_types`, `volume_type_extra_specs`, `quality_of_service_specs`, `services`, `encryption`, `snapshots`, families метаданных volume и group/source dependencies. Явно выдать target normalizations для `service_uuid`, `volume_type_id`, `host` и `cluster_name`.

- [ ] **Шаг 4: Написать failing-тесты для storage probe tests**

```python
def test_nfs_probe_uses_stat_without_mounting(self):
    runner = RecordingRunner(stdout='{"size":1073741824}')
    check = probe_storage("nfs", {"path": "/srv/cinder/volume-volume-1"}, runner)
    self.assertEqual("PASS", check.status)
    self.assertEqual(["stat", "--format", "%s", "/srv/cinder/volume-volume-1"], runner.commands[0])


def test_unknown_storage_driver_is_unknown(self):
    check = probe_storage("vendor-array-x", {"id": "volume-1"}, RecordingRunner())
    self.assertEqual("UNKNOWN", check.status)
```

- [ ] **Шаг 5: Реализовать non-mutating storage probes**

Использовать только:

```text
NFS/file: stat --format %s <validated_path>
RBD: rbd info --format json <validated_pool>/<validated_image>
LVM: lvs --reportformat json --units b --nosuffix <validated_vg>/<validated_lv>
```

Пути и имена должны выводиться из проверенных inventory facts и соответствовать строгим allowlists. Не монтировать NFS, не map-ить RBD, не активировать LV и не создавать новые attachments. Несовпадение размера и нечитаемые backing objects являются blockers.

- [ ] **Шаг 6: Добавить redaction tests**

Проверить, что `connection_info`, CHAP secrets, auth tokens и connector credentials заменены на `[REDACTED]` в обычных артефактах, а проверка сохраняет только driver type, число targets и multipath boolean.

- [ ] **Шаг 7: Запустить focused/full tests and commit**

Команда: `python3 -m unittest tests.test_live_discovery_cinder tests.test_live_discovery_storage -v`

Ожидается: all focused tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

```bash
git add scripts/live_discovery/cinder.py scripts/live_discovery/storage.py tests/test_live_discovery_cinder.py tests/test_live_discovery_storage.py tests/fixtures/live_discovery/cinder-source.json tests/fixtures/live_discovery/cinder-target.json
git commit -m "feat: discover cinder backing readiness"
```

### Задача 8: Метаданные и хранилища Glance, однобайтовая проба данных

**Файлы:**

- Create: `scripts/live_discovery/glance.py`
- Create: `scripts/live_discovery/image_data.py`
- Create: `tests/test_live_discovery_glance.py`
- Create: `tests/test_live_discovery_image_data.py`
- Create: `tests/fixtures/live_discovery/glance-source.json`
- Create: `tests/fixtures/live_discovery/glance-target.json`

**Интерфейсы:**

- Consumes: Nova image refs, Cinder volume image metadata, OpenStackClient.
- Produces: `GlanceCollector(client, side).collect(image_requirements) -> CollectorResult`.
- Produces: `probe_image_data(url, token, expected_size, opener=None) -> CheckResult`.
- Produces node kinds: `image`, `image_member`, `glance_store`, `image_location`.

- [ ] **Шаг 1: Написать failing-тесты для image requirement tests**

```python
def test_boot_from_image_requires_target_image_and_data(self):
    result = collect_from_fixture(self.source_fixture, {"image-1": {"required": True, "reason": "local_root"}})
    image = next(node for node in result.nodes if node.kind == "image")
    self.assertTrue(image.facts["required_for_rehome"])
    self.assertIn("glance_store:file", {edge.target for edge in result.edges if edge.required})


def test_volume_backed_historical_image_is_warning_when_bdm_proves_no_local_root(self):
    result = collect_from_fixture(self.source_fixture, {"image-1": {"required": False, "reason": "volume_image_metadata"}})
    self.assertFalse(result.blockers)
    self.assertTrue(any(check.status == "WARN" for check in result.checks))
```

- [ ] **Шаг 2: Проверить Glance RED**

Команда: `python3 -m unittest tests.test_live_discovery_glance -v`

Ожидается: import failure for `live_discovery.glance`.

- [ ] **Шаг 3: Реализовать metadata/store collection**

Использовать:

```text
openstack image show <image_uuid> -f json
openstack image member list <image_uuid> -f json
GET <image_endpoint>/v2/info/stores
```

Классифицировать `active` как metadata-ready; `queued`, `saving`, `killed`, `deleted`, `pending_delete`, `deactivated`, `uploading` и `importing` не являются data-ready. Предпочитать `os_hash_algo`/`os_hash_value`, сохраняя legacy checksum только как вторичное evidence.

- [ ] **Шаг 4: Написать failing-тесты для one-byte Range probe test**

```python
def test_image_probe_requests_one_byte_and_accepts_partial_content(self):
    opener = RecordingOpener(status=206, headers={"Content-Range": "bytes 0-0/1024", "Content-Length": "1"}, body=b"x")
    check = probe_image_data("https://glance/v2/images/image-1/file", "token-value", 1024, opener=opener)
    self.assertEqual("PASS", check.status)
    self.assertEqual("bytes=0-0", opener.request.headers["Range"])
    self.assertNotIn("token-value", check.reason)
```

- [ ] **Шаг 5: Реализовать urllib Range GET without persisting token**

`probe_image_data` must issue `GET` with `Range: bytes=0-0` and `X-Auth-Token`, read at most one byte, and accept:

- `206` with total size matching `expected_size`;
- `200` as `WARN` after reading at most one byte and immediately closing, because the server ignored the Range request;
- `204` as `BLOCKED` for required images;
- `403/404/416` as `BLOCKED`;
- transport error as `UNKNOWN`.

Token нельзя сохранять в `CheckResult`, evidence argv, тексте исключения или fixtures.

- [ ] **Шаг 6: Запустить focused/full tests and commit**

Команда: `python3 -m unittest tests.test_live_discovery_glance tests.test_live_discovery_image_data -v`

Ожидается: all focused tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

```bash
git add scripts/live_discovery/glance.py scripts/live_discovery/image_data.py tests/test_live_discovery_glance.py tests/test_live_discovery_image_data.py tests/fixtures/live_discovery/glance-source.json tests/fixtures/live_discovery/glance-target.json
git commit -m "feat: discover glance image readiness"
```

### Задача 9: Сборка графа, проверка целостности и verdict

**Файлы:**

- Create: `scripts/live_discovery/graph.py`
- Create: `scripts/live_discovery/verdict.py`
- Create: `tests/test_live_discovery_graph.py`
- Create: `tests/test_live_discovery_verdict.py`

**Интерфейсы:**

- Consumes: all `CollectorResult` payloads and schema mapping.
- Produces: `assemble_graph(results) -> dict`.
- Produces: `validate_graph(graph) -> list[CheckResult]`.
- Produces: `compute_verdict(graph, checks, mapping) -> dict`.

- [ ] **Шаг 1: Написать failing-тесты для graph integrity tests**

```python
def test_required_edge_without_target_node_is_unknown(self):
    graph = assemble_graph([collector_with_missing_volume_node()])
    checks = validate_graph(graph)
    self.assertTrue(any(item.status == "UNKNOWN" and "volume:volume-1" in item.reason for item in checks))


def test_duplicate_node_with_conflicting_facts_is_blocker(self):
    graph = assemble_graph([source_port("port-1", "aa:bb"), source_port("port-1", "cc:dd")])
    checks = validate_graph(graph)
    self.assertTrue(any(item.status == "BLOCKED" and "conflicting facts" in item.reason for item in checks))
```

- [ ] **Шаг 2: Проверить graph RED**

Команда: `python3 -m unittest tests.test_live_discovery_graph -v`

Ожидается: import failure for `live_discovery.graph`.

- [ ] **Шаг 3: Реализовать deterministic merge and validation**

Сортировать nodes по `(side, kind, id)`, edges по `(source, target, relation)`, checks по `check_id`. Одинаковые nodes объединять; конфликтующие facts добавляют проверку `BLOCKED`. Каждый required edge должен разрешаться в node соответствующей стороны или документированный внешний reference node.

- [ ] **Шаг 4: Написать failing-тесты для verdict tests**

```python
def test_unknown_is_fail_closed(self):
    verdict = compute_verdict(empty_graph(), [CheckResult("probe", "UNKNOWN", "timeout")], clean_mapping())
    self.assertEqual("UNKNOWN", verdict["verdict"])
    self.assertEqual(2, verdict["exit_code"])


def test_blocked_has_precedence_over_unknown_and_warning(self):
    checks = [
        CheckResult("warn", "WARN", "historical image"),
        CheckResult("unknown", "UNKNOWN", "store probe unavailable"),
        CheckResult("blocked", "BLOCKED", "target segment missing"),
    ]
    verdict = compute_verdict(empty_graph(), checks, clean_mapping())
    self.assertEqual("BLOCKED", verdict["verdict"])
    self.assertEqual(3, verdict["exit_code"])
```

- [ ] **Шаг 5: Реализовать exact verdict precedence**

```python
EXIT_CODES = {
    "READY": 0,
    "READY_WITH_WARNINGS": 0,
    "UNKNOWN": 2,
    "BLOCKED": 3,
}

PRECEDENCE = ["BLOCKED", "UNKNOWN", "WARN", "PASS"]
```

Любой mapping blocker даёт `BLOCKED`. Отсутствие checks, instances или обязательного service collector даёт `UNKNOWN`.

- [ ] **Шаг 6: Запустить focused/full tests and commit**

Команда: `python3 -m unittest tests.test_live_discovery_graph tests.test_live_discovery_verdict -v`

Ожидается: focused tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

```bash
git add scripts/live_discovery/graph.py scripts/live_discovery/verdict.py tests/test_live_discovery_graph.py tests/test_live_discovery_verdict.py
git commit -m "feat: assemble fail-closed readiness graph"
```

### Задача 10: Коллектор control plane, локальный assembler и рендеринг артефактов

**Файлы:**

- Create: `scripts/live_discovery/render.py`
- Create: `scripts/collect_live_control.py`
- Create: `scripts/assemble_live_discovery.py`
- Create: `tests/test_live_discovery_render.py`
- Create: `tests/test_live_discovery_cli.py`
- Create: `tests/fixtures/live_discovery/full-run/`

**Интерфейсы:**

- Consumes: Tasks 1–9 public interfaces.
- Produces source/target side artifacts from `collect_live_control.py`.
- Produces final artifact directory and process exit code from `assemble_live_discovery.py`.

- [ ] **Шаг 1: Написать failing-тесты для renderer tests**

```python
def test_markdown_contains_verdict_blockers_and_resource_counts(self):
    markdown = render_markdown(sample_report())
    self.assertIn("# Live Discovery Readiness Report", markdown)
    self.assertIn("Verdict: `BLOCKED`", markdown)
    self.assertIn("target segment missing", markdown)
    self.assertIn("Instances: `1`", markdown)


def test_normal_artifacts_do_not_contain_sensitive_values(self):
    rendered = render_json(sample_report_with_secret("chap-secret-value"))
    self.assertNotIn("chap-secret-value", rendered)
    self.assertIn("[REDACTED]", rendered)
```

- [ ] **Шаг 2: Проверить renderer RED**

Команда: `python3 -m unittest tests.test_live_discovery_render -v`

Ожидается: import failure for `live_discovery.render`.

- [ ] **Шаг 3: Реализовать exact artifact set**

`write_artifacts(out_dir, graph, verdict, schema_capabilities, schema_mapping, evidence)` must atomically write:

```text
resource-graph.json
resource-graph.yml
readiness-report.json
readiness-report.md
schema-capabilities.json
schema-mapping.json
uuid-filters.json
evidence-index.json
sensitive/evidence.json
```

Использовать временный sibling-каталог с последующим `os.replace`. Создать `sensitive/` с mode `0700` и `sensitive/evidence.json` с mode `0600`; при отсутствии sensitive evidence файл не создавать. Небольшой YAML renderer реализовать по существующему stdlib-паттерну проекта, не добавляя PyYAML.

- [ ] **Шаг 4: Написать smoke-тесты CLI на fixtures**

```python
def test_assembler_returns_blocked_exit_code_and_writes_report(self):
    proc = subprocess.run(
        [sys.executable, "scripts/assemble_live_discovery.py", "--fixture-dir", str(FIXTURE_DIR), "--out-dir", str(self.out_dir)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    self.assertEqual(3, proc.returncode)
    self.assertTrue((self.out_dir / "readiness-report.md").is_file())
```

- [ ] **Шаг 5: Реализовать control and assembler CLIs**

`collect_live_control.py` is deliberately two-phase so API-derived UUID filters exist before DB reads.

Аргументы фазы `api`:

```text
--phase api
--side {source,target}
--rehome-host HOST
--cloud CLOUD
--clouds-file PATH
--container NAME
--out PATH
--fixture PATH
```

Она записывает `api-result.json`, `uuid-filters.json` и `db-query-plan.json`. Каждый запрос плана — JSON-object `SELECT` из задачи 2, ограниченный этими UUID.

Аргументы фазы `combine`:

```text
--phase combine
--side {source,target}
--api-result PATH
--db-jsonl-dir PATH
--information-schema PATH
--schema-policy PATH
--out PATH
--fixture PATH
```

Она отказывается работать, если обязательный файл `.rc` отсутствует или содержит ненулевой код, строка JSONL некорректна либо для запланированного запроса нет результата.

`assemble_live_discovery.py` arguments:

```text
--source-control PATH
--target-control PATH
--runtime PATH
--schema-policy PATH
--out-dir PATH
--fixture-dir PATH
```

Аргументы fixture взаимоисключаются с live-аргументами. CLI должен возвращать точный exit code verdict из задачи 9.

- [ ] **Шаг 6: Запустить full fixture smoke and tests**

Команда:

```bash
python3 scripts/assemble_live_discovery.py \
  --fixture-dir tests/fixtures/live_discovery/full-run \
  --out-dir /tmp/openstack-rehome-live-discovery-smoke
```

Ожидается: the ready fixture exits `0`; the blocked fixture exits `3`; both write the complete artifact set.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

- [ ] **Шаг 7: Зафиксировать Task 10**

```bash
git add scripts/live_discovery/render.py scripts/collect_live_control.py scripts/assemble_live_discovery.py tests/test_live_discovery_render.py tests/test_live_discovery_cli.py tests/fixtures/live_discovery/full-run
git commit -m "feat: render live discovery artifacts"
```

### Задача 11: Read-only orchestration Ansible и fail-closed gate

**Файлы:**

- Create: `playbooks/02b-discover-live-resource-graph.yml`
- Create: `playbooks/tasks/collect-live-schema-service.yml`
- Create: `playbooks/tasks/collect-live-db-jsonl-service.yml`
- Create: `tests/test_live_discovery_playbook.py`
- Modify: `group_vars/all.yml`
- Modify: `inventory/hosts.yml`
- Modify: `inventory/lab-os1-to-os2.yml`

**Интерфейсы:**

- Consumes: Task 10 CLIs and existing inventory groups `source_control`, `target_control`, `rehome_compute`.
- Produces: `{{ local_artifact_dir }}/live-discovery/{{ live_discovery_run_id }}/readiness-report.json` and companion artifacts.

- [ ] **Шаг 1: Написать failing-тесты для structural playbook test**

```python
class LiveDiscoveryPlaybookTests(unittest.TestCase):
    def test_playbook_is_read_only_and_cleans_credentials_in_always_blocks(self):
        text = (ROOT / "playbooks/02b-discover-live-resource-graph.yml").read_text()
        self.assertIn("collect_live_control.py", text)
        self.assertIn("collect_live_runtime.py", text)
        self.assertIn("assemble_live_discovery.py", text)
        self.assertIn("always:", text)
        self.assertIn("state: absent", text)
        for forbidden in ("online_data_migrations", "openstack server set", "mysql <", "docker stop", "systemctl stop"):
            self.assertNotIn(forbidden, text)

    def test_unknown_or_blocked_assembler_exit_fails_play(self):
        text = (ROOT / "playbooks/02b-discover-live-resource-graph.yml").read_text()
        self.assertIn("failed_when: live_discovery_assemble.rc not in [0]", text)
```

- [ ] **Шаг 2: Проверить playbook RED**

Команда: `python3 -m unittest tests.test_live_discovery_playbook -v`

Ожидается: `FileNotFoundError` for the new playbook.

- [ ] **Шаг 3: Добавить generic variables**

Добавить в `group_vars/all.yml`:

```yaml
live_discovery_enabled: true
live_discovery_run_id: ""
live_discovery_target_profile: vanilla-openstack-2025.1-epoxy
live_discovery_remote_dir: "{{ rehome_stage_dir }}/live-discovery"
live_discovery_local_dir: "{{ local_artifact_dir }}/live-discovery"
live_discovery_schema_policy_file: "{{ playbook_dir }}/../inventory/live-discovery-schema-policy.json"
live_discovery_mysql_json_argv: [mysql, --batch, --raw, --skip-column-names]
live_discovery_storage_backends: {}
live_discovery_source_probe_config_file_local: ""
live_discovery_target_probe_config_file_local: ""
live_discovery_phase_hmac_key_file_local: ""
live_discovery_source_glance_token_file_local: ""
live_discovery_target_glance_token_file_local: ""
live_discovery_source_cinder_sensitive_evidence_file_local: ""
live_discovery_target_cinder_sensitive_evidence_file_local: ""
live_discovery_target_online_migration_evidence_file_local: ""
live_discovery_source_virsh_argv: [virsh]
live_discovery_target_virsh_argv: [virsh]
live_discovery_target_qemu_argv: [qemu-system-x86_64]
live_discovery_glance_range_probe_enabled: true
live_discovery_fail_on_not_ready: true
```

Lab inventory должен задавать команды Kolla, `network_backend: ovs` и фактические
typed storage backend map with source/target probe delegates. NFS is only the
current lab example: NFS/file, RBD and LVM have read-only probes; iSCSI, Fibre
Channel и vendor backends остаются явно `UNKNOWN` без reviewed
backend-specific probe. Generic inventory leaves the backend map empty, which
also yields `UNKNOWN` for required storage evidence.

- [ ] **Шаг 4: Реализовать seven-play orchestration**

Фактическая последовательность, зависящая от данных, содержит ровно семь plays:

1. localhost setup, protected-input freeze, owner lock and frozen run ID;
2. source controller API/schema acquisition, public verify-before-SQL and UUID-scoped JSONL collection;
3. target controller API/schema acquisition, public verify-before-SQL and UUID-scoped JSONL collection;
4. re-home compute domain/disk/interface/dataplane collection;
5. target reference compute libvirt/QEMU capability collection;
6. source and target Cinder/Glance probes on typed-map delegates, signed API refresh, exact phase-triplet return and both controller combines;
7. localhost assembly, artifact publication and owner completion; only assembler rc `0` is accepted.

Итого: plays 2-3 собирают API/schema/DB evidence, play 5 предоставляет target
capabilities, play 6 performs both probe families plus signed refresh and both
combines, and play 7 performs final assembly.

`collect-live-schema-service.yml` reuses the existing service-user credential model but writes a run-local information-schema artifact. `collect-live-db-jsonl-service.yml` accepts only generated `.sql` files, runs `python3 -m live_discovery.mysql_json --validate-sql <file>` before MySQL, records `.jsonl`/`.rc`/protected `.stderr` and creates a query-specific acquisition sidecar through the exact-reviewed `live_discovery.db_evidence` argv. Combine requires the sidecar, preserves its real rc/timestamp/digests, and emits `BLOCKED` for a failed SELECT instead of fabricating success metadata.

Сбор профиля controller также фиксирует `nova-manage api_db version`, `nova-manage db version`, `neutron-db-manage current --verbose`, `cinder-manage db version`, строки Glance Alembic и image/digest facts из `docker inspect`. Разрешены только команды version/current/show/inspect.

Каждая команда сбора имеет `changed_when: false`. Задачи создания каталогов, fetch и archive могут сообщать changed. Sensitive-задачи используют `no_log: true`.

- [ ] **Шаг 5: Запустить structural and syntax tests**

Команда: `python3 -m unittest tests.test_live_discovery_playbook -v`

Ожидается: tests `OK`.

Команда:

```bash
ANSIBLE_LOCAL_TEMP=/tmp/openstack-rehome-live-discovery-ansible \
ansible-playbook -i inventory/hosts.yml --syntax-check playbooks/02b-discover-live-resource-graph.yml
```

Ожидается: exit `0`, playbook name printed.

- [ ] **Шаг 6: Запустить full tests and commit**

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

```bash
git add playbooks/02b-discover-live-resource-graph.yml playbooks/tasks/collect-live-schema-service.yml playbooks/tasks/collect-live-db-jsonl-service.yml group_vars/all.yml inventory/hosts.yml inventory/lab-os1-to-os2.yml tests/test_live_discovery_playbook.py
git commit -m "feat: orchestrate live cluster discovery"
```

### Задача 12: Полное обновление документации

**Файлы:**

- Modify: `README.md`
- Modify: `operator-inputs-ru.md`
- Modify: `playbook-logic-ru.md`
- Modify: `lab-rehome-runbook-ru.md`
- Modify: `docs/lab-topology-ru.md`
- Modify: `neutron-rehome-behavior-ru.md`
- Create: `cinder-rehome-readiness-ru.md`
- Create: `glance-rehome-readiness-ru.md`
- Create: `docs/live-discovery-artifacts-ru.md`
- Create: `docs/live-discovery-data-flow-ru.md`
- Modify: `tests/test_playbook_logic_doc.py`
- Modify: `tests/test_lab_topology_doc.py`
- Create: `tests/test_live_discovery_docs.py`

**Интерфейсы:**

- Documents exact Task 11 command, variables, artifacts, verdict and exclusion scope.
- No later task depends on undocumented behavior.

- [ ] **Шаг 1: Написать failing-тесты для documentation coverage test**

```python
class LiveDiscoveryDocumentationTests(unittest.TestCase):
    def test_readme_orders_discovery_before_database_import(self):
        text = (ROOT / "README.md").read_text()
        discovery = text.index("02b-discover-live-resource-graph.yml")
        import_plan = text.index("04b-plan-db-metadata-import.yml")
        self.assertLess(discovery, import_plan)

    def test_service_docs_cover_required_readiness(self):
        cinder = (ROOT / "cinder-rehome-readiness-ru.md").read_text()
        glance = (ROOT / "glance-rehome-readiness-ru.md").read_text()
        neutron = (ROOT / "neutron-rehome-behavior-ru.md").read_text()
        self.assertIn("service_uuid", cinder)
        self.assertIn("backing object", cinder)
        self.assertIn("Range: bytes=0-0", glance)
        self.assertIn("os_hash_value", glance)
        self.assertIn("ml2_port_binding_levels", neutron)
        self.assertIn("subports", neutron)

    def test_docs_exclude_masakari_and_drs(self):
        text = (ROOT / "docs/live-discovery-artifacts-ru.md").read_text()
        self.assertIn("Masakari", text)
        self.assertIn("DRS", text)
        self.assertIn("не входят", text)
```

- [ ] **Шаг 2: Проверить documentation RED**

Команда: `python3 -m unittest tests.test_live_discovery_docs -v`

Ожидается: missing documentation files or missing execution-order references.

- [ ] **Шаг 3: Обновить operator-facing documentation**

Документировать эту точную команду перед всеми фазами DB import/cutover:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/02b-discover-live-resource-graph.yml
```

Документировать verdict и exit codes:

```text
READY=0
READY_WITH_WARNINGS=0
UNKNOWN=2
BLOCKED=3
```

Указать, что live target vanilla Epoxy является canonical; schema dumps служат только примерами; `UNKNOWN` блокирует продолжение; online data migrations не запускаются; Masakari/DRS исключены.

- [ ] **Шаг 4: Добавить service readiness documents**

`cinder-rehome-readiness-ru.md` must cover attachments, types, QoS, `service_uuid`, encryption keys, snapshots, shared/non-shared storage, NFS/RBD/LVM probes and redaction.

`glance-rehome-readiness-ru.md` must cover image requirement classification, status, stores, members/visibility, secure hashes and one-byte Range GET.

`neutron-rehome-behavior-ru.md` must cover core bindings plus allowed-address-pairs, DNS/DHCP, QoS, trunks/subports, router/FIP/port forwarding, address groups and OVS/OVN runtime evidence.

- [ ] **Шаг 5: Добавить artifact and data-flow documents**

`docs/live-discovery-artifacts-ru.md` must define every JSON/YAML/Markdown file, contract version, evidence index, sensitive directory and retention rule.

`docs/live-discovery-data-flow-ru.md` must include a Mermaid graph from Ansible runner to source control, target control, compute, storage/image probes and local assembler.

- [ ] **Шаг 6: Запустить documentation and full tests**

Команда: `python3 -m unittest tests.test_live_discovery_docs tests.test_playbook_logic_doc tests.test_lab_topology_doc -v`

Ожидается: documentation tests `OK`.

Команда: `python3 -m unittest discover -s tests`

Ожидается: suite `OK`.

- [ ] **Шаг 7: Зафиксировать Task 12**

```bash
git add README.md operator-inputs-ru.md playbook-logic-ru.md lab-rehome-runbook-ru.md docs/lab-topology-ru.md neutron-rehome-behavior-ru.md cinder-rehome-readiness-ru.md glance-rehome-readiness-ru.md docs/live-discovery-artifacts-ru.md docs/live-discovery-data-flow-ru.md tests/test_playbook_logic_doc.py tests/test_lab_topology_doc.py tests/test_live_discovery_docs.py
git commit -m "docs: document live discovery workflow"
```

### Задача 13: Аудит мутаций, полная проверка и передача ветки

**Файлы:**

- Create: `tests/test_live_discovery_mutation_audit.py`
- Modify: `README.md` only if verification commands are not already listed.

**Интерфейсы:**

- Consumes all implementation and documentation tasks.
- Produces final evidence that the branch is read-only, tested and reviewable.

- [ ] **Шаг 1: Написать mutation audit test**

```python
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.runner import MutationRejected, ReadOnlyRunner


class LiveDiscoveryMutationAuditTests(unittest.TestCase):
    def test_collectors_cannot_bypass_the_read_only_runner(self):
        paths = list((ROOT / "scripts/live_discovery").glob("*.py"))
        paths = [path for path in paths if path.name not in {"runner.py", "image_data.py"}]
        paths.extend([ROOT / "scripts/collect_live_control.py", ROOT / "scripts/collect_live_runtime.py", ROOT / "scripts/assemble_live_discovery.py"])
        for path in paths:
            text = path.read_text()
            self.assertNotIn("import subprocess", text, str(path))
            self.assertNotIn("subprocess.", text, str(path))

    def test_live_discovery_playbook_contains_no_mutation_commands(self):
        combined = (ROOT / "playbooks/02b-discover-live-resource-graph.yml").read_text()
        forbidden = [
            "online_data_migrations", "server set", "port set", "volume set",
            "image save", "docker stop", "systemctl stop", "virsh destroy",
            "INSERT INTO", "UPDATE `", "DELETE FROM", "ALTER TABLE", "DROP TABLE",
        ]
        for token in forbidden:
            self.assertNotIn(token, combined, token)

    def test_runner_denies_every_forbidden_operation_class(self):
        runner = ReadOnlyRunner()
        for command in (
            ["openstack", "server", "set", "instance-1"],
            ["openstack", "image", "save", "image-1"],
            ["nova-manage", "db", "online_data_migrations"],
        ):
            with self.assertRaises(MutationRejected):
                runner.run(command, "mutation-audit")
```

- [ ] **Шаг 2: Запустить mutation audit**

Команда: `python3 -m unittest tests.test_live_discovery_mutation_audit -v`

Ожидается: test `OK`.

- [ ] **Шаг 3: Запустить complete unit suite**

Команда: `python3 -m unittest discover -s tests -v`

Ожидается: all tests `OK`, zero failures/errors.

- [ ] **Шаг 4: Проверить синтаксис every top-level playbook**

Команда:

```bash
rc=0
for f in playbooks/[0-9][0-9]*.yml; do
  ANSIBLE_LOCAL_TEMP=/tmp/openstack-rehome-live-discovery-ansible \
    ansible-playbook -i inventory/hosts.yml --syntax-check "$f" || rc=1
done
exit "$rc"
```

Ожидается: exit `0`; all existing playbooks plus `02b-discover-live-resource-graph.yml` pass.

- [ ] **Шаг 5: Запустить ready and blocked fixture smoke tests**

Команда:

```bash
python3 scripts/assemble_live_discovery.py \
  --fixture-dir tests/fixtures/live_discovery/full-run/ready \
  --out-dir /tmp/openstack-rehome-ready
```

Ожидается: exit `0`, verdict `READY` or `READY_WITH_WARNINGS`.

Команда:

```bash
python3 scripts/assemble_live_discovery.py \
  --fixture-dir tests/fixtures/live_discovery/full-run/blocked \
  --out-dir /tmp/openstack-rehome-blocked
```

Ожидается: exit `3`, verdict `BLOCKED`, report names the fixture blocker.

- [ ] **Шаг 6: Проверить repository hygiene**

Команда:

```bash
git diff --check
git status --short
find . -name __pycache__ -o -name '*.pyc' -o -path './artifacts/*'
```

Ожидается: no whitespace errors; only intentional tracked changes before the final commit; no generated artifacts staged.

- [ ] **Шаг 7: Зафиксировать final audit test**

```bash
git add tests/test_live_discovery_mutation_audit.py README.md
git commit -m "test: audit live discovery read-only boundary"
```

- [ ] **Шаг 8: Проверить branch diff and hand off**

Команда:

```bash
git log --oneline origin/main..HEAD
git diff --stat origin/main...HEAD
git status --short --branch
```

Ожидается: one focused commit per task, clean worktree, branch ahead of `origin/main`, no push or merge performed without explicit user request.

## Официальные источники для реализации

- OpenStack 2025.1 Epoxy releases: <https://releases.openstack.org/epoxy/>
- Nova management and migration states: <https://docs.openstack.org/nova/2025.1/cli/nova-manage.html>
- Nova database migrations: <https://docs.openstack.org/nova/2025.1/reference/database-migrations.html>
- Neutron API binding fields: <https://docs.openstack.org/api-ref/network/v2/index.html>
- Neutron Alembic wrapper: <https://docs.openstack.org/neutron/latest/contributor/alembic_migrations.html>
- Cinder volumes and attachments API: <https://docs.openstack.org/api-ref/block-storage/v3/>
- Cinder upgrades: <https://docs.openstack.org/cinder/latest/admin/upgrades.html>
- Cinder Epoxy notes and `service_uuid`: <https://docs.openstack.org/releasenotes/cinder/2025.1.html>
- Glance Image API and Range downloads: <https://docs.openstack.org/api-ref/image/v2/index.html>
