#!/usr/bin/env python3
"""Two-phase, UUID-scoped control-plane discovery transport."""

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))

from live_discovery.mysql_json import build_json_row_query, uuid_in, validate_identifier
from live_discovery.cinder import CinderCollector
from live_discovery.glance import GlanceCollector
from live_discovery.neutron import NeutronCollector
from live_discovery.nova import NovaCollector
from live_discovery.render import render_json
from live_discovery.runner import ReadOnlyRunner, validate_select_only_sql
from live_discovery.schema import parse_information_schema


API_INPUT_VERSION = "openstack-rehome-control-api-input/v1alpha1"
API_RESULT_VERSION = "openstack-rehome-control-api-result/v1alpha1"
PLAN_VERSION = "openstack-rehome-db-query-plan/v1alpha1"
BUNDLE_VERSION = "openstack-rehome-control-bundle/v1alpha1"
_MAX_FILE = 8 * 1024 * 1024
_MAX_LINES = 100_000
_MAX_QUERIES = 512


class _CombinedClient:
    """Serve only the exact API/DB evidence acquired by the two phases."""

    def __init__(self, side, api_result, records, evidence):
        self.side = side
        self._api = {}
        for item in api_result.get("openstack", []):
            if not isinstance(item, dict) or set(item) != {"command", "payload", "evidence"} or not isinstance(item["command"], list):
                raise ValueError("cached OpenStack response is invalid")
            key = tuple(item["command"])
            if key in self._api:
                raise ValueError("cached OpenStack response is duplicated")
            self._api[key] = (deepcopy(item["payload"]), deepcopy(item["evidence"]))
        self._records = records
        self._evidence = {f"{item['schema']}.{item['table']}": item for item in evidence}

    def json(self, command, evidence_id, required=True):
        del evidence_id, required
        key = tuple(command)
        if key not in self._api:
            return None, {"id": "cached-openstack-response-missing"}
        return deepcopy(self._api[key])

    def db_records(self, table, filters=None):
        matches = [key for key in self._records if key.endswith(f".{table}")]
        if len(matches) != 1:
            return [], {"evidence_id": f"{self.side}-db:unknown.{table}"}
        key = matches[0]
        evidence = deepcopy(self._evidence[key])
        if filters is not None and evidence.get("filters") != filters:
            raise ValueError("collector DB filter differs from executed query")
        return deepcopy(self._records[key]), evidence


def _dependency_ids(result, kind):
    prefix = kind + ":"
    return sorted({
        edge.target[len(prefix):]
        for edge in result.edges
        if edge.required and edge.target.startswith(prefix)
    })


def _compose_collectors(side, api_result, records, evidence, snapshot):
    client = _CombinedClient(side, api_result, records, evidence)
    results = []
    if side == "source":
        nova = NovaCollector(client, side).collect(api_result.get("rehome_host", ""))
        results.append(nova)
        port_ids = _dependency_ids(nova, "port")
        volume_ids = _dependency_ids(nova, "volume")
        image_ids = _dependency_ids(nova, "image_ref")
        project_ids = sorted({
            node.facts.get("project_id") for node in nova.nodes
            if node.kind == "instance" and isinstance(node.facts.get("project_id"), str)
        })
    else:
        port_ids = list(api_result.get("port_ids", []))
        volume_ids = list(api_result.get("volume_ids", []))
        image_ids = list(api_result.get("image_ids", []))
        project_ids = list(api_result.get("project_ids", []))
        # Target profile acquisition needs container/runtime probes not present in
        # DB JSONL phase; keep that missing capability explicit and fail-closed.
        from live_discovery.contract import CollectorResult
        profile = CollectorResult(service="target-profile", side="target")
        profile.unknowns.append("target profile runtime evidence is unavailable in control combine")
        results.append(profile)
    results.append(NeutronCollector(client, side, snapshot).collect(port_ids))
    results.append(CinderCollector(client, side, snapshot).collect(volume_ids))
    requirements = {
        image_id: {
            "required": True,
            "reason": "local_root",
            "bdm_proves_no_local_root": False,
            "runtime_proves_no_local_root": False,
            "consumer_project_ids": project_ids,
        }
        for image_id in image_ids
    }
    results.append(GlanceCollector(client, side).collect(requirements))
    return [result.to_dict() for result in results]


def _has_symlink_component(path):
    absolute = Path(path).absolute()
    return any(candidate.is_symlink() and candidate.parent != Path("/") for candidate in (absolute, *absolute.parents))


def _read_json(path):
    path = Path(path)
    if _has_symlink_component(path) or not path.is_file() or path.stat().st_size > _MAX_FILE:
        raise ValueError("input file is unsafe")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _safe_out(path):
    path = Path(path)
    if _has_symlink_component(path) or path.name in {"", ".", ".."}:
        raise ValueError("output path is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _write_directory(path, files):
    path = _safe_out(path)
    staging = Path(tempfile.mkdtemp(prefix=f".{path.name}.staging-", dir=path.parent))
    try:
        for name, payload in files.items():
            if "/" in name or name in {"", ".", ".."}:
                raise ValueError("output filename is unsafe")
            target = staging / name
            target.write_text(render_json(payload), encoding="utf-8")
        if path.exists():
            raise ValueError("output directory already exists")
        os.replace(staging, path)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _request(item, index):
    allowed = {"schema", "table", "columns", "filter_column", "filter_values"}
    if not isinstance(item, dict) or set(item) != allowed:
        raise ValueError("query request is invalid")
    schema = validate_identifier(item["schema"])
    table = validate_identifier(item["table"])
    columns = item["columns"]
    values = item["filter_values"]
    column = validate_identifier(item["filter_column"])
    if not isinstance(columns, list) or not columns or not isinstance(values, list) or not values:
        raise ValueError("query request is unscoped")
    columns = [validate_identifier(value) for value in columns]
    if len(columns) != len(set(columns)):
        raise ValueError("query columns are duplicated")
    where = uuid_in(column, values)
    sql = build_json_row_query(schema, table, columns, where)
    filename = f"{index:04d}-{schema}-{table}"
    return {
        "query_id": filename,
        "schema": schema,
        "table": table,
        "columns": columns,
        "filters": {column: values},
        "sql": sql,
        "jsonl_file": filename + ".jsonl",
        "rc_file": filename + ".rc",
    }


def _api_phase(args):
    if args.fixture is None:
        required = (args.rehome_host, args.cloud, args.clouds_file, args.container)
        if not all(required):
            raise ValueError("live API arguments are incomplete")
        # Live API collection is intentionally limited to the first, read-only root
        # probe. Its output is then reviewed into explicit UUID query requests.
        from live_discovery.openstack import OpenStackClient
        client = OpenStackClient(ReadOnlyRunner(), args.cloud, args.container, str(args.clouds_file))
        servers, evidence = client.json(["server", "list", "--all-projects", "--host", args.rehome_host, "--long", "-f", "json"], f"nova-{args.side}-server-list")
        instance_ids = sorted({item.get("ID") or item.get("id") for item in servers if isinstance(item, dict) and (item.get("ID") or item.get("id"))})
        command = ["server", "list", "--all-projects", "--host", args.rehome_host, "--long", "-f", "json"]
        payload = {"schema_version": API_INPUT_VERSION, "side": args.side, "api_result": {"rehome_host": args.rehome_host, "servers": servers, "openstack": [{"command": command, "payload": servers, "evidence": evidence}]}, "requests": [{"schema": "nova", "table": "instances", "columns": ["uuid", "host", "project_id", "user_id"], "filter_column": "uuid", "filter_values": instance_ids}]}
    else:
        payload = _read_json(args.fixture)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "side", "api_result", "requests"} or payload["schema_version"] != API_INPUT_VERSION or payload["side"] != args.side:
        raise ValueError("API fixture envelope is invalid")
    if not isinstance(payload["api_result"], dict) or not isinstance(payload["requests"], list) or not payload["requests"] or len(payload["requests"]) > _MAX_QUERIES:
        raise ValueError("API result is invalid")
    queries = [_request(item, index + 1) for index, item in enumerate(payload["requests"])]
    query_ids = [item["query_id"] for item in queries]
    if len(query_ids) != len(set(query_ids)):
        raise ValueError("query identity is duplicated")
    filters = {}
    for query in queries:
        filters.setdefault(query["schema"], {}).setdefault(query["table"], {}).update(query["filters"])
    api_result = {"schema_version": API_RESULT_VERSION, "side": args.side, "api_result": payload["api_result"]}
    uuid_filters = {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "side": args.side, "filters": filters}
    plan = {"schema_version": PLAN_VERSION, "side": args.side, "queries": queries}
    _write_directory(args.out, {"api-result.json": api_result, "uuid-filters.json": uuid_filters, "db-query-plan.json": plan})


def _read_jsonl(path, query):
    path = Path(path)
    if _has_symlink_component(path) or not path.is_file() or path.stat().st_size > _MAX_FILE:
        raise ValueError("DB JSONL output is unsafe")
    records = []
    with path.open("r", encoding="utf-8") as stream:
        for index, line in enumerate(stream):
            if index >= _MAX_LINES or len(line) > 1024 * 1024:
                raise ValueError("DB JSONL exceeds safety bounds")
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError("DB JSONL record is malformed") from error
            if not isinstance(record, dict) or set(record) != {"_schema", "_table", "row"} or record["_schema"] != query["schema"] or record["_table"] != query["table"] or not isinstance(record["row"], dict):
                raise ValueError("DB JSONL provenance is invalid")
            if not any(record["row"].get(field) in values for field, values in query["filters"].items()):
                raise ValueError("DB JSONL row is outside query scope")
            records.append(record)
    return records


def _combine_phase(args):
    api = _read_json(args.api_result)
    plan = _read_json(Path(args.api_result).with_name("db-query-plan.json"))
    if not isinstance(api, dict) or set(api) != {"schema_version", "side", "api_result"} or api.get("schema_version") != API_RESULT_VERSION or api.get("side") != args.side:
        raise ValueError("API result envelope is invalid")
    if not isinstance(plan, dict) or set(plan) != {"schema_version", "side", "queries"} or plan.get("schema_version") != PLAN_VERSION or plan.get("side") != args.side or not isinstance(plan["queries"], list) or not plan["queries"] or len(plan["queries"]) > _MAX_QUERIES:
        raise ValueError("DB query plan is invalid")
    db_dir = Path(args.db_jsonl_dir)
    if _has_symlink_component(db_dir) or not db_dir.is_dir() or len(list(db_dir.iterdir())) > _MAX_QUERIES * 2:
        raise ValueError("DB output directory is unsafe")
    expected_outputs = {
        name
        for query in plan["queries"] if isinstance(query, dict)
        for name in (query.get("jsonl_file"), query.get("rc_file"))
        if isinstance(name, str)
    }
    actual_outputs = {entry.name for entry in db_dir.iterdir()}
    if actual_outputs != expected_outputs:
        raise ValueError("DB output set does not match query plan")
    records = {}
    evidence = []
    for query_index, query in enumerate(plan["queries"], start=1):
        expected = {"query_id", "schema", "table", "columns", "filters", "sql", "jsonl_file", "rc_file"}
        if not isinstance(query, dict) or set(query) != expected or not query["filters"]:
            raise ValueError("DB query is invalid")
        if (
            not isinstance(query["columns"], list)
            or not query["columns"]
            or not isinstance(query["filters"], dict)
            or len(query["filters"]) != 1
        ):
            raise ValueError("DB query scope is invalid")
        schema = validate_identifier(query["schema"])
        table = validate_identifier(query["table"])
        columns = [validate_identifier(value) for value in query["columns"]]
        filter_column, filter_values = next(iter(query["filters"].items()))
        filter_column = validate_identifier(filter_column)
        expected_sql = build_json_row_query(
            schema, table, columns, uuid_in(filter_column, filter_values)
        )
        if query["sql"] != expected_sql:
            raise ValueError("DB query does not match its reviewed scope")
        validate_select_only_sql(query["sql"])
        expected_query_id = f"{query_index:04d}-{schema}-{table}"
        if query["query_id"] != expected_query_id or query["jsonl_file"] != expected_query_id + ".jsonl" or query["rc_file"] != expected_query_id + ".rc":
            raise ValueError("DB query filenames are invalid")
        rc_path = db_dir / query["rc_file"]
        output_path = db_dir / query["jsonl_file"]
        if rc_path.parent != db_dir or output_path.parent != db_dir or rc_path.is_symlink() or output_path.is_symlink() or not rc_path.is_file():
            raise ValueError("DB query status is missing")
        if rc_path.stat().st_size > 16 or rc_path.read_text(encoding="ascii").strip() != "0":
            raise ValueError("DB query failed")
        rows = _read_jsonl(output_path, query)
        key = f"{query['schema']}.{query['table']}"
        if key in records:
            raise ValueError("DB query output is duplicated")
        records[key] = rows
        evidence.append({"evidence_id": f"{args.side}-db:{key}", "kind": "db-jsonl", "schema": query["schema"], "table": query["table"], "filters": deepcopy(query["filters"])})
    # Parse/validate the two policy inputs now; service collectors consume these
    # exact documents in the next orchestration layer.
    if _has_symlink_component(args.information_schema) or not args.information_schema.is_file() or args.information_schema.stat().st_size > _MAX_FILE:
        raise ValueError("information_schema input is unsafe")
    snapshot = parse_information_schema(args.information_schema)
    if not snapshot.tables:
        raise ValueError("information_schema evidence is empty")
    schema_policy = _read_json(args.schema_policy)
    if not isinstance(schema_policy, dict):
        raise ValueError("schema policy is invalid")
    supplied_collectors = api["api_result"].get("collectors", [])
    if not isinstance(supplied_collectors, list):
        raise ValueError("collector result set is invalid")
    collectors = deepcopy(supplied_collectors)
    if not collectors:
        collectors = _compose_collectors(
            args.side, api["api_result"], records, evidence, snapshot
        )
    side_filters = {"source": {}, "target": {}}
    side_filters[args.side] = {
        key: value for key, value in sorted(
            ((f"{query['schema']}.{query['table']}", query["filters"]) for query in plan["queries"]),
            key=lambda item: item[0],
        )
    }
    capabilities = deepcopy(api["api_result"].get("schema_capabilities", {}))
    if not isinstance(capabilities, dict):
        raise ValueError("schema capabilities are invalid")
    used_columns = {}
    for query in plan["queries"]:
        used_columns.setdefault(f"{query['schema']}.{query['table']}", set()).update(query["columns"])
    capabilities[f"{args.side}-information-schema"] = {
        "tables": {
            table: {
                column: definition.to_dict()
                for column, definition in sorted(columns.items())
            }
            for table, columns in sorted(snapshot.tables.items())
        },
        "used_columns": {
            table: sorted(columns) for table, columns in sorted(used_columns.items())
        },
    }
    combined = {
        "schema_version": BUNDLE_VERSION,
        "collectors": collectors,
        "checks": [],
        "schema_capabilities": capabilities,
        "uuid_filters": side_filters,
        "evidence_index": evidence,
        "sensitive_evidence": {},
    }
    _write_directory(args.out, {"control-result.json": combined})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Collect read-only control-plane facts")
    parser.add_argument("--phase", choices=("api", "combine"), required=True)
    parser.add_argument("--side", choices=("source", "target"), required=True)
    parser.add_argument("--rehome-host")
    parser.add_argument("--cloud")
    parser.add_argument("--clouds-file", type=Path)
    parser.add_argument("--container")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--api-result", type=Path)
    parser.add_argument("--db-jsonl-dir", type=Path)
    parser.add_argument("--information-schema", type=Path)
    parser.add_argument("--schema-policy", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.phase == "api":
            if any((args.api_result, args.db_jsonl_dir, args.information_schema, args.schema_policy)):
                raise ValueError("combine arguments are forbidden in API phase")
            if args.fixture is not None and any((args.rehome_host, args.cloud, args.clouds_file, args.container)):
                raise ValueError("fixture and live API arguments are mutually exclusive")
            _api_phase(args)
        else:
            if args.fixture is not None or any((args.rehome_host, args.cloud, args.clouds_file, args.container)) or not all((args.api_result, args.db_jsonl_dir, args.information_schema, args.schema_policy)):
                raise ValueError("combine arguments are incomplete")
            _combine_phase(args)
        print(f"PHASE={args.phase} SIDE={args.side} STATUS=OK")
        return 0
    except Exception:
        print("live control discovery input rejected", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
