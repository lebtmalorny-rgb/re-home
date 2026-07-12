import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.render import _AtomicArtifactWriter, _safe_destination, render_json, render_yaml, render_markdown, write_artifacts
from live_discovery.contract import CollectorResult, ResourceNode
from live_discovery.graph import assemble_graph
from live_discovery.verdict import compute_verdict


def sample_graph():
    return assemble_graph([CollectorResult(
        service="nova", side="source",
        nodes=[ResourceNode("instance", "vm-1", "source")],
    )])


def sample_verdict():
    return {
        "schema_version": "openstack-rehome-readiness-verdict/v1alpha1",
        "graph_sha256": sample_graph()["graph_sha256"],
        "verdict": "BLOCKED", "exit_code": 3,
        "counts": {"PASS": 0, "WARN": 0, "UNKNOWN": 0, "BLOCKED": 1},
        "reasons": {"PASS": [], "WARN": [], "UNKNOWN": [], "BLOCKED": ["target segment missing"]},
        "checks": [],
    }


class LiveDiscoveryRenderTests(unittest.TestCase):
    def test_markdown_contains_verdict_blockers_and_resource_counts(self):
        markdown = render_markdown(sample_graph(), sample_verdict())
        self.assertIn("# Live Discovery Readiness Report", markdown)
        self.assertIn("Verdict: `BLOCKED`", markdown)
        self.assertIn("target segment missing", markdown)
        self.assertIn("Instances: `1`", markdown)

    def test_normal_artifacts_are_resanitized(self):
        rendered = render_json({"password": "chap-secret-value", "api_key": "api-key-material", "access_key_id": "access-material", "secret_access_key": "secret-access-material", "private-key": "pem-material", "Authorization": "Basic dXNlcjpwYXNz", "header": "Bearer abc.def.ghi", "safe": "ok"})
        self.assertNotIn("chap-secret-value", rendered)
        self.assertNotIn("api-key-material", rendered)
        self.assertNotIn("access-material", rendered)
        self.assertNotIn("secret-access-material", rendered)
        self.assertNotIn("pem-material", rendered)
        self.assertNotIn("dXNlcjpwYXNz", rendered)
        self.assertNotIn("abc.def.ghi", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertIn("ok", rendered)
        yaml = render_yaml({"private_key":"pem-material","header":"Basic dXNlcjpwYXNz","safe":"Alpha123"})
        self.assertNotIn("pem-material", yaml)
        self.assertNotIn("dXNlcjpwYXNz", yaml)
        self.assertIn("Alpha123", yaml)

    def test_markdown_escapes_html_delimiters_and_controls(self):
        verdict = sample_verdict()
        verdict["reasons"]["BLOCKED"] = ["<script>alert(1)</script> | [link](bad)\t"]
        markdown = render_markdown(sample_graph(), verdict)
        self.assertNotIn("<script>", markdown)
        self.assertNotIn(" | ", markdown)
        self.assertNotIn("[link](bad)", markdown)
        self.assertNotIn("\t", markdown)

    def test_artifacts_are_exact_deterministic_and_sensitive_is_protected(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            evidence = {
                "uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}},
                "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []},
                "sensitive": {"connection_info": "private-material"},
            }
            write_artifacts(out, sample_graph(), sample_verdict(), {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, evidence)
            expected = {
                "resource-graph.json", "resource-graph.yml", "readiness-report.json",
                "readiness-report.md", "schema-capabilities.json", "schema-mapping.json",
                "uuid-filters.json", "evidence-index.json", "sensitive",
            }
            self.assertEqual(expected, {p.name for p in out.iterdir()})
            self.assertEqual({"evidence.json"}, {p.name for p in (out / "sensitive").iterdir()})
            self.assertEqual(0o700, stat.S_IMODE((out / "sensitive").stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE((out / "sensitive/evidence.json").stat().st_mode))
            first = {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}
            write_artifacts(out, sample_graph(), sample_verdict(), {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, evidence)
            second = {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob("*") if p.is_file()}
            self.assertEqual(first, second)

    def test_no_sensitive_file_when_sensitive_evidence_is_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            write_artifacts(out, sample_graph(), sample_verdict(), {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}})
            self.assertFalse((out / "sensitive").exists())

    def test_failed_replacement_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            out.mkdir()
            (out / "keep").write_text("old", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_artifacts(out, sample_graph(), {**sample_verdict(), "unknown": "bad"}, {}, {}, {})
            self.assertEqual("old", (out / "keep").read_text(encoding="utf-8"))

    def test_write_failure_after_staging_begins_preserves_existing_output(self):
        import live_discovery.render as renderer
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            out.mkdir()
            (out / "keep").write_text("old", encoding="utf-8")
            evidence = {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}}
            original = renderer._write
            calls = [0]
            def fail_second_write(*args, **kwargs):
                calls[0] += 1
                if calls[0] == 2:
                    raise OSError("simulated write failure")
                return original(*args, **kwargs)
            with mock.patch("live_discovery.render._write", side_effect=fail_second_write):
                with self.assertRaises(OSError):
                    write_artifacts(out, sample_graph(), sample_verdict(), {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, evidence)
            self.assertEqual({"keep"}, {path.name for path in out.iterdir()})
            self.assertEqual("old", (out / "keep").read_text(encoding="utf-8"))

    def test_signal_cleanup_is_owned_rolls_back_each_atomic_stage_and_reruns(self):
        for stage, signum in (("staging", signal.SIGTERM), ("backup", signal.SIGINT), ("installed", signal.SIGTERM)):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                out = root / "out"
                out.mkdir()
                (out / "keep").write_text("old", encoding="utf-8")
                writer = _AtomicArtifactWriter(out)
                writer.begin()
                (writer.staging / "new").write_text("new", encoding="utf-8")
                if stage in {"backup", "installed"}:
                    writer.backup_existing()
                if stage == "installed":
                    writer.install_staging()
                with self.assertRaises(InterruptedError):
                    writer.handle_signal(signum, None)
                self.assertEqual("old", (out / "keep").read_text(encoding="utf-8"))
                self.assertFalse(any(path.name.startswith(".out.") for path in root.iterdir()))
                evidence = {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}}
                write_artifacts(out, sample_graph(), sample_verdict(), {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, evidence)
                self.assertTrue((out / "readiness-report.json").is_file())

    def test_writer_does_not_delete_foreign_owned_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / ".out.lock"
            lock.mkdir()
            (lock / "owner.json").write_text('{"pid":999999,"token":"foreign"}', encoding="utf-8")
            writer = _AtomicArtifactWriter(root / "out")
            with self.assertRaisesRegex(ValueError, "writer"):
                writer.begin()
            writer.cleanup()
            self.assertTrue(lock.is_dir())

    def test_rejects_symlink_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            (root / "out").symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                write_artifacts(root / "out", sample_graph(), sample_verdict(), {}, {}, {})

    def test_rejects_concurrent_writer_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".out.lock").mkdir()
            evidence = {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}}
            with self.assertRaisesRegex(ValueError, "writer"):
                write_artifacts(root / "out", sample_graph(), sample_verdict(), {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, evidence)

    def test_rejects_invalid_graph_hash(self):
        graph = sample_graph()
        graph["graph_sha256"] = "f" * 64
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "hash"):
                write_artifacts(Path(temporary) / "out", graph, {**sample_verdict(), "graph_sha256": "f" * 64}, {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}})

    def test_rejects_symlink_in_output_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            (root / "link").symlink_to(real, target_is_directory=True)
            evidence = {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}}
            with self.assertRaisesRegex(ValueError, "symlink"):
                write_artifacts(root / "link" / "nested" / "out", sample_graph(), sample_verdict(), {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, evidence)

    def test_system_top_level_tmp_symlink_is_allowed(self):
        candidate = Path("/tmp") / "live-discovery-render-safe-destination"
        self.assertEqual(candidate, _safe_destination(candidate))

    def test_structurally_valid_blocked_graph_is_rendered(self):
        result = CollectorResult(service="nova", side="source", nodes=[ResourceNode("instance", "vm-1", "source")], blockers=["target segment missing"])
        graph = assemble_graph([result])
        mapping = {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}
        verdict = compute_verdict(graph, [], mapping)
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            write_artifacts(out, graph, verdict, {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, mapping, {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}})
            self.assertEqual("BLOCKED", json.loads((out / "readiness-report.json").read_text())["verdict"])

    def test_rejects_unknown_nested_verdict_schema(self):
        verdict = sample_verdict()
        verdict["counts"]["EXTRA"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "verdict"):
                write_artifacts(Path(temporary) / "out", sample_graph(), verdict, {"schema_version": "openstack-rehome-schema-capabilities/v1alpha1", "services": {}}, {"schema_version": "openstack-rehome-directional-schema-mapping/v1alpha1", "source_profile": "keystack-2025.1", "target_profile": "vanilla-openstack-2025.1-epoxy", "tables": {}, "blockers": []}, {"uuid_filters": {"schema_version": "openstack-rehome-uuid-filters/v1alpha1", "source": {}, "target": {}}, "index": {"schema_version": "openstack-rehome-evidence-index/v1alpha1", "entries": []}, "sensitive": {}})


if __name__ == "__main__":
    unittest.main()
