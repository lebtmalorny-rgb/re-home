import pathlib
import json
import re
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from live_discovery.probe_plan import validate_probe_contract


def read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


class LiveDiscoveryDocumentationTests(unittest.TestCase):
    def test_readme_orders_discovery_before_database_import(self):
        text = read("README.md")
        discovery = text.index("02b-discover-live-resource-graph.yml")
        import_plan = text.index("04b-plan-db-metadata-import.yml")
        self.assertLess(discovery, import_plan)
        self.assertIn("ansible-playbook -i inventory/hosts.yml playbooks/02b-discover-live-resource-graph.yml", text)

        for document in ("operator-inputs-ru.md", "lab-rehome-runbook-ru.md"):
            other = read(document)
            with self.subTest(document=document):
                self.assertLess(
                    other.index("02b-discover-live-resource-graph.yml"),
                    other.index("04b-plan-db-metadata-import.yml"),
                )

    def test_readme_has_first_read_links_and_exact_verdicts(self):
        text = read("README.md")
        for link in (
            "[Поток live discovery](docs/live-discovery-data-flow-ru.md)",
            "[Артефакты live discovery](docs/live-discovery-artifacts-ru.md)",
            "[готовность Cinder](cinder-rehome-readiness-ru.md)",
            "[готовность Glance](glance-rehome-readiness-ru.md)",
        ):
            self.assertIn(link, text)
        for verdict in ("READY=0", "READY_WITH_WARNINGS=0", "UNKNOWN=2", "BLOCKED=3"):
            self.assertIn(verdict, text)

    def test_service_docs_cover_required_readiness(self):
        cinder = read("cinder-rehome-readiness-ru.md")
        glance = read("glance-rehome-readiness-ru.md")
        neutron = read("neutron-rehome-behavior-ru.md")
        for needle in (
            "service_uuid", "backing object", "multiattach", "encryption",
            "NFS/file", "RBD", "LVM", "iSCSI", "Fibre Channel", "UNKNOWN",
        ):
            self.assertIn(needle, cinder)
        for needle in (
            "Range: bytes=0-0", "os_hash_value", "os_hash_algo", "visibility",
            "members", "project", "store", "volume-backed",
        ):
            self.assertIn(needle, glance)
        for needle in (
            "ml2_port_binding_levels", "subports", "allowed-address-pairs",
            "extra DHCP options", "QoS", "port forwarding", "address groups",
            "OVS", "OVN",
        ):
            self.assertIn(needle, neutron)

    def test_artifact_doc_is_exact_and_excludes_other_scopes(self):
        text = read("docs/live-discovery-artifacts-ru.md")
        for artifact in (
            "resource-graph.json", "resource-graph.yml", "readiness-report.json",
            "readiness-report.md", "schema-capabilities.json", "schema-mapping.json",
            "uuid-filters.json", "evidence-index.json", "sensitive/evidence.json",
        ):
            self.assertIn(artifact, text)
        for version in (
            "openstack-rehome-resource-graph/v1alpha1",
            "openstack-rehome-readiness-verdict/v1alpha1",
            "openstack-rehome-schema-capabilities/v1alpha1",
            "openstack-rehome-directional-schema-mapping/v1alpha1",
            "openstack-rehome-uuid-filters/v1alpha1",
            "openstack-rehome-evidence-index/v1alpha1",
        ):
            self.assertIn(version, text)
        self.assertIn("Masakari", text)
        self.assertIn("DRS", text)
        self.assertIn("не входят", text)
        self.assertIn("0600", text)
        self.assertIn("0700", text)

    def test_data_flow_documents_signed_two_phase_and_seven_plays(self):
        text = read("docs/live-discovery-data-flow-ru.md")
        self.assertIn("```mermaid", text)
        self.assertIn("семь plays", text)
        self.assertIn("--phase api", text)
        self.assertIn("--phase verify", text)
        self.assertIn("--phase combine", text)
        self.assertIn("verify-before-SQL", text)
        self.assertIn("HMAC", text)
        for role in ("source_control", "target_control", "rehome_compute", "target_reference_compute"):
            self.assertIn(role, text)

    def test_operator_docs_cover_inputs_security_and_reruns(self):
        combined = "\n".join(read(path) for path in (
            "operator-inputs-ru.md", "playbook-logic-ru.md", "lab-rehome-runbook-ru.md",
        ))
        for needle in (
            "live_discovery_storage_backends", "live_discovery_phase_hmac_key_file_local",
            "live_discovery_source_glance_token_file_local",
            "live_discovery_target_glance_token_file_local",
            "run-id", "concurrent", "cleanup", "preflight", "повторн",
            "online_data_migrations", "не запуска",
        ):
            self.assertIn(needle, combined)
        self.assertIn("live_discovery_source_glance_token_file_local", combined)
        self.assertIn("live_discovery_target_glance_token_file_local", combined)

    def test_tracked_docs_have_no_known_stale_discovery_claims(self):
        # Scratch SDD reports/briefs are ignored and intentionally preserve the
        # original task wording; audit only repository documentation surfaces.
        tracked_docs = [
            path for path in ROOT.rglob("*.md")
            if not path.relative_to(ROOT).parts[0].startswith(".")
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in tracked_docs)
        for stale in (
            "schema-only dumps first",
            "первый реализованный шаг",
            "Generic inventory leaves backend kind empty",
            "NFS backend kind and actual storage probe delegate",
            "live_discovery_storage_backend_kind",
            "live_discovery_source_storage_probe_host",
            "live_discovery_target_storage_probe_host",
            "four-play orchestration",
            "NFS-only",
            "token_file:",
        ):
            self.assertNotIn(stale, combined)
        sql_readme = read("sql-skeleton/README.md")
        self.assertTrue(sql_readme.startswith("# Каркас импорта SQL"))
        self.assertIn("02b-discover-live-resource-graph.yml", sql_readme)

    def test_directional_mapping_is_gate_and_full_schema_tools_are_diagnostic(self):
        for document in (
            "operator-inputs-ru.md", "playbook-logic-ru.md",
            "lab-rehome-runbook-ru.md",
        ):
            text = read(document)
            with self.subTest(document=document):
                self.assertIn("resource-scoped directional mapping", text)
                self.assertIn("schema-mapping.json", text)
                self.assertIn("legacy-диагностика", text)
                self.assertIn("полное равенство", text)
                self.assertRegex(text, r"полное равенство[\s\S]{0,160}не\s+требуется")

    def test_all_execution_docs_put_02b_before_optional_02a(self):
        sections = {
            "README.md": read("README.md").split("## Рекомендуемый порядок выполнения", 1)[1],
            "lab-rehome-runbook-ru.md": read("lab-rehome-runbook-ru.md").split("## Короткая последовательность", 1)[1],
            "playbook-logic-ru.md": read("playbook-logic-ru.md").split("## Короткая последовательность", 1)[1],
            "kolla-image-tags.md": read("kolla-image-tags.md").split("## Порядок фаз", 1)[1],
        }
        for document, section in sections.items():
            with self.subTest(document=document):
                self.assertLess(
                    section.index("02b-discover-live-resource-graph.yml"),
                    section.index("02a-build-rehome-manifest.yml"),
                )
                self.assertIn("необязатель", section.lower())

    def test_probe_examples_are_exact_per_side_and_token_env_only(self):
        text = read("operator-inputs-ru.md")
        configs = {}
        for side in ("source", "target"):
            match = re.search(
                rf"<!-- {side}-probe-config.json -->\s*```json\s*(.*?)\s*```",
                text,
                re.DOTALL,
            )
            self.assertIsNotNone(match, side)
            configs[side] = json.loads(match.group(1))
        for side, expected_scope in (("source", "source-compute"), ("target", "target-storage")):
            config = configs[side]
            self.assertEqual("openstack-rehome-probe-config/v1alpha1", config["schema_version"])
            self.assertEqual("LIVE_DISCOVERY_GLANCE_TOKEN", config["glance"]["token_env"])
            self.assertNotIn("token_file", config["glance"])
            self.assertTrue(config["storage"])
            self.assertTrue(all(item["scope"] == expected_scope for item in config["storage"]))
            stores = {item["store_id"] for item in config["glance"]["store_capabilities"]}
            self.assertTrue(stores)
            self.assertTrue(all(set(image["store_ids"]) <= stores for image in config["glance"]["images"]))
            resources = [item["resource"] for item in config["storage"]]
            self.assertTrue(any("allowed_roots" in resource for resource in resources))
            self.assertTrue(any("allowed_pools" in resource for resource in resources))
            self.assertTrue(any("allowed_vgs" in resource for resource in resources))
        backends = {
            backend_id: {
                "kind": kind,
                "source_delegate": "source-probe",
                "target_delegate": "target-probe",
                "allowed_scopes": ["source-compute", "target-storage"],
                "probe_template": kind,
            }
            for backend_id, kind in (
                ("shared-nfs", "nfs"), ("ceph-rbd", "rbd"),
                ("local-lvm", "lvm"),
            )
        }
        result = validate_probe_contract(
            backends, configs["source"], configs["target"], True,
            "source-control", "target-control",
            {"source-control", "target-control", "source-probe", "target-probe"},
        )
        self.assertEqual(["lvm", "nfs", "rbd"], result["backend_kinds"])

    def test_protected_path_examples_cover_inventory_vault_and_lab_command(self):
        text = read("operator-inputs-ru.md") + read("lab-rehome-runbook-ru.md")
        for needle in (
            "live_discovery_kolla_passwords_files[inventory_hostname]",
            "ansible-vault encrypt",
            "--ask-vault-pass",
            "-e @/secure/live-discovery-paths.vault.yml",
            "live_discovery_source_cinder_sensitive_evidence_file_local",
            "live_discovery_target_cinder_sensitive_evidence_file_local",
            "live_discovery_target_online_migration_evidence_file_local",
            "условно обязатель",
        ):
            self.assertIn(needle, text)

    def test_artifact_doc_has_exact_modes_evidence_shapes_and_cleanup_boundary(self):
        text = read("docs/live-discovery-artifacts-ru.md")
        self.assertRegex(text, r"финальный run-каталог — `0700`,\s+восемь normal files —\s+`0644`")
        for needle in (
            "openstack-json", "runtime-command", "db-jsonl", "storage-probe",
            "glance-range", "cinder-connection", "resource_fingerprint",
            "endpoint_origin", "caller-owned", "никогда не изменяются",
        ):
            self.assertIn(needle, text)

    def test_glance_200_warn_and_delegates_run_both_probe_families(self):
        glance = read("glance-rehome-readiness-ru.md")
        flow = read("docs/live-discovery-data-flow-ru.md")
        self.assertIn("HTTP 206", glance)
        self.assertIn("PASS", glance)
        self.assertIn("HTTP 200", glance)
        self.assertIn("WARN", glance)
        self.assertIn("Cinder backing probes и Glance Range probes", flow)

    def test_implementation_plan_uses_current_variables_and_seven_play_sequence(self):
        text = read("docs/superpowers/plans/2026-07-11-live-cluster-discovery.md")
        for current in (
            "live_discovery_storage_backends", "live_discovery_source_probe_config_file_local",
            "live_discovery_target_probe_config_file_local", "seven-play orchestration",
            "plays 2-3", "play 5", "play 6", "play 7",
        ):
            self.assertIn(current, text)
        for stale in (
            "live_discovery_storage_backend_kind", "live_discovery_source_storage_probe_host",
            "live_discovery_target_storage_probe_host", "four-play orchestration",
        ):
            self.assertNotIn(stale, text)

    def test_docs_state_profiles_and_live_source_of_truth(self):
        combined = "\n".join(read(path) for path in (
            "README.md", "operator-inputs-ru.md", "playbook-logic-ru.md",
            "lab-rehome-runbook-ru.md", "docs/live-discovery-data-flow-ru.md",
        ))
        self.assertIn("keystack-2025.1", combined)
        self.assertIn("vanilla-openstack-2025.1-epoxy", combined)
        self.assertIn("жив", combined.lower())
        self.assertRegex(combined.lower(), r"(dump|дамп).{0,100}(пример|fixture)")

    def test_docs_do_not_claim_live_deployment_was_executed(self):
        new_docs = "\n".join(read(path) for path in (
            "cinder-rehome-readiness-ru.md", "glance-rehome-readiness-ru.md",
            "docs/live-discovery-artifacts-ru.md", "docs/live-discovery-data-flow-ru.md",
        ))
        self.assertIn("fixture", new_docs)
        self.assertIn("syntax-check", new_docs)
        self.assertNotRegex(new_docs.lower(), r"успешно выполнен(?:о|а)? на (?:живом|production)")

    def test_all_operator_markdown_links_resolve(self):
        docs = (
            "README.md", "operator-inputs-ru.md", "playbook-logic-ru.md",
            "lab-rehome-runbook-ru.md", "docs/lab-topology-ru.md",
            "neutron-rehome-behavior-ru.md", "cinder-rehome-readiness-ru.md",
            "glance-rehome-readiness-ru.md", "docs/live-discovery-artifacts-ru.md",
            "docs/live-discovery-data-flow-ru.md",
        )
        for relative in docs:
            path = ROOT / relative
            text = path.read_text(encoding="utf-8")
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
                if target.startswith(("http://", "https://", "#")):
                    continue
                resolved = (path.parent / target.split("#", 1)[0]).resolve()
                with self.subTest(document=relative, target=target):
                    self.assertTrue(resolved.exists())


if __name__ == "__main__":
    unittest.main()
