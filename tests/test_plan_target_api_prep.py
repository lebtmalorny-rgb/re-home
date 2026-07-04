import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import plan_target_api_prep


def sample_manifest():
    return {
        "source": {
            "instances": [
                {
                    "uuid": "d6015a8d-e41f-4c8f-8765-b73c83f7f159",
                    "name": "os1-vm-100",
                    "flavor": {
                        "id": "lab.tiny",
                        "name": "lab.tiny",
                        "ram": 512,
                        "disk": 1,
                        "vcpus": 1,
                        "ephemeral": 0,
                        "swap": 0,
                        "is_public": True,
                        "extra_specs": {},
                    },
                    "ports": [
                        {
                            "id": "0333a723-8f93-4d00-a9c6-9a8af62c4c68",
                            "mac_address": "fa:16:3e:21:b6:cc",
                            "fixed_ips": [
                                {
                                    "ip_address": "192.168.10.100",
                                    "subnet_id": "e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7",
                                }
                            ],
                            "network": {
                                "id": "e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b",
                                "name": "lab-net",
                                "provider_network_type": "flat",
                                "provider_physical_network": "physnet1",
                                "provider_segmentation_id": None,
                            },
                            "subnets": [
                                {
                                    "id": "e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7",
                                    "name": "lab-subnet",
                                    "cidr": "192.168.10.0/24",
                                    "gateway_ip": "192.168.10.1",
                                    "enable_dhcp": False,
                                }
                            ],
                            "security_groups": [
                                {
                                    "id": "0b394beb-8ca1-43e9-83a5-398309f5dfdb",
                                    "name": "lab-access",
                                    "rules": [{"id": "rule-1"}],
                                }
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "id": "15c47caf-e3e0-4b14-86f0-a1bbc97d4256",
                            "status": "in-use",
                            "bootable": "true",
                        }
                    ],
                }
            ]
        }
    }


class TargetApiPrepPlanTests(unittest.TestCase):
    def test_missing_resources_are_classified_by_safe_apply_boundary(self):
        plan = plan_target_api_prep.build_plan(sample_manifest(), {})

        actions = {(item["resource_type"], item["id"]): item["action"] for item in plan["items"]}

        self.assertEqual(actions[("flavor", "lab.tiny")], "create_api_safe")
        self.assertEqual(
            actions[("network", "e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b")],
            "requires_existing_or_db_import",
        )
        self.assertEqual(
            actions[("subnet", "e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7")],
            "requires_existing_or_db_import",
        )
        self.assertEqual(
            actions[("security_group", "0b394beb-8ca1-43e9-83a5-398309f5dfdb")],
            "requires_existing_or_db_import",
        )
        self.assertEqual(
            actions[("port", "0333a723-8f93-4d00-a9c6-9a8af62c4c68")],
            "requires_existing_or_db_import",
        )
        self.assertEqual(
            actions[("volume", "15c47caf-e3e0-4b14-86f0-a1bbc97d4256")],
            "db_import_only",
        )
        self.assertEqual(plan["summary"]["create_api_safe"], 1)
        self.assertEqual(plan["summary"]["requires_existing_or_db_import"], 4)
        self.assertEqual(plan["summary"]["db_import_only"], 1)

    def test_existing_uuid_backed_resources_are_reported_as_existing(self):
        target_state = {
            "flavors": {"lab.tiny": {"id": "lab.tiny", "name": "lab.tiny"}},
            "networks": {"e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b": {"id": "e1c2f8d7-33b8-44b8-8ea7-222b6be4c62b"}},
            "subnets": {"e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7": {"id": "e0b3e205-b767-46d3-9a5d-9b87b7bfe4d7"}},
            "security_groups": {"0b394beb-8ca1-43e9-83a5-398309f5dfdb": {"id": "0b394beb-8ca1-43e9-83a5-398309f5dfdb"}},
            "ports": {"0333a723-8f93-4d00-a9c6-9a8af62c4c68": {"id": "0333a723-8f93-4d00-a9c6-9a8af62c4c68"}},
        }

        plan = plan_target_api_prep.build_plan(sample_manifest(), target_state)

        non_volume_actions = {
            item["action"]
            for item in plan["items"]
            if item["resource_type"] != "volume"
        }
        self.assertEqual(non_volume_actions, {"exists"})
        self.assertEqual(plan["summary"]["exists"], 5)
        self.assertEqual(plan["summary"]["db_import_only"], 1)


if __name__ == "__main__":
    unittest.main()
