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
