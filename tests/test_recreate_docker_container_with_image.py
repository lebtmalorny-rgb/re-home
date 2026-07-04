import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import recreate_docker_container_with_image


class RecreateDockerContainerWithImageTests(unittest.TestCase):
    def test_builds_run_args_from_existing_container_with_new_image(self):
        inspect_data = {
            "Name": "/nova_libvirt",
            "Config": {
                "Hostname": "os1-compute-02.example.local",
                "Env": [
                    "KOLLA_CONFIG_STRATEGY=COPY_ALWAYS",
                    "KOLLA_SERVICE_NAME=nova-libvirt",
                ],
                "Entrypoint": ["dumb-init"],
                "Cmd": ["--single-child", "--", "kolla_start"],
            },
            "HostConfig": {
                "NetworkMode": "host",
                "Privileged": True,
                "IpcMode": "host",
                "PidMode": "host",
                "RestartPolicy": {"Name": "unless-stopped"},
                "Binds": [
                    "/etc/kolla/nova-libvirt:/var/lib/kolla/config_files:ro",
                    "/run:/run",
                ],
            },
        }

        args = recreate_docker_container_with_image.build_run_args(
            inspect_data,
            "quay.io/openstack.kolla/nova-libvirt:2025.1-ubuntu-noble",
            name="nova_libvirt",
        )

        rendered = " ".join(args)
        self.assertEqual(args[:3], ["docker", "run", "-d"])
        self.assertIn("--name", args)
        self.assertIn("nova_libvirt", args)
        self.assertIn("--network", args)
        self.assertIn("host", args)
        self.assertIn("--privileged", args)
        self.assertIn("--ipc", args)
        self.assertIn("host", args)
        self.assertIn("-v", args)
        self.assertIn("/etc/kolla/nova-libvirt:/var/lib/kolla/config_files:ro", args)
        self.assertIn("-e", args)
        self.assertIn("KOLLA_SERVICE_NAME=nova-libvirt", args)
        self.assertIn("--entrypoint", args)
        self.assertIn("dumb-init", args)
        self.assertIn("quay.io/openstack.kolla/nova-libvirt:2025.1-ubuntu-noble", args)
        self.assertTrue(rendered.endswith("quay.io/openstack.kolla/nova-libvirt:2025.1-ubuntu-noble --single-child -- kolla_start"))

    def test_report_summarizes_env_keys_without_values(self):
        inspect_data = {
            "Name": "/fluentd",
            "Config": {
                "Image": "quay.io/openstack.kolla/fluentd:2025.1-rocky-9",
                "Env": [
                    "KOLLA_SERVICE_NAME=fluentd",
                    "SECRET_TOKEN=do-not-print",
                ],
            },
            "HostConfig": {"Binds": ["/etc/kolla/fluentd:/var/lib/kolla/config_files:ro"]},
        }

        report = recreate_docker_container_with_image.build_report(
            inspect_data,
            "quay.io/openstack.kolla/fluentd:2025.1-ubuntu-noble",
            backup_name="fluentd_rehome_backup_20260704",
        )

        self.assertEqual(report["name"], "fluentd")
        self.assertTrue(report["would_change"])
        self.assertIn("KOLLA_SERVICE_NAME", report["env_keys"])
        self.assertIn("SECRET_TOKEN", report["env_keys"])
        self.assertNotIn("do-not-print", str(report))

    def test_env_overrides_update_run_args_and_mark_report_changed_without_values(self):
        inspect_data = {
            "Name": "/cron",
            "Config": {
                "Image": "quay.io/openstack.kolla/cron:2025.1-ubuntu-noble",
                "Env": [
                    "KOLLA_SERVICE_NAME=cron",
                    "KOLLA_BASE_DISTRO=rocky",
                    "SECRET_TOKEN=do-not-print",
                ],
                "Entrypoint": ["dumb-init"],
                "Cmd": ["--single-child", "--", "kolla_start"],
            },
            "HostConfig": {"NetworkMode": "host"},
        }

        overrides = {"KOLLA_BASE_DISTRO": "ubuntu", "EXTRA_ENV": "new-value"}
        args = recreate_docker_container_with_image.build_run_args(
            inspect_data,
            "quay.io/openstack.kolla/cron:2025.1-ubuntu-noble",
            name="cron",
            env_overrides=overrides,
        )
        report = recreate_docker_container_with_image.build_report(
            inspect_data,
            "quay.io/openstack.kolla/cron:2025.1-ubuntu-noble",
            env_overrides=overrides,
        )

        self.assertIn("KOLLA_BASE_DISTRO=ubuntu", args)
        self.assertIn("EXTRA_ENV=new-value", args)
        self.assertNotIn("KOLLA_BASE_DISTRO=rocky", args)
        self.assertTrue(report["would_change"])
        self.assertEqual(report["env_override_keys"], ["EXTRA_ENV", "KOLLA_BASE_DISTRO"])
        self.assertNotIn("new-value", str(report))
        self.assertNotIn("do-not-print", str(report))

    def test_drop_mount_destinations_remove_matching_binds_and_mark_report_changed(self):
        inspect_data = {
            "Name": "/nova_ssh",
            "Config": {
                "Image": "quay.io/openstack.kolla/nova-ssh:2025.1-ubuntu-noble",
                "Env": ["KOLLA_SERVICE_NAME=nova-ssh"],
            },
            "HostConfig": {
                "NetworkMode": "host",
                "Binds": [
                    "/etc/kolla/nova-ssh:/var/lib/kolla/config_files:ro",
                    "/var/lib/nova/mnt:/var/lib/nova/mnt:shared",
                    "/run:/run",
                ],
            },
        }

        args = recreate_docker_container_with_image.build_run_args(
            inspect_data,
            "quay.io/openstack.kolla/nova-ssh:2025.1-ubuntu-noble",
            name="nova_ssh",
            drop_mount_destinations=["/var/lib/nova/mnt"],
        )
        report = recreate_docker_container_with_image.build_report(
            inspect_data,
            "quay.io/openstack.kolla/nova-ssh:2025.1-ubuntu-noble",
            drop_mount_destinations=["/var/lib/nova/mnt"],
        )

        self.assertIn("/etc/kolla/nova-ssh:/var/lib/kolla/config_files:ro", args)
        self.assertIn("/run:/run", args)
        self.assertNotIn("/var/lib/nova/mnt:/var/lib/nova/mnt:shared", args)
        self.assertTrue(report["would_change"])
        self.assertEqual(report["bind_mounts"], 3)
        self.assertEqual(report["dropped_bind_mounts"], 1)
        self.assertEqual(report["drop_mount_destinations"], ["/var/lib/nova/mnt"])

    def test_maps_multi_part_kolla_entrypoint_to_entrypoint_plus_command_args(self):
        inspect_data = {
            "Name": "/fluentd",
            "Config": {
                "Entrypoint": ["dumb-init", "--single-child", "--"],
                "Cmd": ["kolla_start"],
            },
            "HostConfig": {"NetworkMode": "host"},
        }

        args = recreate_docker_container_with_image.build_run_args(
            inspect_data,
            "quay.io/openstack.kolla/fluentd:2025.1-ubuntu-noble",
            name="fluentd",
        )

        self.assertIn("--entrypoint", args)
        self.assertIn("dumb-init", args)
        self.assertTrue(
            " ".join(args).endswith(
                "quay.io/openstack.kolla/fluentd:2025.1-ubuntu-noble --single-child -- kolla_start"
            )
        )


if __name__ == "__main__":
    unittest.main()
