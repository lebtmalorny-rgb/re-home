#!/usr/bin/env python3
import argparse
import json
import pathlib
import shlex
import subprocess
import sys


def container_name(inspect_data):
    return str(inspect_data.get("Name", "")).lstrip("/")


def current_image(inspect_data):
    config = inspect_data.get("Config") or {}
    return config.get("Image") or inspect_data.get("Image") or ""


def list_value(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def env_key(value):
    return str(value).split("=", 1)[0]


def merge_env(env_items, env_overrides=None):
    env_overrides = env_overrides or {}
    merged = []
    seen = set()
    for item in env_items or []:
        key = env_key(item)
        if not key:
            continue
        if key in env_overrides:
            merged.append(f"{key}={env_overrides[key]}")
        else:
            merged.append(str(item))
        seen.add(key)
    for key in sorted(env_overrides):
        if key not in seen:
            merged.append(f"{key}={env_overrides[key]}")
    return merged


def env_overrides_change(inspect_data, env_overrides=None):
    env_overrides = env_overrides or {}
    current = {}
    for item in (inspect_data.get("Config") or {}).get("Env") or []:
        key, _, value = str(item).partition("=")
        if key:
            current[key] = value
    return any(current.get(key) != str(value) for key, value in env_overrides.items())


def bind_destination(bind):
    parts = str(bind).split(":")
    if len(parts) < 2:
        return ""
    return parts[1]


def filter_binds(binds, drop_mount_destinations=None):
    drop_mount_destinations = set(str(item) for item in (drop_mount_destinations or []))
    if not drop_mount_destinations:
        return [str(bind) for bind in binds or []]
    return [
        str(bind)
        for bind in binds or []
        if bind_destination(bind) not in drop_mount_destinations
    ]


def dropped_bind_count(inspect_data, drop_mount_destinations=None):
    binds = (inspect_data.get("HostConfig") or {}).get("Binds") or []
    return len(binds) - len(filter_binds(binds, drop_mount_destinations=drop_mount_destinations))


def add_option(args, option, value):
    if value not in (None, ""):
        args.extend([option, str(value)])


def restart_policy_arg(policy):
    policy = policy or {}
    name = policy.get("Name") or ""
    if not name or name == "no":
        return None
    retry_count = policy.get("MaximumRetryCount")
    if retry_count not in (None, 0):
        return f"{name}:{retry_count}"
    return name


def device_arg(device):
    parts = [device.get("PathOnHost"), device.get("PathInContainer")]
    if device.get("CgroupPermissions"):
        parts.append(device.get("CgroupPermissions"))
    return ":".join(str(part) for part in parts if part)


def healthcheck_args(healthcheck):
    if not healthcheck:
        return []
    if healthcheck.get("Test") in (None, [], ["NONE"]):
        return []

    args = []
    test = healthcheck.get("Test") or []
    if len(test) >= 2:
        args.extend(["--health-cmd", " ".join(str(part) for part in test[1:])])
    for inspect_key, cli_key in [
        ("Interval", "--health-interval"),
        ("Timeout", "--health-timeout"),
        ("StartPeriod", "--health-start-period"),
    ]:
        value = healthcheck.get(inspect_key)
        if value:
            args.extend([cli_key, f"{value}ns"])
    if healthcheck.get("Retries"):
        args.extend(["--health-retries", str(healthcheck["Retries"])])
    return args


def build_run_args(
    inspect_data,
    target_image,
    name=None,
    runtime="docker",
    env_overrides=None,
    drop_mount_destinations=None,
):
    config = inspect_data.get("Config") or {}
    host_config = inspect_data.get("HostConfig") or {}
    name = name or container_name(inspect_data)

    args = [runtime, "run", "-d", "--name", name]
    add_option(args, "--hostname", config.get("Hostname"))
    add_option(args, "--user", config.get("User"))
    add_option(args, "--workdir", config.get("WorkingDir"))

    network_mode = host_config.get("NetworkMode")
    if network_mode:
        args.extend(["--network", str(network_mode)])
    if host_config.get("Privileged"):
        args.append("--privileged")
    add_option(args, "--ipc", host_config.get("IpcMode"))
    add_option(args, "--pid", host_config.get("PidMode"))
    add_option(args, "--cgroupns", host_config.get("CgroupnsMode"))

    restart_arg = restart_policy_arg(host_config.get("RestartPolicy"))
    if restart_arg:
        args.extend(["--restart", restart_arg])

    for env in merge_env(config.get("Env") or [], env_overrides=env_overrides):
        args.extend(["-e", str(env)])
    for bind in filter_binds(host_config.get("Binds") or [], drop_mount_destinations=drop_mount_destinations):
        args.extend(["-v", str(bind)])
    for volume_from in host_config.get("VolumesFrom") or []:
        args.extend(["--volumes-from", str(volume_from)])
    for device in host_config.get("Devices") or []:
        rendered = device_arg(device)
        if rendered:
            args.extend(["--device", rendered])
    for cap in host_config.get("CapAdd") or []:
        args.extend(["--cap-add", str(cap)])
    for security_opt in host_config.get("SecurityOpt") or []:
        args.extend(["--security-opt", str(security_opt)])
    for group in host_config.get("GroupAdd") or []:
        args.extend(["--group-add", str(group)])

    tmpfs = host_config.get("Tmpfs") or {}
    if isinstance(tmpfs, dict):
        for path, options in tmpfs.items():
            value = f"{path}:{options}" if options else str(path)
            args.extend(["--tmpfs", value])
    elif isinstance(tmpfs, list):
        for value in tmpfs:
            args.extend(["--tmpfs", str(value)])

    entrypoint = config.get("Entrypoint")
    entrypoint_items = list_value(entrypoint)
    entrypoint_command_prefix = []
    if entrypoint_items:
        args.extend(["--entrypoint", str(entrypoint_items[0])])
        entrypoint_command_prefix = [str(part) for part in entrypoint_items[1:]]

    args.extend(healthcheck_args(config.get("Healthcheck")))
    args.append(target_image)
    args.extend(entrypoint_command_prefix)
    args.extend(str(part) for part in list_value(config.get("Cmd")))
    return args


def env_keys(inspect_data):
    config = inspect_data.get("Config") or {}
    keys = []
    for item in config.get("Env") or []:
        key = str(item).split("=", 1)[0]
        if key:
            keys.append(key)
    return sorted(set(keys))


def build_report(inspect_data, target_image, backup_name=None, env_overrides=None, drop_mount_destinations=None):
    host_config = inspect_data.get("HostConfig") or {}
    env_overrides = env_overrides or {}
    drop_mount_destinations = [str(item) for item in (drop_mount_destinations or [])]
    dropped_binds = dropped_bind_count(inspect_data, drop_mount_destinations=drop_mount_destinations)
    report = {
        "name": container_name(inspect_data),
        "current_image": current_image(inspect_data),
        "target_image": target_image,
        "would_change": current_image(inspect_data) != target_image
        or env_overrides_change(inspect_data, env_overrides=env_overrides)
        or dropped_binds > 0,
        "backup_name": backup_name,
        "network_mode": host_config.get("NetworkMode"),
        "privileged": bool(host_config.get("Privileged")),
        "bind_mounts": len(host_config.get("Binds") or []),
        "dropped_bind_mounts": dropped_binds,
        "volumes_from": len(host_config.get("VolumesFrom") or []),
        "env_keys": env_keys(inspect_data),
        "env_override_keys": sorted(env_overrides),
        "drop_mount_destinations": sorted(drop_mount_destinations),
    }
    return report


def run(args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


def inspect_container(runtime, name):
    result = run([runtime, "inspect", name])
    data = json.loads(result.stdout)
    if not data:
        raise SystemExit(f"container not found: {name}")
    return data[0]


def container_exists(runtime, name):
    result = run([runtime, "inspect", name], check=False)
    return result.returncode == 0


def image_exists(runtime, image):
    result = run([runtime, "image", "inspect", image], check=False)
    return result.returncode == 0


def write_report(path, report):
    if not path:
        return
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def print_report(report):
    print(json.dumps(report, indent=2, sort_keys=True))


def report_action(args):
    inspect_data = inspect_container(args.runtime, args.container)
    env_overrides = parse_env_overrides(args.env_overrides_json)
    drop_mount_destinations = parse_drop_mount_destinations(args.drop_mount_destinations_json)
    report = build_report(
        inspect_data,
        args.target_image,
        backup_name=args.backup_name,
        env_overrides=env_overrides,
        drop_mount_destinations=drop_mount_destinations,
    )
    if args.include_run_argv:
        report["run_argv"] = build_run_args(
            inspect_data,
            args.target_image,
            name=args.container,
            runtime=args.runtime,
            env_overrides=env_overrides,
            drop_mount_destinations=drop_mount_destinations,
        )
        report["run_command"] = shlex.join(report["run_argv"])
    write_report(args.report, report)
    print_report(report)


def rollback_action(args):
    if not args.backup_name:
        raise SystemExit("--backup-name is required for rollback")

    if not container_exists(args.runtime, args.backup_name):
        if container_exists(args.runtime, args.container):
            print_report({"name": args.container, "rollback": "already-current", "backup_name": args.backup_name})
            return
        raise SystemExit(f"backup container not found: {args.backup_name}")

    if container_exists(args.runtime, args.container):
        run([args.runtime, "rm", "-f", args.container])
    run([args.runtime, "rename", args.backup_name, args.container])
    if args.start_after_rollback:
        run([args.runtime, "start", args.container])
    print_report({"name": args.container, "rollback": "restored", "backup_name": args.backup_name})


def apply_action(args):
    if not args.backup_name:
        raise SystemExit("--backup-name is required for apply")
    if container_exists(args.runtime, args.backup_name):
        raise SystemExit(f"backup container already exists: {args.backup_name}")
    if not image_exists(args.runtime, args.target_image):
        raise SystemExit(f"target image is not present locally: {args.target_image}")

    inspect_data = inspect_container(args.runtime, args.container)
    env_overrides = parse_env_overrides(args.env_overrides_json)
    drop_mount_destinations = parse_drop_mount_destinations(args.drop_mount_destinations_json)
    report = build_report(
        inspect_data,
        args.target_image,
        backup_name=args.backup_name,
        env_overrides=env_overrides,
        drop_mount_destinations=drop_mount_destinations,
    )
    if not report["would_change"]:
        report["changed"] = False
        write_report(args.report, report)
        print_report(report)
        return

    was_running = bool((inspect_data.get("State") or {}).get("Running"))
    run_args = build_run_args(
        inspect_data,
        args.target_image,
        name=args.container,
        runtime=args.runtime,
        env_overrides=env_overrides,
        drop_mount_destinations=drop_mount_destinations,
    )

    if was_running:
        run([args.runtime, "stop", args.container])
    run([args.runtime, "rename", args.container, args.backup_name])
    try:
        run(run_args)
    except subprocess.CalledProcessError:
        rollback_args = argparse.Namespace(
            runtime=args.runtime,
            container=args.container,
            backup_name=args.backup_name,
            start_after_rollback=was_running,
        )
        rollback_action(rollback_args)
        raise

    report["changed"] = True
    report["backup_created"] = True
    report["was_running"] = was_running
    write_report(args.report, report)
    print_report(report)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Recreate a Docker container with a different image.")
    parser.add_argument("--action", choices=["report", "apply", "rollback"], default="report")
    parser.add_argument("--runtime", default="docker")
    parser.add_argument("--container", required=True)
    parser.add_argument("--target-image")
    parser.add_argument("--backup-name")
    parser.add_argument("--report")
    parser.add_argument("--include-run-argv", action="store_true")
    parser.add_argument("--env-overrides-json", default="{}")
    parser.add_argument("--drop-mount-destinations-json", default="[]")
    parser.add_argument("--no-start-after-rollback", dest="start_after_rollback", action="store_false")
    parser.set_defaults(start_after_rollback=True)
    args = parser.parse_args(argv)
    if args.action in {"report", "apply"} and not args.target_image:
        parser.error("--target-image is required for report/apply")
    return args


def parse_env_overrides(raw):
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid --env-overrides-json: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("--env-overrides-json must be a JSON object")
    return {str(key): str(item) for key, item in value.items()}


def parse_drop_mount_destinations(raw):
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid --drop-mount-destinations-json: {exc}") from exc
    if not isinstance(value, list):
        raise SystemExit("--drop-mount-destinations-json must be a JSON array")
    return [str(item) for item in value]


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if args.action == "report":
        report_action(args)
    elif args.action == "apply":
        apply_action(args)
    elif args.action == "rollback":
        rollback_action(args)


if __name__ == "__main__":
    main()
