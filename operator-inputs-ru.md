# Входные данные и prerequisites для re-home playbooks

Этот документ описывает, что нужно подготовить перед запуском playbook-ов в
другой инфраструктуре. Lab inventory `inventory/lab-os1-to-os2.yml` является
примером, а не универсальным источником правды.

## Главный принцип

Playbook-и не должны угадывать параметры кластера. Оператор должен явно подать:

- адреса и роли source/target control plane;
- re-home compute host;
- команды управления OpenStack/Kolla;
- доступ к OpenStack admin API;
- доступ к БД для read-only schema checks и backup/import этапов;
- список service/container groups;
- сетевые probe targets для проверки доступности ВМ.

Если параметр неизвестен, re-home нужно остановить до выяснения. Нельзя
подменять неизвестный параметр значением из lab-примера.

Live discovery использует только факты живых кластеров. Приложенная schema/DB
dump не является входом playbook-а: её можно использовать только как
санитизированную fixture для unit tests. Approved source profile —
`keystack-2025.1`; target должен быть доказан live evidence как
`vanilla-openstack-2025.1-epoxy`.

## Обязательные входы live discovery

Точный entrypoint выполняется до любого DB import или cutover:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/02b-discover-live-resource-graph.yml
```

Inventory должен содержать ровно по одному host в группах:

```yaml
source_control:
target_control:
rehome_compute:
target_reference_compute:
```

Playbook не выбирает «первый» host из неоднозначной группы. Значения на
`source_control` и `target_control` замораживаются и обязаны совпасть для
`rehome_host`, local/remote dirs, profile, HMAC path, storage map, Range flag и
fail-closed policy. Переменные `localhost` не заменяют controller authority.

### Базовые переменные

```yaml
live_discovery_enabled: true
live_discovery_run_id: ""
live_discovery_target_profile: vanilla-openstack-2025.1-epoxy
live_discovery_remote_dir: /var/tmp/openstack-rehome/live-discovery
live_discovery_local_dir: /path/to/artifacts/compute-023/live-discovery
live_discovery_schema_policy_file: /path/to/inventory/live-discovery-schema-policy.json
live_discovery_glance_range_probe_enabled: true
live_discovery_fail_on_not_ready: true
```

Пустой `live_discovery_run_id` создаёт ID из UTC microseconds и случайного
suffix. Явный ID должен соответствовать
`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` и быть новым. Concurrent или повторный
запуск с тем же `run-id` останавливается owner-lock до remote reset. Для rerun
использовать новый ID; не удалять чужой/completed owner вручную.

### Clouds, БД и точные argv

```yaml
source_clouds_file_local: /secure/source/clouds.yaml
target_clouds_file_local: /secure/target/clouds.yaml
source_cloud_name: kolla-admin
target_cloud_name: kolla-admin
openstack_cli_container: kolla_toolbox

live_discovery_kolla_passwords_file_local: /secure/kolla/passwords.yml
live_discovery_schema_mysql_user: root
live_discovery_schema_mysql_password_key: database_password
live_discovery_db_service_credentials:
  nova_api: {user: nova_api, password_key: nova_api_database_password}
  nova: {user: nova, password_key: nova_database_password}
  neutron: {user: neutron, password_key: neutron_database_password}
  cinder: {user: cinder, password_key: cinder_database_password}
```

Для Kolla нужно задать argv как YAML lists, без shell-строк:

```yaml
live_discovery_mysql_json_argv:
  - docker
  - exec
  - -e
  - MYSQL_PWD={{ live_discovery_mysql_password }}
  - -i
  - mariadb
  - mysql
  - -u{{ live_discovery_mysql_user }}
  - -h
  - "{{ schema_compat_mysql_host }}"
  - --batch
  - --raw
  - --skip-column-names
live_discovery_mysql_environment: {}
live_discovery_mysql_no_log: true
live_discovery_nova_api_db_version_argv: [docker, exec, nova_api, nova-manage, api_db, version]
live_discovery_nova_cell_db_version_argv: [docker, exec, nova_conductor, nova-manage, db, version]
live_discovery_neutron_db_version_argv: [docker, exec, neutron_server, neutron-db-manage, current, --verbose]
live_discovery_cinder_db_version_argv: [docker, exec, cinder_api, cinder-manage, db, version]
live_discovery_container_inspect_argv_prefix: [docker, inspect]
live_discovery_source_virsh_argv: [docker, exec, nova_libvirt, virsh]
live_discovery_target_virsh_argv: [docker, exec, nova_libvirt, virsh]
live_discovery_target_qemu_argv: [docker, exec, nova_libvirt, /usr/bin/qemu-system-x86_64]
```

`argv_policy.py` проверяет executable, container и разрешённый suffix до
выполнения. Нельзя добавлять shell operators, mutation arguments или менять
ожидаемый container. SQL строится самим collector, проходит `--phase verify`,
привязывается к digest плана и выполняется только как UUID-scoped SELECT.

В `group_vars/all.yml` пока также присутствуют строковые compatibility defaults
`live_discovery_mysql_json_command`, `live_discovery_target_virsh_command` и
`live_discovery_target_qemu_command`. Семиплейный orchestration использует
только безопасные list variables `live_discovery_mysql_json_argv`,
`live_discovery_target_virsh_argv` и `live_discovery_target_qemu_argv`; менять
строковый default вместо соответствующего `*_argv` недостаточно.

### Защищённые входы

Все непустые caller files должны быть regular files владельца запускающего
uid, без symlink, с mode `0600` и допустимым размером:

```yaml
live_discovery_phase_hmac_key_file_local: /secure/live-discovery/phase-hmac.key
live_discovery_source_probe_config_file_local: /secure/live-discovery/source-probe.json
live_discovery_target_probe_config_file_local: /secure/live-discovery/target-probe.json
live_discovery_source_glance_token_file_local: /secure/live-discovery/source-glance.token
live_discovery_target_glance_token_file_local: /secure/live-discovery/target-glance.token
live_discovery_source_cinder_sensitive_evidence_file_local: ""
live_discovery_target_cinder_sensitive_evidence_file_local: ""
live_discovery_target_online_migration_evidence_file_local: ""
```

HMAC key — 16..4096 bytes. Probe JSON — не более 1 MiB; clouds/passwords и
migration evidence — не более 1 MiB; Cinder sensitive evidence — не более
8 MiB. Source и target Glance tokens должны быть отдельными файлами с разными
checksums. В orchestration-supported probe JSON допустим только
`token_env: LIVE_DISCOVERY_GLANCE_TOKEN`; token value не встраивается в JSON.
Root manifest не является операторским input: его выводит
первая live source API phase.

Inputs открываются один раз через `O_NOFOLLOW`, копируются в owned каталог
`0700` как files `0600`, а caller paths больше не читаются. После успешного
запуска frozen secret bytes удаляются; при failure/unreachable выполняется
ownership-checked cleanup только текущего незавершённого run.

Опциональный online-migration envelope имеет contract
`openstack-rehome-online-migration-evidence/v1alpha1`, timestamp не старше 24
часов, точные live revisions Nova API/cell, Neutron, Cinder, Glance и записи
Nova/Cinder с `returncode: 0`, `completed: true`. Playbook никогда не запускает
`nova-manage db online_data_migrations` или
`cinder-manage db online_data_migrations`; он только проверяет заранее
полученное operator evidence. Отсутствие/устаревание/несовпадение оставляет
target capability в `UNKNOWN`/`BLOCKED`.

### Карта backend-ов Cinder

NFS не является обязательным. Единственный authority — plural map
`live_discovery_storage_backends`. Для каждого entry нужны ровно `kind`, оба
delegate, оба scope и template:

```yaml
live_discovery_storage_backends:
  primary-rbd:
    kind: rbd
    source_delegate: compute-023
    target_delegate: target-storage-01
    allowed_scopes: [source-compute, target-storage]
    probe_template: rbd
```

Поддержаны NFS/file (`probe_template: nfs`), RBD (`rbd`) и LVM (`lvm`). Для
iSCSI, Fibre Channel и vendor backend указывать фактический `kind` и
`probe_template: unsupported`: они остаются типизированным evidence, но дают
`UNKNOWN`, пока не реализован и не reviewed отдельный read-only probe. Empty
map `{}` разрешён generic inventory, но не доказывает storage readiness и
поэтому также даёт `UNKNOWN`. В одной side phase все backend entries должны
использовать одного explicit delegate.

Probe configs имеют contract `openstack-rehome-probe-config/v1alpha1` и
содержат `storage` плюс `glance`. Storage item обязан согласоваться с inventory
по backend ID, kind и scope (`source-compute`/`target-storage`). Discovery не
mount-ит NFS, не map-ит RBD, не активирует LV и не устанавливает iSCSI/FC
session.

### Копируемые source/target probe JSON

Ниже полные структурно валидные примеры. Перед запуском заменить UUID, paths,
pool/VG names, sizes, endpoints и store IDs реальными live значениями. Каждый
`backend_id` должен существовать в `live_discovery_storage_backends`; allowlist
должен быть узким и включать фактический resource.

<!-- source-probe-config.json -->
```json
{
  "schema_version": "openstack-rehome-probe-config/v1alpha1",
  "storage": [
    {
      "volume_id": "11111111-1111-4111-8111-111111111111",
      "scope": "source-compute",
      "kind": "nfs",
      "backend_id": "shared-nfs",
      "resource": {
        "path": "/var/lib/nova/mnt/cinder/volume-11111111-1111-4111-8111-111111111111",
        "allowed_roots": ["/var/lib/nova/mnt/cinder"],
        "expected_size": 1073741824
      }
    },
    {
      "volume_id": "22222222-2222-4222-8222-222222222222",
      "scope": "source-compute",
      "kind": "rbd",
      "backend_id": "ceph-rbd",
      "resource": {
        "pool": "volumes",
        "allowed_pools": ["volumes"],
        "image": "volume-22222222-2222-4222-8222-222222222222",
        "expected_size": 1073741824
      }
    },
    {
      "volume_id": "33333333-3333-4333-8333-333333333333",
      "scope": "source-compute",
      "kind": "lvm",
      "backend_id": "local-lvm",
      "resource": {
        "vg": "cinder-volumes",
        "allowed_vgs": ["cinder-volumes"],
        "lv": "volume-33333333-3333-4333-8333-333333333333",
        "expected_size": 1073741824
      }
    }
  ],
  "glance": {
    "endpoint_url": "https://glance-source.example",
    "token_env": "LIVE_DISCOVERY_GLANCE_TOKEN",
    "images": [
      {
        "image_id": "44444444-4444-4444-8444-444444444444",
        "expected_size": 2147483648,
        "required": true,
        "store_ids": ["rbd-images"]
      }
    ],
    "store_capabilities": [
      {"store_id": "rbd-images", "backend_type": "rbd"}
    ]
  }
}
```

<!-- target-probe-config.json -->
```json
{
  "schema_version": "openstack-rehome-probe-config/v1alpha1",
  "storage": [
    {
      "volume_id": "11111111-1111-4111-8111-111111111111",
      "scope": "target-storage",
      "kind": "nfs",
      "backend_id": "shared-nfs",
      "resource": {
        "path": "/srv/cinder/volume-11111111-1111-4111-8111-111111111111",
        "allowed_roots": ["/srv/cinder"],
        "expected_size": 1073741824
      }
    },
    {
      "volume_id": "22222222-2222-4222-8222-222222222222",
      "scope": "target-storage",
      "kind": "rbd",
      "backend_id": "ceph-rbd",
      "resource": {
        "pool": "volumes",
        "allowed_pools": ["volumes"],
        "image": "volume-22222222-2222-4222-8222-222222222222",
        "expected_size": 1073741824
      }
    },
    {
      "volume_id": "33333333-3333-4333-8333-333333333333",
      "scope": "target-storage",
      "kind": "lvm",
      "backend_id": "local-lvm",
      "resource": {
        "vg": "cinder-volumes",
        "allowed_vgs": ["cinder-volumes"],
        "lv": "volume-33333333-3333-4333-8333-333333333333",
        "expected_size": 1073741824
      }
    }
  ],
  "glance": {
    "endpoint_url": "https://glance-target.example",
    "token_env": "LIVE_DISCOVERY_GLANCE_TOKEN",
    "images": [
      {
        "image_id": "44444444-4444-4444-8444-444444444444",
        "expected_size": 2147483648,
        "required": true,
        "store_ids": ["rbd-images"]
      }
    ],
    "store_capabilities": [
      {"store_id": "rbd-images", "backend_type": "rbd"}
    ]
  }
}
```

Один configured delegate на стороне выполняет обе семьи: Cinder backing probes
и Glance Range probes. Поэтому endpoint/token также должны быть доступны с
`source_delegate`/`target_delegate`, а не только с controller.

### Inventory, Vault и extra-vars для protected paths

Inventory связывает общий Kolla variable с отдельным path каждого controller и
задаёт authoritative typed backend map:

```yaml
all:
  vars:
    live_discovery_kolla_passwords_file_local: >-
      {{ live_discovery_kolla_passwords_files[inventory_hostname] }}
    live_discovery_storage_backends:
      shared-nfs:
        kind: nfs
        source_delegate: os1-compute-02
        target_delegate: os2-ctrl-01
        allowed_scopes: [source-compute, target-storage]
        probe_template: nfs
      ceph-rbd:
        kind: rbd
        source_delegate: os1-compute-02
        target_delegate: os2-ctrl-01
        allowed_scopes: [source-compute, target-storage]
        probe_template: rbd
      local-lvm:
        kind: lvm
        source_delegate: os1-compute-02
        target_delegate: os2-ctrl-01
        allowed_scopes: [source-compute, target-storage]
        probe_template: lvm
```

Файл `/secure/live-discovery-paths.vault.yml` содержит все caller-owned paths:

```yaml
live_discovery_kolla_passwords_files:
  os1-ctrl-01: /secure/os1/passwords.yml
  os2-ctrl-01: /secure/os2/passwords.yml
source_clouds_file_local: /secure/os1/clouds.yaml
target_clouds_file_local: /secure/os2/clouds.yaml
live_discovery_phase_hmac_key_file_local: /secure/live-discovery/phase-hmac.key
live_discovery_source_probe_config_file_local: /secure/live-discovery/source-probe-config.json
live_discovery_target_probe_config_file_local: /secure/live-discovery/target-probe-config.json
live_discovery_source_glance_token_file_local: /secure/live-discovery/source-glance.token
live_discovery_target_glance_token_file_local: /secure/live-discovery/target-glance.token
live_discovery_source_cinder_sensitive_evidence_file_local: /secure/live-discovery/source-cinder-sensitive.json
live_discovery_target_cinder_sensitive_evidence_file_local: /secure/live-discovery/target-cinder-sensitive.json
live_discovery_target_online_migration_evidence_file_local: /secure/live-discovery/target-online-migrations.json
```

Подготовка и запуск:

```bash
chmod 0600 /secure/os1/clouds.yaml /secure/os1/passwords.yml
chmod 0600 /secure/os2/clouds.yaml /secure/os2/passwords.yml
chmod 0600 /secure/live-discovery/*
chmod 0600 /secure/live-discovery-paths.vault.yml
ansible-vault encrypt /secure/live-discovery-paths.vault.yml
ansible-playbook -i inventory/lab-os1-to-os2.yml \
  playbooks/02b-discover-live-resource-graph.yml \
  --ask-vault-pass \
  -e @/secure/live-discovery-paths.vault.yml \
  -e live_discovery_run_id=rehome-20260712-review01
```

Пути Cinder evidence условно обязательны: если selected volume имеет active
attachment, для каждой пары `(volume_uuid, attachment_uuid)` нужен защищённый
entry, иначе closure останется `BLOCKED/UNKNOWN`. Если активных attachments на
стороне нет, соответствующий path можно оставить `""`. Migration envelope
формально optional input, но свежий matching файл фактически обязателен, чтобы
canonical target profile не остался `UNKNOWN`; playbook его не генерирует и
`online_data_migrations` не запускает.

### Итоговые verdict

```text
READY=0
READY_WITH_WARNINGS=0
UNKNOWN=2
BLOCKED=3
```

`UNKNOWN` — fail-closed и запрещает дальнейший import/cutover. Точные файлы и
retention описаны в
[`docs/live-discovery-artifacts-ru.md`](docs/live-discovery-artifacts-ru.md),
а Cinder/Glance детали — в
[`cinder-rehome-readiness-ru.md`](cinder-rehome-readiness-ru.md) и
[`glance-rehome-readiness-ru.md`](glance-rehome-readiness-ru.md).

Authoritative schema gate — resource-scoped directional mapping из
`schema-mapping.json`, созданный `02b`. Для `keystack-2025.1` →
`vanilla-openstack-2025.1-epoxy` полное равенство source/target schema не
требуется. `03a`/`03b` — необязательная legacy-диагностика полного diff для
близких/same-schema кластеров, а не prerequisite или hard gate.

## Inventory

Минимальные группы Ansible:

```yaml
source_control:
  hosts:
    source-ctrl-01:
      ansible_host: 10.0.0.11

target_control:
  hosts:
    target-ctrl-01:
      ansible_host: 10.1.0.11

target_reference_compute:
  hosts:
    target-compute-01:
      ansible_host: 10.1.1.21

rehome_compute:
  hosts:
    compute-023:
      ansible_host: 10.2.0.23
```

Обязательные identity-параметры:

```yaml
rehome_host: compute-023
hypervisor_hostname: compute-023
instances_path: /var/lib/nova/instances
```

`rehome_host` должен совпадать с canonical host identity в Nova source control
plane: `openstack compute service list --host <name>` и
`openstack server list --all-projects --host <name>` должны возвращать нужный
compute и его ВМ. В lab это FQDN `os1-compute-02.example.local`, хотя Ansible
host называется `os1-compute-02`. `hypervisor_hostname` должен совпадать с тем,
как host зарегистрирован в Nova и Placement. Нельзя менять эти значения во
время cutover.

## OpenStack admin access

Нужно подготовить один из вариантов:

- `OS_CLOUD` entries для source и target;
- или `openrc_file` на control nodes;
- или Kolla `clouds.yaml`/`admin-openrc.sh`, если команды выполняются из
  `kolla_toolbox`.

Inventory-переменные:

```yaml
use_os_cloud: true
source_os_cloud: source-admin
target_os_cloud: target-admin
```

или:

```yaml
use_os_cloud: false
openrc_file: /etc/kolla/admin-openrc.sh
```

Admin access нужен для:

- freeze source compute service;
- сбора host-scoped manifest ВМ через `02a-build-rehome-manifest.yml`;
- проверки Neutron ports/security groups;
- проверки Nova services;
- Neutron rebind;
- Placement/Nova validation.

Для `02a-build-rehome-manifest.yml` в Kolla-окружении нужно явно задать:

```yaml
openstack_cli_container: kolla_toolbox
source_clouds_file_local: /path/to/source/etc-kolla/clouds.yaml
target_clouds_file_local: /path/to/target/etc-kolla/clouds.yaml
source_cloud_name: kolla-admin
target_cloud_name: kolla-admin
```

Эти файлы копируются playbook-ом на соответствующий control node и затем внутрь
`kolla_toolbox`. Секреты из `clouds.yaml` не должны попадать в git.

## Kolla/OpenStack commands

В каждой инфраструктуре нужно определить, где выполняются manage-команды.

Host-level пример:

```yaml
schema_compat_nova_manage_command: nova-manage
schema_compat_neutron_db_manage_command: neutron-db-manage
schema_compat_cinder_manage_command: cinder-manage
```

Kolla container пример:

```yaml
schema_compat_nova_manage_command: docker exec nova_api nova-manage
schema_compat_neutron_db_manage_command: docker exec neutron_server neutron-db-manage
schema_compat_cinder_manage_command: docker exec cinder_api cinder-manage
```

Для compute runtime guard нужно определить `virsh` command:

```yaml
runtime_guard_virsh_command: virsh
```

или для Kolla:

```yaml
runtime_guard_virsh_command: docker exec nova_libvirt virsh
```

## DB names

Нужно определить фактические имена БД из service configs, а не брать их из
примера.

Проверять в:

- `nova.conf`: `[database] connection`, `[api_database] connection`;
- `neutron.conf`: `[database] connection`;
- `cinder.conf`: `[database] connection`;
- `placement.conf`: `[placement_database] connection`.

Пример:

```yaml
schema_compat_db_names:
  - keystone
  - nova_api
  - nova_cell0
  - nova
  - neutron
  - cinder
  - placement
```

В разных окружениях рабочая Nova cell DB может называться `nova`, `nova_cell1`
или иначе. `nova_cell0` обычно служит для unscheduled/error instances и не
заменяет рабочую cell DB. Это должно быть задано явно.

## DB credentials

Для необязательной legacy-диагностики
`03a-check-db-schema-compat.yml` нужен read-only доступ к `information_schema`
по критичным БД. Этот full-schema tool не заменяет directional mapping `02b`.
Есть два рабочих варианта.

### Вариант 1: общий DB admin/read-only user

Задается команда:

```yaml
schema_compat_mysql_query_command: >-
  mysql --defaults-extra-file=/root/.my.cnf --batch --raw --skip-column-names
schema_compat_mysql_query_no_log: false
```

Файл defaults должен существовать на соответствующем DB/control host и давать
доступ к `information_schema`.

### Вариант 2: Kolla service users

Для Kolla часто удобнее использовать service DB users и passwords из локального
`passwords.yml`. Значения секретов не выводятся, tasks идут с `no_log`.

Пример:

```yaml
schema_compat_mysql_query_command: >-
  docker exec -e MYSQL_PWD="$SCHEMA_COMPAT_DB_PASSWORD" -i mariadb
  mysql -u"$SCHEMA_COMPAT_DB_USER" -h "$SCHEMA_COMPAT_DB_HOST"
  --batch --raw --skip-column-names
schema_compat_mysql_query_no_log: true
schema_compat_kolla_passwords_file_local: /path/to/etc-kolla/passwords.yml
schema_compat_mysql_host: 10.0.0.90
schema_compat_mysql_service_queries:
  - label: keystone
    user: keystone
    password_key: keystone_database_password
    db_names:
      - keystone
  - label: nova_api
    user: nova_api
    password_key: nova_api_database_password
    db_names:
      - nova_api
  - label: nova_cell
    user: nova
    password_key: nova_database_password
    db_names:
      - nova_cell0
      - nova
  - label: neutron
    user: neutron
    password_key: neutron_database_password
    db_names:
      - neutron
  - label: cinder
    user: cinder
    password_key: cinder_database_password
    db_names:
      - cinder
  - label: placement
    user: placement
    password_key: placement_database_password
    db_names:
      - placement
```

Для `04c-collect-source-db-rows.yml` дополнительно нужен список service users,
которыми можно читать строки из source DB:

```yaml
source_db_rows_nova_cell_db_name: nova
source_db_row_service_queries:
  - label: keystone
    user: keystone
    password_key: keystone_database_password
    sql_file: keystone.sql
  - label: neutron
    user: neutron
    password_key: neutron_database_password
    sql_file: neutron.sql
  - label: cinder
    user: cinder
    password_key: cinder_database_password
    sql_file: cinder.sql
  - label: nova_api
    user: nova_api
    password_key: nova_api_database_password
    sql_file: nova_api.sql
  - label: nova_cell
    user: nova
    password_key: nova_database_password
    sql_file: nova_cell.sql
```

`source_db_rows_nova_cell_db_name` должен указывать именно на рабочую Nova cell
DB с running instances, а не на `nova_cell0`, если running instances хранятся в
другой БД.

Требования:

- local `passwords.yml` должен соответствовать именно этому кластеру;
- `schema_compat_mysql_host` должен совпадать с host/VIP из service DB grants;
- service user должен видеть `information_schema` для своей БД;
- secrets нельзя коммитить в репозиторий.

## Backup/import DB access

Для destructive этапов нужны отдельные credentials:

- backup source DB;
- backup target DB перед import;
- import reviewed host-scoped SQL в target.

Это может быть DB admin defaults file:

```yaml
mysql_defaults_file: /root/.my.cnf
```

или отдельная Kolla-aware реализация backup/import через `mariadb` container.
Перед реальным import обязательно должен быть backup target DB.

Для `04f-backup-target-db.yml` нужен доступ к target MariaDB из Kolla
`mariadb` container. Штатный вариант для Kolla - unix socket внутри контейнера;
это обходит VIP/ProxySQL и правила вида `root@<vip>`, которые могут запрещать
root login:

```yaml
target_db_backup_container: mariadb
target_db_backup_user: root
target_db_backup_socket: /run/mysqld/mysqld.sock
target_db_backup_host: ""
target_db_backup_password_key: database_password
target_db_names:
  - keystone
  - nova_api
  - nova_cell0
  - nova
  - neutron
  - cinder
  - placement
```

Если в другом окружении socket другой, его нужно переопределить. Если backup
должен идти по TCP, задайте `target_db_backup_socket: ""` и явно укажите
`target_db_backup_host`; это должен быть адрес, с которого выбранный DB user
реально имеет права на dump всех нужных БД.

Для `04g-apply-target-sql.yml` и `04h-normalize-target-metadata.yml` оператор
должен отдельно задать target-specific маппинги. Это значения, которые не
должны слепо переноситься из source DB:

```yaml
target_db_import_column_replacements:
  - table: nova_api.host_mappings
    column: cell_id
    value: "6"
  - table: nova_api.instance_mappings
    column: cell_id
    value: "6"
  - table: cinder.volumes
    column: volume_type_id
    value: 81bf219f-8f67-493b-927f-215176983345

target_metadata_normalizations:
  - name: cinder-default-volume-type
    schema: cinder
    table: volumes
    column: volume_type_id
    old: 59cbeca1-1937-4a44-be09-f612dc4d0373
    new: 81bf219f-8f67-493b-927f-215176983345
    where_column: id
    where_values:
      - 15c47caf-e3e0-4b14-86f0-a1bbc97d4256
```

Типичные значения для такой нормализации: Nova cell `cell_id`, Cinder
`service_uuid`, Cinder `volume_type_id`, backend host/service identifiers. Если
они не совпадают с target, target API может видеть instance/port, но падать на
volume или attachment lookup.

## Service classification

Оператор обязан классифицировать сервисы re-home host.

Pre-cutover source-only allowlist:

```yaml
source_only_containers: []
source_only_systemd_units: []
```

Cutover switch services:

```yaml
source_runtime_switch_containers:
  - nova_compute
  - neutron_openvswitch_agent

target_runtime_switch_containers:
  - neutron_openvswitch_agent
  - nova_compute
```

Dataplane keep list:

```yaml
dataplane_keep_containers:
  - nova_libvirt
  - openvswitch_db
  - openvswitch_vswitchd
  - iscsid
  - multipathd
```

Если Kolla container управляется systemd unit, нужно указывать и unit, например:

```yaml
source_only_systemd_units:
  - kolla-hacluster_pacemaker_remote-container.service
source_only_containers:
  - hacluster_pacemaker_remote
```

Иначе `docker stop` может пройти, но systemd сразу поднимет container обратно.

## Runtime guard inputs

Нужно задать внешнюю проверку доступности ВМ:

```yaml
runtime_guard_enabled: true
runtime_guard_probe_delegate: localhost
runtime_guard_probe_targets:
  - name: vm-01
    ip: 192.168.10.100
    required: true
```

`runtime_guard_probe_delegate` должен быть узлом, с которого проверяется
реальная сетевая доступность ВМ. Для production лучше использовать внешний
probe host, а не сам compute host.

## Network inputs

Перед re-home нужно описать:

- source network backend: OVS, OVN, Linux Bridge, SR-IOV или hybrid;
- provider network mappings;
- bridge/interface names;
- physnet names;
- Neutron network/subnet/port UUIDs;
- fixed IP, MAC, security groups;
- DHCP on/off;
- route/gateway/DNS внутри guest.

Пример:

```yaml
network_backend: ovs
```

Для OVS/OVN нельзя считать достаточным совпадение IP/MAC. Важны port UUID,
binding и существующие tap/vif устройства.

Для сохранения непрерывности сети target Neutron должен иметь не только
API-visible port с тем же fixed IP, но и полноценную ML2 binding model для
этого port UUID. Перед cutover нужно проверить `ml2_port_bindings`,
`ml2_port_binding_levels`, `networksegments` и registration target network
agent для `rehome_host`. Если target OVS agent пишет `Device <port_uuid> is not
bound`, запуск target network agent может почистить OVS flows и оборвать ping
до running VM. Подробно: `neutron-rehome-behavior-ru.md`.

## Identity and Horizon visibility inputs

Перед re-home нужно явно решить, как переносится tenant identity:

- сохраняем source `project_id`/`user_id` и импортируем соответствующие
  Keystone project/user/role assignments в target;
- или нормализуем imported Nova/Neutron/Cinder metadata на существующий target
  project/user.

Для Horizon это критично: target `Project -> Compute -> Instances`
(`/project/instances/`) показывает только instances текущего project scope.
Если target Nova API видит ВМ, но `openstack project show
<server.project_id>` не находит project, project-страница Horizon не покажет
ВМ. Admin/API-level проверка `server list --all-projects` при этом может
проходить.

Для каждого переносимого instance нужно знать:

- source `project_id` и `user_id`;
- source project/user names и domain;
- target project/user UUID, если выполняется normalization;
- role assignments, которые нужны оператору в target Horizon;
- ожидаемый Horizon project, в котором оператор должен увидеть ВМ.

Подробно: `horizon-rehome-visibility-ru.md`.

## Image tags and configs

Если source и target используют разные Kolla image tags, нужно задать:

- source registry/namespace/tag;
- target registry/namespace/tag;
- список target images для pre-pull;
- путь staging target configs;
- порядок переключения network agent перед `nova_compute`.

Target images скачиваются до cutover, но active containers переключаются на
target tag только во время cutover.

## Local artifacts

Нужно задать, куда складывать отчеты:

```yaml
rehome_stage_dir: /var/tmp/openstack-rehome
manifest_remote_dir: /var/tmp/openstack-rehome/manifest
schema_compat_report_dir: /var/tmp/openstack-rehome/schema-compat
schema_compat_local_artifact_dir: /path/to/artifacts/schema-compat/source-to-target
target_prep_remote_dir: /var/tmp/openstack-rehome/target-api-prep
local_artifact_dir: /path/to/artifacts/compute-023
manifest_file: /path/to/artifacts/compute-023/rehome_manifest.yml
db_import_sql_review_dir: /path/to/artifacts/compute-023/target-db-import-sql-review
source_db_rows_nova_cell_db_name: nova
target_preimport_guard_fail_on_conflict: true
```

Remote `rehome_stage_dir` должен быть на диске с достаточным местом и не должен
очищаться между preflight, backup, schema check и cutover.

## Что нельзя подавать неявно

Нельзя оставлять значения из lab-примера:

- IP адреса control/compute/VIP;
- `schema_compat_mysql_host`;
- `schema_compat_kolla_passwords_file_local`;
- DB names;
- `source_only_*`;
- `runtime_guard_probe_targets`;
- image tags;
- `target_cell_uuid`;
- provider network names.

Если эти значения неизвестны, сначала запускается discovery/audit, а не
cutover.

## Минимальный checklist перед запуском

- Inventory содержит singleton `source_control`, `target_control`,
  `rehome_compute`, `target_reference_compute`.
- SSH/become работает на всех нужных hosts.
- `rehome_host` совпадает с Nova host.
- На re-home host есть running libvirt domains.
- Runtime guard видит ВМ и может пинговать probe IP.
- DB names проверены по service configs.
- DB credentials дают доступ к `information_schema`.
- Все обязательные live discovery protected inputs имеют owner uid, mode
  `0600`, не являются symlink; source/target Glance tokens различаются.
- `live_discovery_storage_backends` отражает реальные backend kinds и probe
  delegates; пустая карта осознанно означает `UNKNOWN`.
- `02b-discover-live-resource-graph.yml` завершился с `READY` или
  `READY_WITH_WARNINGS`; восемь normal artifacts и evidence index проверены.
- Cinder, Glance, Neutron и target Epoxy capability не содержат
  `UNKNOWN`/`BLOCKED`; Masakari/DRS не ожидаются в графе.
- Только после live discovery можно переходить к следующим пунктам.
- Если нужна дополнительная диагностика, необязательные legacy `03a`/`03b`
  выполнены и их полный diff сохранён; их rc не заменяет gate `02b`.
- `04a-plan-target-api-prep.yml` сформировал target API prep report.
- `04b-plan-db-metadata-import.yml` сформировал DB metadata import review-pack.
- `04c-collect-source-db-rows.yml` собрал source DB rows для review.
- `04d-generate-target-sql-draft.yml` сформировал hard-stopped SQL draft.
- `04e-target-preimport-guard.yml` подтвердил отсутствие target DB конфликтов.
- `04f-backup-target-db.yml` сохранил target DB backup перед import.
- `04g-apply-target-sql.yml` применен только после review и backup.
- `04h-normalize-target-metadata.yml` применен для target-specific UUID/FK, если такие отличия есть.
- `04j-ensure-neutron-ml2-binding-levels.yml` подтвердил наличие target ML2 binding levels для переносимых Neutron ports.
- `04k-ensure-nova-compute-service.yml` подтвердил наличие target Nova compute service row для `rehome_host`.
- `04l-normalize-target-project-visibility.yml` применен, если выбран target project/user normalization вместо Keystone identity import.
- Target Nova API показывает ВМ через `server show` и `server list --all-projects`.
- Target Keystone содержит project из `server.project_id`, либо явно выбран и применен target project/user normalization.
- Source-only services явно классифицированы.
- Dataplane keep list проверен.
- Target metadata import SQL подготовлен и review completed.
- Rollback authority: source DB/configs/backups сохранены.
