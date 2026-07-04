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

Для `03a-check-db-schema-compat.yml` нужен read-only доступ к `information_schema`
по критичным БД. Есть два рабочих варианта.

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

- Inventory содержит `source_control`, `target_control`, `rehome_compute`.
- SSH/become работает на всех нужных hosts.
- `rehome_host` совпадает с Nova host.
- На re-home host есть running libvirt domains.
- Runtime guard видит ВМ и может пинговать probe IP.
- DB names проверены по service configs.
- DB credentials дают доступ к `information_schema`.
- `03a-check-db-schema-compat.yml` проходит.
- `03b-normalize-schema-diff.yml` проходит или diff вручную классифицирован.
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
