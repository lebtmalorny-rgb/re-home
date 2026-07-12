# Логика playbook-ов re-home

Этот документ описывает, что делает каждый playbook, где он выполняется и какие
изменения применяет. Команды запускаются с Ansible runner, обычно из каталога
репозитория:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/<name>.yml
```

Фактическое место выполнения задает `hosts:` внутри playbook:

- `localhost` - локальная подготовка artifacts и SQL review files;
- `source_control` - control plane source-кластера;
- `target_control` - control plane target-кластера;
- `target_reference_compute` - штатный compute host target-кластера, с
  которого берется full Kolla config bundle для таких же runtime containers;
- `rehome_compute` - compute host с работающими ВМ.

## Kolla-Ansible и применение изменений

В cutover window изменения не применяются полным `kolla-ansible reconfigure`.
Для re-home это слишком широкий механизм: он может перегенерировать или
перезапустить больше сервисов, чем нужно, а нам нельзя трогать libvirt/QEMU,
OVS dataplane и storage helpers.

Штатная логика для Kolla такая:

1. До cutover подготовить target images и full target Kolla config bundle для
   runtime containers.
2. Положить target configs в staging на re-home host:

   ```text
   /var/tmp/openstack-rehome/target-config-stage/kolla/nova-compute/
   /var/tmp/openstack-rehome/target-config-stage/kolla/neutron-openvswitch-agent/
   ```

3. Во время cutover `06-cutover-compute.yml` сам:
   - проверяет наличие `config.json` и safe-mode в staged `nova.conf`;
   - делает backup текущих `/etc/kolla/<service>`;
   - копирует staged target configs в `/etc/kolla/<service>`;
   - останавливает только source runtime containers;
   - запускает target-tag network container, затем target-tag `nova_compute`.

`kolla-ansible` можно использовать до cutover для подготовки configs/images или
после burn-in для возврата host под штатное управление target deployment. В
самом cutover используется guarded playbook, а не полный `reconfigure`.

## Общие правила

- Любой destructive или state-changing шаг должен иметь явный apply-флаг либо
  быть заранее классифицирован как безопасный.
- Во время cutover `nova_libvirt`, running QEMU, `openvswitch_db`,
  `openvswitch_vswitchd`, active storage sessions и local instance disks не
  останавливаются. После burn-in host containers можно приводить к target-tag
  отдельным guarded шагом `12`, по одному контейнеру и с runtime guard.
- Target `nova_compute` стартует только в safe-mode.
- Source и target `nova_compute` не должны работать одновременно.
- Source DB/configs остаются rollback authority до завершения burn-in.

## Playbooks

### `00-preflight.yml`

- **Где выполняется:** `rehome_compute`, затем `target_control[0]`.
- **Назначение:** базовая проверка, что compute host и target control plane
  выглядят пригодными для re-home.
- **Что читает:** `/etc/nova/nova.conf`, `instances_path`, libvirt domains,
  версии Nova/Neutron/Cinder DB на target.
- **Что меняет:** только создает stage directories на compute.
- **Guards:** проверяет `CONF.host == rehome_host`, `instances_path`, наличие
  running domains.
- **Важно для Kolla:** текущая skeleton-версия использует host-level `virsh` и
  management commands; для Kolla-lab предпочтительнее использовать более новые
  manifest/schema playbooks, где команды параметризованы.

### `01-freeze-source.yml`

- **Где выполняется:** `source_control[0]`, часть задач делегируется
  `localhost`.
- **Назначение:** выключить source `nova-compute` из scheduling, чтобы на
  re-home host не попали новые ВМ.
- **Что читает:** source OpenStack API.
- **Что меняет:** `openstack compute service set --disable` для source
  `nova-compute`.
- **Artifacts:** `source_servers.json` в `local_artifact_dir`.
- **Guard:** падает, если на source host не найдено серверов.

### `02-collect-inventory.yml`

- **Где выполняется:** `rehome_compute`, затем `localhost`.
- **Назначение:** собрать compute-local inventory и OpenStack source/target API
  state старым helper-путем.
- **Что читает:** libvirt XML, ip/OVS/OVN state, storage/Pci state,
  `instances_path`.
- **Что меняет:** только пишет inventory artifacts.
- **Artifacts:** `compute-inventory.tar.gz` и JSON/API exports в
  `local_artifact_dir`.
- **Комментарий:** для старых helper-фаз manifest entrypoint — необязательный
  `02a-build-rehome-manifest.yml`; обязательный gate всего workflow — `02b`.

### `02a-build-rehome-manifest.yml`

- **Где выполняется:** `localhost`, `source_control[0]`, `target_control[0]`,
  `rehome_compute`.
- **Назначение:** собрать единый host-scoped manifest для re-home.
- **Что читает:** source API, target API pre-state, compute runtime state.
- **Что меняет:** не меняет OpenStack state; копирует временные collectors и
  `clouds.yaml` на control nodes.
- **Artifacts:** `rehome_manifest.yml`, `rehome_manifest.json`, tar.gz
  manifests source/target/compute.
- **Guard:** требует `source_clouds_file_local`, `target_clouds_file_local`,
  cloud names и working `runtime_guard_virsh_command`.

### `02b-discover-live-resource-graph.yml`

- **Где выполняется:** семь plays в строгом порядке: `localhost`,
  `source_control`, `target_control`, `rehome_compute`,
  `target_reference_compute`, снова `localhost` для probe/combine и
  `localhost` для assembly. Каждая inventory role — singleton. Storage/Glance
  probes делегируются только на host из `live_discovery_storage_backends`; при
  пустой карте стороны используют controller и storage readiness остаётся
  `UNKNOWN`.
- **Назначение:** обязательный read-only gate перед любым DB import/cutover.
  Он строит graph по живому source `keystack-2025.1` и canonical target
  `vanilla-openstack-2025.1-epoxy`. SQL dump не является источником данных и
  может быть только fixture. Masakari/DRS исключены.
- **Schema gate:** authoritative результат — resource-scoped directional
  mapping из `schema-mapping.json`. Для Keystack → Epoxy полное равенство
  source/target schema не требуется. `03a`/`03b` — необязательная
  legacy-диагностика полного diff, а не hard gate.
- **Порядок фаз:** первая подписанная `--phase api` определяет roots и UUID
  filters. Публичная `--phase verify` сверяет HMAC, API/filter/plan envelopes,
  live `information_schema`, exact query coverage, SQL и plan digest до записи
  SQL: это verify-before-SQL. Только `verified-plan.json` позволяет выполнить
  UUID-scoped SELECT/JSONL. После runtime/capability и storage/Glance probes
  HMAC-bound phase triplets возвращаются контроллерам; `--phase combine`
  вызывает реальные Nova/Neutron/Cinder/Glance collectors. Последний play
  запускает local assembler.
- **Что читает:** OpenStack API; `information_schema`; scoped SELECT Nova,
  Neutron, Cinder; libvirt/QEMU и OVS/OVN; target image refs/digests/revisions;
  Cinder backing object; Glance `Range: bytes=0-0`. Source roots выводятся из
  live API, операторский/dump-backed root manifest отсутствует.
- **Что меняет:** только owned remote/local staging и artifacts. OpenStack/SQL
  state, services и data не меняются. Все probe-команды имеют
  `changed_when: false`; исключение — создание/завершение собственного
  owner-lock. `online_data_migrations` не запускаются. Опциональный свежий
  migration evidence только доказывает ранее выполненную оператором проверку и
  exact Nova/Neutron/Cinder/Glance revisions.
- **Защита:** HMAC key, clouds/passwords, probe configs, source/target Glance
  tokens, optional Cinder/migration evidence — caller-owned regular files mode
  `0600`. Source и target tokens различны. Они один раз открываются без symlink,
  замораживаются в owned boundary `0700`; raw values не попадают в normal
  artifacts. На success frozen secrets удаляются и completed owner остаётся;
  rescue/unreachable cleanup удаляет только собственный incomplete owner.
  Concurrent run с тем же `run-id` отклоняется.
- **Artifacts:** assembler атомарно публикует ровно
  `resource-graph.json`, `resource-graph.yml`, `readiness-report.json`,
  `readiness-report.md`, `schema-capabilities.json`, `schema-mapping.json`,
  `uuid-filters.json`, `evidence-index.json`; опционально
  `sensitive/evidence.json` (`0700`/`0600`). Промежуточные
  `source-control.json`, `target-control.json`, `runtime.json` и phase files не
  входят в финальный normal set.
- **Verdict:** `READY=0`, `READY_WITH_WARNINGS=0`, `UNKNOWN=2`, `BLOCKED=3`.
  Top-level play принимает только rc `0`. Runtime collector rc `2` допускается
  как промежуточный semantic verdict только после contract validation; local
  assembler сохраняет его как итоговый fail-closed `UNKNOWN/BLOCKED`.
- **Storage:** NFS не обязателен. NFS/file, RBD и LVM имеют безопасные
  read-only size probes; iSCSI, Fibre Channel и vendor drivers остаются
  типизированными, но дают `UNKNOWN` без reviewed probe template.
- **Документация:** [data flow](docs/live-discovery-data-flow-ru.md),
  [artifacts](docs/live-discovery-artifacts-ru.md),
  [operator inputs](operator-inputs-ru.md).

### `03-backup-databases.yml`

- **Где выполняется:** `source_control[0]`, `target_control[0]`.
- **Назначение:** generic DB backup source и target.
- **Что читает:** DB через `mysql_defaults_file`.
- **Что меняет:** пишет dumps в `/var/backups/openstack-rehome/<rehome_id>/`.
- **Artifacts:** `source-full.sql`, `source-schema.sql`,
  `target-preimport-full.sql`, `target-preimport-schema.sql`.
- **Комментарий:** для Kolla-lab предпочтителен `04f-backup-target-db.yml`,
  потому что он ходит в MariaDB через container socket.

### `03a-check-db-schema-compat.yml`

- **Где выполняется:** `source_control[0]`, `target_control[0]`, затем
  `localhost`.
- **Назначение:** legacy-диагностика полного DB schema diff и migration heads
  для близких/same-schema кластеров. Authoritative resource-scoped directional
  mapping создаёт `02b` в `schema-mapping.json`; полное равенство Keystack и
  Epoxy не требуется.
- **Что читает:** Nova/Neutron/Cinder migration versions и
  `information_schema`.
- **Что меняет:** только local artifacts.
- **Artifacts:** `artifacts/schema-compat/<source>-to-<target>/`.
- **Guard:** сам legacy-инструмент падает, если migration versions или полный
  `information_schema` отличаются. Этот rc не является hard gate для
  Keystack → Epoxy и не заменяет verdict `02b`.

### `03b-normalize-schema-diff.yml`

- **Где выполняется:** `localhost`.
- **Назначение:** необязательная legacy-диагностика: убрать шум из полного
  schema diff после `03a`.
- **Что читает:** artifacts `03a`.
- **Что меняет:** только normalized artifacts.
- **Artifacts:** `normalized/`, `normalized-diffs/`,
  `normalization-summary.txt`.
- **Guard:** если normalized diff остается непустым, playbook падает.

### `04-prepare-target-control-plane.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** legacy/skeleton шаг для optional DB sync и direct SQL import.
- **Что меняет:** только если явно включены `allow_target_db_sync` или
  `allow_target_sql_import`.
- **Guard:** по умолчанию ничего destructive не делает и выводит сообщение, что
  `sql-skeleton/` является только reference.
- **Комментарий:** для текущего lab основной путь: `04a`-`04h`, а не прямой
  import из `sql-skeleton`.

### `04a-plan-target-api-prep.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** построить report-first план подготовки target API из
  `rehome_manifest.json`.
- **Что читает:** manifest, target `clouds.yaml`, target OpenStack API.
- **Что меняет:** по умолчанию ничего; при `target_prep_apply=true` применяет
  только API-safe действия.
- **Artifacts:** `target-api-prep-report.json`, `target-api-prep-report.yml`.
- **Guard:** missing resources, которые нельзя безопасно создать через API с
  исходными UUID, помечаются как `requires_existing_or_db_import`.

### `04b-plan-db-metadata-import.yml`

- **Где выполняется:** `localhost`.
- **Назначение:** построить review-pack для target DB metadata import.
- **Что читает:** `rehome_manifest.json` и `target-api-prep-report.json`.
- **Что меняет:** только local plan/review artifacts.
- **Artifacts:** `target-db-import-plan.*`,
  `target-db-import-sql-review/`.
- **Guard:** не подключается к DB и не применяет SQL.

### `04c-collect-source-db-rows.yml`

- **Где выполняется:** source DB/control host и `localhost`.
- **Назначение:** собрать source DB rows по UUID/instance filters из import
  plan.
- **Что читает:** source DB service users из Kolla `passwords.yml`.
- **Что меняет:** только artifacts.
- **Artifacts:** `source-db-rows.tar.gz`, `source-db-rows/queries/`,
  `source-db-rows/rows/`, query manifest.
- **Guard:** выполняет только `SELECT`.

### `04d-generate-target-sql-draft.yml`

- **Где выполняется:** `localhost`.
- **Назначение:** сгенерировать target SQL draft из собранных source rows.
- **Что читает:** `source-db-rows`, `target-db-import-plan`.
- **Что меняет:** только local SQL draft.
- **Artifacts:** `target-db-import-sql-draft/`,
  `target-db-import-sql-draft-summary.*`.
- **Guard:** каждый SQL файл содержит hard-stop `SIGNAL SQLSTATE`; draft нельзя
  случайно применить.

### `04e-target-preimport-guard.yml`

- **Где выполняется:** `target_control[0]` и `localhost`.
- **Назначение:** проверить, что target DB не содержит конфликтующих rows перед
  import.
- **Что читает:** target DB по тем же UUID/filters.
- **Что меняет:** только report artifacts.
- **Artifacts:** `target-preimport-guard-report.*`,
  `target-preimport-guard/rows/`.
- **Guard:** по умолчанию падает при любых конфликтах.

### `04f-backup-target-db.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** Kolla-aware backup target DB непосредственно перед import.
- **Что читает:** target MariaDB через `mariadb` container socket
  `/run/mysqld/mysqld.sock`.
- **Что меняет:** пишет backup archive и manifest.
- **Artifacts:** `target-db-backup/<timestamp>.tar.gz`,
  `<timestamp>.manifest.json`.
- **Guard:** использует local Kolla `passwords.yml`, секреты не выводятся.

### `04g-apply-target-sql.yml`

- **Где выполняется:** сначала `localhost`, затем `target_control[0]`.
- **Назначение:** подготовить reviewed SQL и применить его в target DB.
- **Что читает:** SQL draft/review, guard report, backup manifest,
  replacement maps.
- **Что меняет:** target DB, только с `target_db_import_apply=true`.
- **Artifacts:** `target-db-import-sql-apply/`,
  `target-db-import-run/<timestamp>/`.
- **Guard:** требует clean `04e`, наличие `04f` backup, explicit apply flag;
  применяет SQL одной транзакцией через MariaDB socket.

### `04h-normalize-target-metadata.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** post-import нормализация target-specific UUID/FK, например
  `cinder.volumes.volume_type_id`.
- **Что читает:** target DB и `target_metadata_normalizations`.
- **Что меняет:** target DB, только с `target_metadata_normalize_apply=true`.
- **Artifacts:** `target-metadata-normalization/<timestamp>/report.tsv`.
- **Guard:** allowlist таблиц/колонок, report-only по умолчанию,
  идемпотентный `ROW_COUNT()`-based changed detection.

### `04j-ensure-neutron-ml2-binding-levels.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** убедиться, что target Neutron содержит
  `ml2_port_binding_levels` для port UUID переносимых ВМ.
- **Что читает:** `rehome_manifest.yml`, target Neutron DB,
  target `networksegments`, target `ml2_port_bindings`.
- **Что меняет:** target DB, только с
  `target_neutron_ml2_binding_levels_apply=true`; вставляет отсутствующие rows
  в `neutron.ml2_port_binding_levels`.
- **Artifacts:** `target-neutron-ml2-binding-levels/<timestamp>/report.tsv` и
  `manifest.json`.
- **Guard:** OVS-only, явный apply flag, idempotent `NOT EXISTS`, проверка, что
  target segment найден ровно один раз по `network_id`, provider type,
  physical network и segmentation id.
- **Зачем нужно:** target API может показывать Neutron port как `ACTIVE`, но
  без `ml2_port_binding_levels` target OVS agent при RPC sync получает
  `Device <port_uuid> is not bound` и чистит OVS flows. Этот playbook закрывает
  именно этот разрыв в ML2 metadata.

### `04k-ensure-nova-compute-service.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** убедиться, что target Nova DB содержит service row
  `nova-compute` для `rehome_host` до первого запуска target `nova_compute`.
- **Что читает:** `rehome_manifest.yml`, source compute service UUID из
  manifest, target Nova DB.
- **Что меняет:** target DB, только с
  `target_nova_compute_service_apply=true`; вставляет отсутствующую строку в
  `nova.services` с `disabled=true` по умолчанию.
- **Artifacts:** `target-nova-compute-service/<timestamp>/report.tsv` и
  `manifest.json`.
- **Guard:** report-only по умолчанию, явный apply flag, idempotent
  `NOT EXISTS`, service UUID берется из source manifest, runtime containers не
  трогаются.
- **Зачем нужно:** при запуске target `nova_compute` на host с уже running
  libvirt domains Nova отказывается стартовать, если считает себя новым
  service в target DB. Этот playbook заранее фиксирует service identity, но не
  включает scheduling и не принимает новые ВМ.

### `04l-normalize-target-project-visibility.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** нормализовать imported Nova/Neutron/Cinder metadata на
  существующий target project/user, чтобы ВМ появилась в target Horizon
  `/project/instances/`.
- **Что читает:** `rehome_manifest.yml`, target DB,
  `target_project_visibility_project_id`,
  `target_project_visibility_user_id`.
- **Что меняет:** target DB, только с
  `target_project_visibility_normalize_apply=true`; обновляет project/user UUID
  только у host-scoped resources из manifest.
- **Artifacts:** `target-project-visibility-normalization/<timestamp>/report.tsv`
  и `manifest.json`.
- **Guard:** report-only по умолчанию, явный apply flag, idempotent
  `ROW_COUNT()`-based changed detection, runtime containers не трогаются.
- **Зачем нужно:** target Nova API может видеть ВМ через
  `server list --all-projects`, но Horizon `/project/instances/` не покажет ее,
  если `server.project_id` отсутствует в target Keystone или не совпадает с
  текущим project scope пользователя.

### `04i-prepull-target-images.yml`

- **Где выполняется:** `rehome_compute`.
- **Назначение:** заранее скачать target-tag Kolla images для runtime
  containers, которые будут переключены в cutover.
- **Что читает:** `target_runtime_switch_containers` и
  `target_runtime_switch_container_images` из inventory.
- **Что меняет:** только локальный Docker image cache на re-home host и digest
  report в `rehome_stage_dir`.
- **Artifacts:** `target-image-digests.txt` на re-home host и копия в
  `local_artifact_dir`.
- **Guard:** требует Kolla/Docker mode и явную image map для каждого target
  runtime container.
- **Не делает:** не останавливает и не запускает containers, не меняет
  `/etc/kolla`, не вызывает `kolla-ansible reconfigure`.

### `05-stage-compute-target-config.yml`

- **Где выполняется:** `rehome_compute`.
- **Назначение:** подготовить staging area на compute без restart/stop
  containers.
- **Что читает:** текущие `/etc/nova`, `/etc/neutron`, `/etc/openvswitch`.
- **Что меняет:** backup текущих configs и staging files в
  `target_config_stage_dir`.
- **Artifacts:** staged safe overlay и Neutron/OVS overlay.
- **Guard:** проверяет running domains через `runtime_guard_virsh_command`.
- **Важно:** этот playbook пока не генерирует full Kolla config bundle для
  cutover. Для `06` нужны staged каталоги
  `target-config-stage/kolla/nova-compute/` и
  `target-config-stage/kolla/neutron-openvswitch-agent/` с `config.json`.

### `05b-stage-target-kolla-config.yml`

- **Где выполняется:** сначала `target_reference_compute[0]`, затем
  `rehome_compute`.
- **Назначение:** подготовить full target Kolla config bundle для runtime
  containers, которые будут запущены во время `06`.
- **Что читает:** `/etc/kolla/nova-compute/` и
  `/etc/kolla/neutron-openvswitch-agent/` на reference compute целевого
  кластера; локальные host-specific значения re-home host.
- **Что меняет:** только staging на re-home host:
  `target-config-stage/kolla/nova-compute/` и
  `target-config-stage/kolla/neutron-openvswitch-agent/`.
- **Artifacts:** `target-kolla-config-reference.tar.gz` и
  `target-kolla-config-stage-manifest.json` без содержимого секретных конфигов.
- **Логика:** копирует full Kolla service directories с target reference
  compute, заменяет reference hostname/IP на `rehome_host` и IP re-home host,
  сохраняет local `hostnqn` и local libvirt `auth.conf`, выставляет
  `[DEFAULT] host`, `instances_path`, safe-mode Nova keys и
  `openvswitch_agent.ini [ovs] local_ip`.
- **Guard:** требует `config.json` для обоих сервисов, проверяет safe-mode,
  `local_ip` и отсутствие reference hostname/IP в staged bundle.
- **Не делает:** не копирует staged configs в `/etc/kolla`, не останавливает и
  не запускает containers, не вызывает `kolla-ansible reconfigure`.

### `05a-disable-source-only-services.yml`

- **Где выполняется:** `rehome_compute`.
- **Назначение:** остановить только явно разрешенные source-only non-runtime
  сервисы до cutover.
- **Что читает:** running containers, systemd units, runtime state ВМ.
- **Что меняет:** останавливает только элементы из `source_only_*`.
- **Artifacts:** audits running containers/systemd units.
- **Guard:** source-only списки не должны пересекаться с runtime switch и
  dataplane keep lists; после каждого stop запускается runtime guard.

### `06-cutover-compute.yml`

- **Где выполняется:** `rehome_compute`.
- **Назначение:** Kolla/Docker cutover runtime containers с source control
  plane на target control plane.
- **Что читает:** staged full target Kolla configs, target image map,
  runtime guard state.
- **Что меняет:** только при `cutover_apply=true`:
  - backup текущих `/etc/kolla/nova-compute` и
    `/etc/kolla/neutron-openvswitch-agent`;
  - копирует staged target Kolla configs в `/etc/kolla/...`;
  - останавливает `kolla-<container>-container.service` для source runtime
    containers, чтобы systemd не перезапускал source agents после `docker stop`;
  - останавливает source `nova_compute` и source network agent;
  - запускает target network container;
  - перепривязывает target Neutron ports к `rehome_host`;
  - запускает target `nova_compute` последним.
- **Guard:** explicit apply flag, Kolla/Docker driver, dataplane exclusions,
  target images pre-pulled, staged `config.json`, safe-mode в staged
  `nova.conf`, bounded mount entry count под `/var/lib/nova/mnt`, target
  Neutron port visibility before source stop, runtime guard до/после каждого
  критичного шага.
- **Mount leak guard:** если `/proc/1/mountinfo` уже содержит слишком много
  entries под `/var/lib/nova/mnt`, playbook падает до cutover. Это защищает от
  повторения lab-инцидента, где restart loop `kolla-nova_compute-container.service`
  с shared bind `/var/lib/nova/mnt:/var/lib/nova/mnt:shared` размножил mount
  tree до 16383 entries.
- **Neutron/OVS failure mode:** target API может показывать port как `ACTIVE` и
  привязанный к `rehome_host`, но target OVS agent при RPC sync может получить
  `Device <port_uuid> is not bound`. В этом случае agent чистит stale flows на
  OVS bridges, QEMU/tap остаются живыми, но ping до ВМ пропадает. `06` должен
  останавливаться на runtime guard и не запускать target `nova_compute`, пока
  target ML2 binding не исправлен. Подробно: `neutron-rehome-behavior-ru.md`.
- **Не делает:** не запускает полный `kolla-ansible reconfigure`, не трогает
  `nova_libvirt`, QEMU, OVS dataplane и storage helpers.
- **Важно:** target containers запускаются с `--hostname {{ rehome_host }}`,
  чтобы Nova внутри контейнера видела canonical host identity re-home host.
- **Текущее lab-состояние:** preflight останавливается до `docker stop`, пока
  нет full staged target Kolla configs в `target-config-stage/kolla/`.

### `07-rebind-network-ports.yml`

- **Где выполняется:** `target_control[0]`.
- **Назначение:** перепривязать Neutron ports к `rehome_host` на target.
- **Что читает:** target OpenStack API и список `rehome_ports`.
- **Что меняет:** target Neutron ports через `openstack port set`.
- **Artifacts:** `target-port-rebind-results.yml`.
- **Guard:** должен запускаться после успешного cutover network agent.

### `08-heal-and-validate.yml`

- **Где выполняется:** `target_control[0]`, затем `rehome_compute`.
- **Назначение:** Kolla-aware heal Placement allocations и формальная
  validation перед включением target compute service.
- **Что читает:** manifest, target Nova/Placement через
  `docker exec nova_api nova-manage`, target OpenStack API через
  `kolla_toolbox` с временным `clouds.yaml`, libvirt runtime через
  `runtime_guard_virsh_command`.
- **Что меняет:** только `nova-manage placement heal_allocations`, если
  allocations еще отсутствуют. Не запускает `kolla-ansible reconfigure`, не
  перезапускает containers и не трогает libvirt/OVS dataplane.
- **Artifacts:** `target-validation.yml` на target control и
  `compute-validation.yml` на re-home compute.
- **Guard:** проверяет `cell_v2 verify_instance`, `placement audit`, target
  `server show`, project-scoped `server list`, наличие server project в target
  Keystone, состояние target compute service, runtime guard и QGA ping если
  guest-agent доступен.

### `09-enable-target-service.yml`

- **Где выполняется:** `target_control[0]`, затем `rehome_compute`.
- **Назначение:** включить target compute service для scheduling после
  успешного `08` и burn-in.
- **Что читает:** validation artifact `target-validation.yml`, target
  OpenStack API через `kolla_toolbox` с временным `clouds.yaml`, compute-local
  runtime через `runtime_guard_virsh_command`.
- **Что меняет:** только target Nova compute service status через
  `openstack compute service set --enable`, если service еще не `enabled`.
  Не запускает `kolla-ansible reconfigure`, не перезапускает containers, не
  удаляет safe-mode и не трогает libvirt/OVS dataplane.
- **Artifacts:** `target-enable-compute-service.yml` на target control.
- **Guard:** explicit `target_enable_compute_apply=true`, обязательный
  validation artifact от `08`, runtime guard после enable, проверка что
  safe-mode ключи остались в `/etc/kolla/nova-compute/nova.conf`.

### `10-source-quarantine.yml`

- **Где выполняется:** сначала `target_control[0]`, затем `source_control[0]`,
  затем `rehome_compute`.
- **Назначение:** перевести source-side API records в карантин после того, как
  target уже принял host и target compute service включен.
- **Что читает:** target enable artifact от `09`, source OpenStack API через
  `kolla_toolbox` с временным `clouds.yaml`, manifest, compute-local runtime.
- **Что меняет:** только source Nova API state:
  - `openstack compute service set --disable --disable-reason ...`;
  - optional `openstack compute service set --down`;
  - `openstack server lock --reason ...` для source-side server records.
- **Что не делает:** не удаляет source Nova/Neutron/Cinder metadata, не
  запускает `kolla-ansible reconfigure`, не останавливает containers, не
  трогает libvirt/OVS/dataplane и не меняет target control plane.
- **Artifacts:** `source-quarantine/source-quarantine.yml` на source control.
- **Guard:** explicit `source_quarantine_apply=true`, обязательный artifact
  `target-enable-compute-service.yml` от `09`, cleanup временного `clouds.yaml`,
  runtime guard после quarantine.
- **Важно:** старый source Horizon может по-прежнему показывать stale VM, но
  source compute service disabled/down, а source-side server locked. Это
  организационный и API-level карантин до закрытия rollback window; это не
  cleanup source DB.

### `11-cleanup-old-source-images.yml`

- **Где выполняется:** сначала `source_control[0]`, затем `rehome_compute`.
- **Назначение:** после burn-in подготовить отчет или удалить старые source-tag
  runtime images, которые уже заменены target-tag containers.
- **Что читает:** source quarantine artifact
  `source-quarantine/source-quarantine.yml`, Docker image/container state на
  re-home compute, `source_runtime_cleanup_container_images`.
- **Что меняет:** по умолчанию ничего, только пишет report. При
  `source_runtime_image_cleanup_apply=true` удаляет через `docker rmi` только
  images из explicit allowlist `source_runtime_cleanup_container_images`, и
  только если image не используется ни одним container.
- **Что не делает:** не удаляет source DB metadata, не вызывает
  `kolla-ansible`, не останавливает и не удаляет containers, не трогает
  `nova_libvirt`, OVS, storage helpers и любые `dataplane_keep_containers`.
- **Artifacts:** `source-runtime-image-cleanup/report.txt` на re-home compute.
- **Guard:** требует source quarantine artifact, проверяет что allowlist не
  пересекается с `dataplane_keep_containers`, после report/apply запускает
  runtime guard.
- **Важно:** для текущего lab allowlist содержит только старые Rocky images
  `nova_compute` и `neutron_openvswitch_agent`. Rocky images для
  `nova_libvirt`/OVS остаются на месте, потому что эти containers еще работают.

### `12-reconcile-target-host-containers.yml`

- **Где выполняется:** `rehome_compute`.
- **Назначение:** привести оставшиеся host-local Kolla containers к target
  image tags после того, как target уже принял host и ВМ прошла burn-in.
- **Что читает:** текущий Docker container spec через `docker inspect`, target
  image map `target_host_container_reconcile_images`, runtime state ВМ через
  `runtime_guard_virsh_command`, staged target Kolla config из
  `target_host_container_reconcile_config_stage_dir`.
- **Что меняет:** по умолчанию ничего, только пишет report. При
  `target_host_container_reconcile_apply=true` helper пересоздает выбранный
  container с тем же Docker spec и новым image. Старый container сначала
  переименовывается в backup, поэтому при ошибке playbook пытается rollback.
- **Default scope:** `fluentd`, `cron`, `kolla_toolbox`, `nova_ssh`. Это
  host-local service/support containers, которые не являются libvirt/OVS/storage
  dataplane и не должны влиять на работу уже запущенной ВМ.
- **Target config/env:** для `cron`, `kolla_toolbox`, `nova_ssh` playbook
  сначала проверяет staged target Kolla config, при `apply` ставит его в
  `/etc/kolla/<service>` с backup/rollback и передает helper'у per-container
  env overrides. Это нужно для cross-distro re-home: простой image tag switch
  может оставить source-команды или source env, например Rocky `crond` внутри
  Ubuntu image.
- **Per-container mount drops:** helper поддерживает
  `target_host_container_reconcile_drop_mount_destinations`. В lab для
  `nova_ssh` задано удаление destination `/var/lib/nova/mnt`, потому что на
  re-home host обнаружен mount namespace leak: тысячи duplicate mount entries
  на `/var/lib/nova/mnt` и Cinder NFS volume path. С таким namespace Docker/runc
  может падать на bind `/var/lib/nova/mnt:/var/lib/nova/mnt:shared` с
  `no space left on device`, хотя disk space/inodes нормальные.
- **Libvirt:** `nova_libvirt` описан в inventory, но запускается только при
  `target_host_container_reconcile_include_libvirt=true`. В текущем lab
  target Ubuntu `nova_libvirt` на live Rocky re-home host не увидел running
  libvirt domain даже после retry runtime guard, поэтому playbook откатил
  контейнер на Rocky image. Для strict continuity это правильное поведение:
  running QEMU остается живым, но libvirt management plane нельзя принимать,
  пока target-tag container не видит домены.
- **Libvirt preflight:** до любого `apply` для `nova_libvirt` playbook
  собирает machine types запущенных libvirt domains, текущие версии
  libvirt/QEMU, запускает target image через
  `docker run --rm --entrypoint /bin/bash`, собирает target libvirt/QEMU и
  `qemu -machine help`. Playbook падает до остановки контейнера, если target
  image не поддерживает machine type текущих доменов или делает downgrade
  libvirt/QEMU. Candidate image можно подать через
  `target_host_container_reconcile_nova_libvirt_image`, например для проверки
  `quay.io/openstack.kolla/nova-libvirt:2025.1-rocky-10` без правки inventory.
  Override-флаги `target_host_container_reconcile_allow_unsupported_libvirt_machine_types`
  и `target_host_container_reconcile_allow_libvirt_version_downgrade` существуют
  только для сознательного lab-эксперимента.
- **Успешный machine type path:** если report-only preflight для candidate
  image чистый, то есть `missing machine types` пустой и нет downgrade
  libvirt/QEMU, `nova_libvirt` можно переключать отдельным apply-окном, не как
  часть первичного cutover. Команда должна включать только libvirt scope:
  `target_host_container_reconcile_apply=true`,
  `target_host_container_reconcile_include_libvirt=true` и тот же
  `target_host_container_reconcile_nova_libvirt_image`, который прошел
  report-only проверку. После пересоздания контейнера playbook обязан пройти
  `runtime guard`: running domain set, domain interface snapshot и network
  probe ВМ. Если target `nova_libvirt` не видит домены, `virsh` не отвечает,
  Nova получает `HypervisorUnavailable` или network probe теряет ВМ, результат
  считается неуспешным, а контейнер возвращается через rollback из backup.
- **OVS:** `openvswitch_db` и `openvswitch_vswitchd` описаны в inventory, но
  запускаются только при `target_host_container_reconcile_include_ovs=true`.
  Это отдельное окно: OVS является dataplane. Для lab apply выполнялся с
  `runtime_guard_compare_ovs_ports=true` и внешним ping-monitor; после retry
  OVS port snapshot восстановился, OVS перешел на Ubuntu images без packet loss.
- **Подробности:** причины по `nova_libvirt` и OVS зафиксированы в
  `nova-ovs-rehome-investigation-ru.md`.
- **Что не делает:** не запускает `kolla-ansible reconfigure`, не меняет Nova
  DB/Neutron DB/source metadata, не удаляет старые images.
- **Artifacts:** `target-host-container-reconcile/report.txt` и per-container
  JSON reports на re-home compute.
- **Guard:** explicit apply flag, проверка target image, runtime guard после
  каждого контейнера, rollback из backup при ошибке или провале guard.

### `90-rollback-to-source.yml`

- **Где выполняется:** `rehome_compute`, затем `source_control[0]`, затем
  `target_control[0]`.
- **Назначение:** вернуть compute host к source control plane до target-side
  destructive операций.
- **Что меняет:** останавливает target runtime units, восстанавливает source
  configs из backup, запускает source units, включает source compute service.
- **Guard:** рассчитан на ранний rollback. После target-side операций с ВМ
  rollback требует отдельного ручного плана.

## Короткая последовательность

1. `02b-discover-live-resource-graph.yml` — обязательный live gate и
   authoritative resource-scoped directional mapping.
2. Необязательный legacy `02a-build-rehome-manifest.yml` — дополнительный
   manifest для старых helper-фаз.
3. Необязательные `03a`/`03b` — legacy-диагностика полного schema diff; полное
   равенство Keystack/Epoxy не требуется.
4. `04a`-`04h` - подготовить target metadata и нормализовать target-specific
   identifiers.
5. `04j` - проверить/добавить target Neutron ML2 binding levels для ports ВМ.
6. `04k` - проверить/добавить target Nova compute service row для re-home host.
7. `04l` - нормализовать target project/user visibility для Horizon, если
   выбран target project/user normalization.
8. `04i` - скачать target-tag images на re-home host и сохранить digests.
9. `05` - подготовить safe overlays/staging на compute.
10. `05b` - подготовить full target Kolla config bundle в
   `target-config-stage/kolla/`.
11. `05a` - остановить source-only non-runtime сервисы.
12. `06 -e cutover_apply=true` - выполнить guarded cutover.
13. Проверить target admin/API visibility:
    `openstack server show <uuid>` и
    `openstack server list --all-projects --long --name <name>`.
14. Проверить target project-level visibility:
    `openstack project show <server.project_id>` и role assignments. Если
    project отсутствует, target `/project/instances/` не покажет ВМ до
    Keystone import или target project/user normalization.
15. `07`, `08`, `09` - network rebind, heal/validate, enable target service.
16. `10` - source API quarantine после принятия ВМ target-кластером.
17. `11` - report/cleanup старых source runtime images.
18. `12` - привести оставшиеся host containers к target image tags; штатно
    только `fluentd`. `nova_libvirt` и OVS только отдельными флагами и окнами.
