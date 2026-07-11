# Re-home os1 -> os2: исходное состояние и первый безопасный шаг

Документ описывает lab-сценарий из текущего репозитория и правила, которые
должны сохраниться при переносе метода на другие кластеры.

Перед адаптацией этих playbook-ов к другой инфраструктуре сначала заполнить
чеклист входных данных из `operator-inputs-ru.md`: inventory, OpenStack admin
access, DB credentials, Kolla/global configs, service classification, runtime
probe и local artifact paths.

Краткая логика каждого playbook-а, место выполнения, side effects, guards и
Kolla-specific порядок применения изменений описаны в `playbook-logic-ru.md`.

## Исходное состояние

Source control plane `os1`:

- Kolla-Ansible, `openstack_release: 2025.1`;
- base distro образов Kolla: `rocky`;
- VIP: `192.168.10.90`;
- control nodes: `192.168.10.70-72`;
- compute nodes: `192.168.10.73-74`;
- Masakari включен: `enable_masakari: yes`,
  `enable_masakari_hostmonitor: yes`,
  `enable_masakari_instancemonitor: no`.

Target control plane `os2`:

- Kolla-Ansible, `openstack_release: 2025.1`;
- base distro образов Kolla: `ubuntu`;
- VIP: `192.168.10.91`;
- control nodes: `192.168.10.75-77`;
- compute nodes: `192.168.10.78-79`;
- Masakari выключен.

Общая сеть для ВМ:

- OpenStack network: `lab-net`;
- subnet: `lab-subnet`;
- CIDR: `192.168.10.0/24`;
- DHCP выключен;
- allocation pool: `192.168.10.100-192.168.10.110`;
- provider type: `flat`;
- physical network: `physnet1`;
- текущая тестовая ВМ использует `192.168.10.100`.

Важно: одинаковая адресация source/target и сохраненный fixed IP не гарантируют
непрерывность трафика. Для OVS target Neutron должен вернуть target
`neutron_openvswitch_agent` полноценный bound-port через RPC. Если agent пишет
`Device <port_uuid> is not bound` / `binding failed`, он может почистить flows в
`br-int`/`br-ex`, и ping до ВМ пропадет, хотя QEMU domain, tap interface, MAC и
IP останутся на месте. Подробно это поведение описано в
`neutron-rehome-behavior-ru.md`.

Важно: target Nova API visibility и target Horizon `/project/instances/` - это
разные проверки. В текущем lab target Nova API видит ВМ `os1-vm-100`, но
страница project instances не показывает ее, потому что imported instance
сохранил source `project_id`, а в target Keystone такого project нет. Source
Horizon при этом может продолжать показывать stale-запись ВМ до source
quarantine/cleanup. Подробно: `horizon-rehome-visibility-ru.md`.

NFS-хост общий, но пути разделены по кластерам:

- `192.168.10.80:/srv/openstack-nfs/os1/...`;
- `192.168.10.80:/srv/openstack-nfs/os2/...`.

## Главный инвариант

Во время re-home ВМ должна продолжать работать на том же compute host и
оставаться доступной по сети.

Нельзя останавливать или пересоздавать:

- QEMU-процессы гостевых ВМ;
- `nova_libvirt` / libvirt runtime;
- `openvswitch_db`, `openvswitch_vswitchd`;
- tap/veth-интерфейсы ВМ;
- storage helpers и активные storage sessions;
- локальный `instances_path`.

Можно заранее отключать только те source-only сервисы, которые не участвуют в
runtime ВМ. Это не только Masakari: на других кластерах такими сервисами могут
быть Watcher, Mistral, telemetry, monitoring/exporters, log agents или другие
операционные агенты. Каждый такой сервис должен быть явно внесен в allowlist.

## Классификация сервисов

Сервис на re-home host должен попасть ровно в одну из групп:

1. `source_only_containers` / `source_only_systemd_units`
   - есть в source cluster;
   - отсутствует в target cluster;
   - не влияет на runtime ВМ;
   - можно остановить до cutover, но только с проверкой ВМ после каждого
     сервиса.

2. `source_runtime_switch_containers` / `target_runtime_switch_containers`
   - нужен для принятия хоста target control plane;
   - переключается только внутри cutover window;
   - примеры: `nova_compute`, `neutron_openvswitch_agent`, `ovn_controller`.

3. `dataplane_keep_containers` / `dataplane_keep_systemd_units`
   - не останавливается во время re-home;
   - примеры: `nova_libvirt`, `openvswitch_db`, `openvswitch_vswitchd`,
     `iscsid`, `multipathd`.

Если сервис не классифицирован, playbook не должен сам решать, что с ним делать.
Оператор должен явно добавить его в одну из групп.

## Обязательный live discovery gate

До старого manifest/schema/import пути нужно выполнить новый live gate:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml \
  playbooks/02b-discover-live-resource-graph.yml \
  --ask-vault-pass \
  -e @/secure/live-discovery-paths.vault.yml \
  -e live_discovery_run_id=rehome-20260712-review01
```

Vault/extra-vars file должен задавать непустые paths HMAC key, обоих probe
JSON, двух разных Glance tokens, source/target clouds и per-controller Kolla
passwords. Точные inventory/Vault примеры приведены во
[входных данных оператора](operator-inputs-ru.md). Cinder sensitive paths
условно обязательны при active attachments; свежий target migration envelope
нужен, чтобы target profile не остался `UNKNOWN`.

Для другого окружения заменить inventory, но не порядок. Живые source/target
API, БД, compute runtime, target capability, Cinder backing и Glance store
являются источником истины. Uploaded SQL/schema dump — только пример/fixture,
не способ наполнить discovery. Source profile — `keystack-2025.1`; target
принимается только при live proof `vanilla-openstack-2025.1-epoxy`.

Playbook выполняет семь plays: local freeze/owner, source control, target
control, re-home runtime, target reference capability, source/target probes и
local assembly. API roots подписываются HMAC; `--phase verify` проверяет план и
live schema до SQL (verify-before-SQL); затем выполняются только UUID-scoped
SELECT и `--phase combine`. Masakari/DRS не входят в этот graph/verdict.

### Preflight оператора

Перед командой проверить:

- в каждой из `source_control`, `target_control`, `rehome_compute`,
  `target_reference_compute` ровно один host;
- `rehome_host`, local/remote dirs, target profile, schema policy, storage map
  и fail-closed flags совпадают на source/target controller;
- clouds files, Kolla passwords, HMAC key, probe configs и два разных Glance
  tokens принадлежат uid оператора, mode `0600`, не symlink;
- HMAC key содержит 16..4096 bytes;
- `live_discovery_source_glance_token_file_local` и
  `live_discovery_target_glance_token_file_local` имеют разные checksums;
- storage map отражает реальный backend, а не lab assumption;
- все overrideable argv заданы YAML lists и не содержат shell
  operators/mutations; playbook сам передаёт frozen config в
  `argv_policy.py --config-json` до remote execution;
- доступен writable `live_discovery_local_dir`, но каталога конкретного
  `<run-id>` ещё нет;
- опциональное online-migration evidence свежее (не старше 24 часов) и содержит
  exact current revisions. Сам playbook `online_data_migrations` не запускает.

Для NFS текущего lab используется map из inventory. Решение не ограничено NFS:
NFS/file, RBD и LVM имеют read-only size probes. iSCSI, Fibre Channel или
vendor backend должны быть объявлены фактическим kind с
`probe_template: unsupported` и дадут `UNKNOWN`, пока нет reviewed безопасного
probe. Пустая `live_discovery_storage_backends: {}` также даёт `UNKNOWN`.

### Где искать результат

```text
{{ local_artifact_dir }}/live-discovery/<run-id>/
```

Проверить `readiness-report.json`, `readiness-report.md`,
`resource-graph.json`, `schema-mapping.json`, `uuid-filters.json` и
`evidence-index.json`. Полный normal set содержит восемь файлов, перечисленных
в [документе об артефактах](docs/live-discovery-artifacts-ru.md).

```text
READY=0
READY_WITH_WARNINGS=0
UNKNOWN=2
BLOCKED=3
```

Продолжать к import/cutover можно только после rc `0` и инженерного review
всех warnings. `UNKNOWN` запрещает продолжение: отсутствие probe/evidence не
означает готовность.

### Troubleshooting

| Симптом | Проверка | Действие |
| --- | --- | --- |
| preflight до remote commands | singleton groups, controller variable equality, `0600`, file owner/size | исправить inventory/input; не обходить assert |
| `another owner`/collision | `.control/owners/<run-id>` и completion marker | для rerun выбрать новый `run-id`; не удалять concurrent owner |
| verify не создал SQL | HMAC, API/filter/plan binding, live `information_schema`, schema policy | повторить acquisition новым run ID после исправления; не запускать SQL вручную |
| Cinder `UNKNOWN` | backend kind/delegate, protected attachment summary, backing identity/size | добавить reviewed NFS/file/RBD/LVM probe либо отдельный безопасный template для другого backend |
| Glance `BLOCKED/UNKNOWN` | отдельный side token, catalog origin, store ID, size, Range response | исправить endpoint/access/store evidence; не отключать required image probe |
| Neutron `BLOCKED` | required edge closure, segment tuple, ML2 binding/levels, OVS/OVN evidence | исправить metadata/runtime readiness до запуска target agent |
| target profile `UNKNOWN` | official Kolla image repo/tag/digest/label, DB revisions, migration evidence | получить актуальное read-only evidence; не подменять profile inventory string |
| unreachable/failure | owner marker и protected dirs | дать штатному rescue cleanup завершиться; проверить, что удалён только incomplete owner этого run |

### Cleanup, rerun и concurrency

Успех удаляет frozen HMAC/clouds/tokens/configs и сохраняет completed owner
marker. Failure/unreachable запускает ownership-checked cleanup. Не выполнять
ручной `rm -rf` для общего `live-discovery` или `.control/owners`: это может
затронуть concurrent run. Если процесс был аварийно прерван, сначала сверить
`run-id`, owner token/completion marker и отсутствие активного процесса; затем
оформить отдельный cleanup по процедуре change management.

Для повторного запуска использовать новый auto-generated ID (оставить
`live_discovery_run_id: ""`) или новый явный ID. Нельзя «дополнить» старый
partial run: final set записывается атомарно. Protected
`sensitive/evidence.json` (`0700`/`0600`) хранить отдельно и удалить после
минимально необходимого review/rollback window; обычные artifacts сохранять с
inventory revision и change record.

На текущем этапе репозиторий прошёл fixture/unit tests и Ansible
`syntax-check`. Это не утверждение о выполненном live deployment: операторский
запуск на конкретном кластере и review его evidence остаются обязательными.

## Короткая последовательность

1. Сначала обязательный
   `02b-discover-live-resource-graph.yml`: live graph, verdict и authoritative
   resource-scoped directional mapping в `schema-mapping.json`.
2. Только после rc `0` при необходимости выполнить необязательный legacy
   `02a-build-rehome-manifest.yml` для старых helper-фаз.
3. `03a`/`03b` запускать только как необязательную legacy-диагностику полного
   schema diff; полное равенство Keystack и Epoxy не требуется.
4. Затем выполнять reviewed planning/import/cutover фазы ниже.

## Необязательный legacy manifest и последующие фазы

Следующий старый шаг собирает host-scoped manifest по re-home host и ВМ. Он не
заменяет `02b` и запускается только в согласованном общем порядке. Выполняется
playbook-ом, helper-скрипты внутри него являются implementation detail:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/02a-build-rehome-manifest.yml
```

Playbook собирает:

- source OpenStack API state из `os1` через `kolla_toolbox`;
- target pre-state из `os2` через `kolla_toolbox`;
- compute-local runtime snapshot с `os1-compute-02`;
- объединенный `rehome_manifest.yml` и `rehome_manifest.json`.

В manifest должны попасть все идентификаторы, которые нельзя потерять при
re-home: instance UUID/name/status, libvirt domain name/UUID, Neutron port UUID,
MAC, fixed IP, network/subnet/provider mapping, security groups, flavor/image
metadata, Cinder volume IDs и attachments.

Итоговые файлы:

```bash
artifacts/os1-compute-02/rehome_manifest.yml
artifacts/os1-compute-02/rehome_manifest.json
```

`03a`/`03b` — только необязательная legacy-диагностика полного schema diff для
близких/same-schema сред. Authoritative gate уже сформирован `02b` как
resource-scoped directional mapping в `schema-mapping.json`. Для Keystack →
Epoxy полное равенство schema не требуется.

Если дополнительная полная диагностика полезна, выполнить:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/03a-check-db-schema-compat.yml
```

Playbook собирает:

- `nova-manage api_db version`;
- `nova-manage db version`;
- `neutron-db-manage current`;
- `cinder-manage db version`;
- `information_schema` snapshot для `keystone`, `nova_api`, `nova_cell0`,
  `nova`, `neutron`, `cinder`, `placement`.

Отчеты сохраняются локально:

```bash
artifacts/schema-compat/os1-to-os2/
```

Если версии migrations или полный `information_schema` отличаются, сам legacy
playbook падает. Это повод изучить diagnostic diff, но его rc не заменяет и не
усиливает verdict `02b` для vendor → vanilla направления.

После `03a` можно запустить локальную нормализацию уже собранных artifacts:

```bash
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/03b-normalize-schema-diff.yml
```

Она создает:

```bash
artifacts/schema-compat/os1-to-os2/normalized/
artifacts/schema-compat/os1-to-os2/normalized-diffs/
artifacts/schema-compat/os1-to-os2/normalization-summary.txt
```

Нормализация консервативная: удаляет пустые строки и известный command noise,
затем сортирует normalized lines. Непустой полный diff ожидаем между Keystack и
Epoxy; обязательным остаётся отсутствие blocker-ов в directional mapping и
общий rc `0` от `02b`.

После успешной проверки схем нужно построить target API prep report. Этот шаг
не является cutover и по умолчанию ничего не создает:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04a-plan-target-api-prep.yml
```

Отчеты:

```bash
artifacts/os1-compute-02/target-api-prep-report.json
artifacts/os1-compute-02/target-api-prep-report.yml
```

В первом варианте playbook автоматически применяет только API-safe изменения,
если явно задано `target_prep_apply=true`. Сейчас таким изменением считается
создание flavor с сохранением flavor ID. Missing Neutron network/subnet/security
group/port с исходными UUID не создаются через generic OpenStack API, а
помечаются как `requires_existing_or_db_import`. Cinder/Nova volume attachment
metadata помечается как `db_import_only`.

После target API prep report нужно сформировать локальный review-pack для DB
metadata import:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04b-plan-db-metadata-import.yml
```

Этот шаг не подключается к БД и не пишет SQL в target. Он создает план и
неисполняемые SQL skeletons, которые нужно заменить на reviewed host-scoped SQL:

```bash
artifacts/os1-compute-02/target-db-import-plan.json
artifacts/os1-compute-02/target-db-import-plan.yml
artifacts/os1-compute-02/target-db-import-plan.md
artifacts/os1-compute-02/target-db-import-sql-review/
```

После этого можно собрать source DB rows для ручного review. Это read-only шаг:
он выполняет только `SELECT` по UUID/instance_name фильтрам из import plan и
сохраняет результат в artifacts:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04c-collect-source-db-rows.yml
```

Отчеты и исходные SQL queries:

```bash
artifacts/os1-compute-02/source-db-rows.tar.gz
artifacts/os1-compute-02/source-db-rows/queries/
artifacts/os1-compute-02/source-db-rows/rows/
artifacts/os1-compute-02/source-db-rows/source-db-row-query-manifest.json
```

Для текущего lab рабочая Nova cell DB задана как `nova`, а `nova_cell0`
оставлена в schema checks только как системная cell0 DB. Running VM metadata
для `instance-00000004` собирается из `nova`.

Из собранных source rows можно сгенерировать target SQL import draft:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04d-generate-target-sql-draft.yml
```

Этот draft не должен применяться автоматически. Каждый SQL файл начинается с
`SIGNAL SQLSTATE '45000'`, чтобы случайный запуск остановился до `INSERT`.
Перед использованием оператор должен вручную проверить auto-increment IDs,
foreign keys, target row existence, service-specific invariants и заменить draft
на reviewed SQL:

```bash
artifacts/os1-compute-02/target-db-import-sql-draft/
artifacts/os1-compute-02/target-db-import-sql-draft-summary.json
artifacts/os1-compute-02/target-db-import-sql-draft-summary.md
```

Перед реальным импортом нужно проверить target DB на конфликты по тем же UUID:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04e-target-preimport-guard.yml
```

Этот шаг выполняет только `SELECT` на target DB. Если найдены строки с такими
UUID, playbook падает до импорта:

```bash
artifacts/os1-compute-02/target-preimport-guard-report.json
artifacts/os1-compute-02/target-preimport-guard-report.md
artifacts/os1-compute-02/target-preimport-guard/rows/
```

Если guard прошел, сделать backup target DB непосредственно перед import:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04f-backup-target-db.yml
```

Backup выполняется через Kolla `mariadb` container и сохраняет full/schema dump,
checksums и manifest. По умолчанию `04f` использует unix socket
`/run/mysqld/mysqld.sock` внутри контейнера, а не `127.0.0.1` или VIP, чтобы не
зависеть от ProxySQL/root grants:

```bash
artifacts/os1-compute-02/target-db-backup/
```

После backup reviewed SQL применяется только с явным apply-флагом:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04g-apply-target-sql.yml \
  -e target_db_import_apply=true \
  -e target_db_import_strip_hard_stop=true
```

Если source и target имеют разные UUID для локальных справочников, после import
нужно выполнить нормализацию target-specific metadata. В текущем lab это Cinder
volume type `__DEFAULT__`: на `os1` UUID
`59cbeca1-1937-4a44-be09-f612dc4d0373`, на `os2` UUID
`81bf219f-8f67-493b-927f-215176983345`.

Сначала можно запустить report-only режим:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04h-normalize-target-metadata.yml
```

Применение требует отдельного флага:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04h-normalize-target-metadata.yml \
  -e target_metadata_normalize_apply=true
```

Артефакты нормализации:

```bash
artifacts/os1-compute-02/target-metadata-normalization/
```

Этот шаг не трогает libvirt/QEMU, OVS, tap-интерфейсы и containers на compute.
Он меняет только явно разрешенные target DB поля из
`target_metadata_normalizations`, например `cinder.volumes.volume_type_id`.

После DB import и общей нормализации нужно проверить Neutron ML2 binding levels
для port UUID ВМ. Это отдельный guard против ситуации, когда target API уже
показывает port как `ACTIVE`, но target OVS agent получает от plugin
`Device <port_uuid> is not bound`.

Report-only:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04j-ensure-neutron-ml2-binding-levels.yml
```

Применение требует отдельного флага:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04j-ensure-neutron-ml2-binding-levels.yml \
  -e target_neutron_ml2_binding_levels_apply=true
```

Ожидаемый report для уже исправленного port:

```text
segment_count    <port_uuid>    1    <segment_uuid>
before           <port_uuid>    1
inserted         <port_uuid>    0    <segment_uuid>
after            <port_uuid>    1    <segment_uuid>
```

После Neutron ML2 normalization нужно подготовить target Nova service row для
re-home host. Это не запускает `nova_compute`, но предотвращает отказ target
Nova вида "на гипервизоре уже есть instances, а service выглядит новым в этой
DB".

Report-only:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04k-ensure-nova-compute-service.yml
```

Применение требует отдельного флага:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04k-ensure-nova-compute-service.yml \
  -e target_nova_compute_service_apply=true
```

Если выбран вариант нормализации на существующий target project/user, нужно
отдельно привести imported Nova/Neutron/Cinder metadata к target Keystone
identity. Это влияет на видимость ВМ в target Horizon `/project/instances/`.

Report-only:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04l-normalize-target-project-visibility.yml
```

Применение требует отдельного флага:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04l-normalize-target-project-visibility.yml \
  -e target_project_visibility_normalize_apply=true
```

После подготовки metadata нужно заранее скачать target-tag Kolla images на
re-home host. Это не cutover: playbook только выполняет `docker pull` для
образов из `target_runtime_switch_container_images` и сохраняет digest report.

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/04i-prepull-target-images.yml
```

Отчет:

```bash
artifacts/os1-compute-02/target-image-digests.txt
```

Для lab-направления `os1 -> os2` добавлен inventory:

```bash
migration_project/openstack-rehome-ansible/inventory/lab-os1-to-os2.yml
```

В нем задан Ansible re-home host `os1-compute-02` (`192.168.10.74`), но Nova
canonical host identity:

```yaml
rehome_host: os1-compute-02.example.local
hypervisor_hostname: os1-compute-02.example.local
```

Это имя должно совпадать с Nova compute service, hypervisor hostname и
`[DEFAULT] host`.

Также в lab inventory задан `target_reference_compute`:

```yaml
os2-compute-01:
  ansible_host: 192.168.10.78
  target_kolla_config_reference_hostname: os2-compute-01.example.local
```

С этой ноды `05b-stage-target-kolla-config.yml` берет full Kolla configs для
`nova-compute` и `neutron-openvswitch-agent`, затем на re-home host заменяет
reference hostname/IP на `os1-compute-02.example.local` и `192.168.10.74`,
добавляет Nova safe-mode и staged `openvswitch_agent.ini [ovs] local_ip`.
Содержимое конфигов содержит target service secrets и не должно печататься в
лог или документацию.

Также задан target VM probe `192.168.10.100`, probe delegate `localhost`,
Kolla/Docker mode, `runtime_guard_virsh_command: docker exec nova_libvirt virsh`
и lab source-only allowlist:

- `hacluster_pacemaker_remote`;
- `masakari_instancemonitor`.
- `kolla-hacluster_pacemaker_remote-container.service`.

Для Kolla важно указывать и systemd unit, если он управляет контейнером. Иначе
прямой `docker stop` может пройти успешно, но unit поднимет контейнер обратно.

Если контейнера нет на хосте, это не ошибка: playbook запишет `ABSENT` и пойдет
дальше. Если контейнер есть и работает, он будет остановлен только после baseline
проверки ВМ.

Команда:

```bash
cd /Users/dmitry/Desktop/test_migration/migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/05a-disable-source-only-services.yml
```

Что делает playbook:

1. Проверяет, что source-only allowlist не пересекается с cutover/dataplane
   списками.
2. Сохраняет аудит running containers и relevant systemd units на re-home host.
3. Снимает baseline:
   - running libvirt domains;
   - `virsh domiflist` для каждого домена;
   - ping до `192.168.10.100` с Ansible runner через `delegate_to: localhost`.
4. Останавливает source-only сервисы по одному.
5. После каждого сервиса повторяет runtime guard.
6. Если ВМ исчезла, изменились интерфейсы или пропал ping, пытается вернуть
   остановленный сервис и завершает playbook с ошибкой.

## Идемпотентность

Повторный запуск допустим:

- уже остановленный сервис дает `ALREADY_STOPPED`;
- отсутствующий сервис дает `ABSENT`;
- baseline создается заново в начале запуска;
- runtime guard каждый раз проверяет фактическое состояние ВМ;
- playbook не останавливает сервисы вне явного allowlist.

## Дальше

После успешного `05a` следующий этап - подготовка target metadata/config и
Kolla-aware cutover:

1. заранее скачать target Ubuntu Kolla images на re-home host;
2. подготовить target config для `neutron_openvswitch_agent` и `nova_compute`
   через `05b-stage-target-kolla-config.yml`;
3. перед cutover проверить target ML2 binding model для port UUID ВМ;
4. в cutover window остановить source `nova_compute` и source network agent;
5. запустить target-tag network agent;
6. продолжать только если runtime guard подтверждает непрерывный ping и в логах
   target network agent нет `Device <port_uuid> is not bound`;
7. запустить target-tag `nova_compute` в safe-mode;
8. выполнить Kolla-aware validation:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/08-heal-and-validate.yml
   ```

   Этот шаг использует `docker exec nova_api nova-manage`, временный
   `clouds.yaml` внутри `kolla_toolbox` и `docker exec nova_libvirt virsh`
   через `runtime_guard_virsh_command`. Он не запускает
   `kolla-ansible reconfigure` и не перезапускает dataplane containers.

   Важно для Kolla: перед `docker stop` playbook `06` останавливает
   `kolla-<container>-container.service` для source runtime containers. Без
   этого systemd может поднять source `nova_compute` обратно в restart loop.
   В lab это уже привело к mount propagation leak: repeated restarts
   `kolla-nova_compute-container.service` с shared bind
   `/var/lib/nova/mnt:/var/lib/nova/mnt:shared` размножили entries в
   `/proc/1/mountinfo` до 16383. Поэтому `06` теперь также падает до cutover,
   если count под `/var/lib/nova/mnt` выше guard threshold.
9. после burn-in включить target compute service, но оставить Nova safe-mode:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/09-enable-target-service.yml \
     -e target_enable_compute_apply=true
   ```

   Этот шаг включает scheduling через target Nova API, проверяет runtime guard и
   подтверждает, что safe-mode в `/etc/kolla/nova-compute/nova.conf` остается
   включенным. Он не запускает `kolla-ansible reconfigure`, не перезапускает
   containers и не трогает `nova_libvirt`/OVS.
10. перевести source-side API records в карантин:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/10-source-quarantine.yml \
     -e source_quarantine_apply=true
   ```

   Этот шаг не удаляет source metadata. Он выключает/force-down source
   `nova-compute` service и ставит `server lock` на source-side записи ВМ,
   чтобы старая Horizon-консоль не была местом для штатных действий с ВМ.
   После этого runtime guard еще раз проверяет, что ВМ продолжает работать.
11. после отдельного burn-in сначала построить отчет по старым source runtime
    images:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/11-cleanup-old-source-images.yml
   ```

   По умолчанию этот шаг ничего не удаляет. Он проверяет только images из
   `source_runtime_cleanup_container_images`: старые Rocky images
   `nova_compute` и `neutron_openvswitch_agent`. Dataplane images
   `nova_libvirt`/OVS не входят в allowlist.

   Удаление включается только отдельным явным флагом:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/11-cleanup-old-source-images.yml \
     -e source_runtime_image_cleanup_apply=true
   ```

12. привести оставшиеся host containers к target image tags. Сначала
    report-only:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/12-reconcile-target-host-containers.yml
   ```

   По умолчанию playbook проверяет `fluentd`, `cron`, `kolla_toolbox` и
   `nova_ssh`. Это host-local service/support containers, не libvirt/OVS
   dataplane. Playbook использует текущий `docker inspect` как шаблон запуска,
   не вызывает `kolla-ansible reconfigure` и после каждого контейнера запускает
   runtime guard.

   Для `cron`, `kolla_toolbox` и `nova_ssh` одного image switch недостаточно:
   playbook также ставит staged target Kolla config из `05b` и per-container
   env overrides. В cross-distro сценарии это штатное требование: source Rocky
   config мог содержать команду `crond`, а target Ubuntu image ожидает
   `cron -f`.

   Для `nova_ssh` в lab inventory дополнительно задано:

   ```yaml
   target_host_container_reconcile_drop_mount_destinations:
     nova_ssh:
       - /var/lib/nova/mnt
   ```

   Причина - mount namespace leak на re-home host: в `/proc/self/mountinfo`
   было найдено 16383 записей под `/var/lib/nova/mnt`, включая тысячи duplicate
   entries на Cinder NFS volume path. Это не расход disk space/inodes, а записи
   kernel mount table внутри namespace. При таком состоянии bind
   `/var/lib/nova/mnt:/var/lib/nova/mnt:shared` может ломать запуск/healthcheck
   `nova_ssh` через Docker/runc с ошибкой `no space left on device`.

   Применение:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/12-reconcile-target-host-containers.yml \
     -e target_host_container_reconcile_apply=true
   ```

   `nova_libvirt` не входит в default scope. В текущем lab target Ubuntu
   `nova_libvirt` на live Rocky host не увидел running domain, runtime guard
   сработал, и playbook откатил контейнер обратно. Это нужно считать
   ожидаемой защитой strict continuity: QEMU/ВМ остаются живыми, но libvirt
   management plane нельзя принимать, если target container не видит домены.
   Для `nova_libvirt` playbook до любого `apply` дополнительно проверяет:
   текущие machine types запущенных libvirt domains, версии libvirt/QEMU в
   текущем контейнере, версии libvirt/QEMU в target image и наличие нужных
   machine types в `qemu -machine help`.

   Candidate Rocky 10 можно проверить безопасно в report-only режиме:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/12-reconcile-target-host-containers.yml \
     -e target_host_container_reconcile_include_libvirt=true \
     -e target_host_container_reconcile_nova_libvirt_image=quay.io/openstack.kolla/nova-libvirt:2025.1-rocky-10
   ```

   Для текущей ВМ это должно остановиться на preflight: Rocky 10 image имеет
   libvirt/QEMU нужного поколения, но не содержит machine type
   `pc-i440fx-rhel7.6.0`.

   Применять `nova_libvirt` можно только отдельным флагом и только если
   preflight чистый:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/12-reconcile-target-host-containers.yml \
     -e target_host_container_reconcile_apply=true \
     -e target_host_container_reconcile_include_libvirt=true
   ```

   Рабочий алгоритм при успешной проверке machine type:

   1. Сначала выполнить report-only проверку с тем candidate image, который
      планируется использовать. Не менять image между report-only и apply.
   2. Проверить `/var/tmp/openstack-rehome/target-host-container-reconcile/`
      и убедиться, что compatibility report для `nova_libvirt` не содержит
      missing machine types и downgrade libvirt/QEMU.
   3. Запустить отдельное apply-окно только для `nova_libvirt`:

      ```bash
      ansible-playbook -i inventory/lab-os1-to-os2.yml \
        playbooks/12-reconcile-target-host-containers.yml \
        -e target_host_container_reconcile_apply=true \
        -e target_host_container_reconcile_include_libvirt=true \
        -e target_host_container_reconcile_nova_libvirt_image=<candidate-image>
      ```

   4. Принять результат только если после apply прошел `runtime guard`: тот же
      набор running domains, тот же snapshot interfaces и успешный network
      probe ВМ.
   5. Если target `nova_libvirt` не видит домены, `virsh` не отвечает,
      `nova-compute` пишет `HypervisorUnavailable` или пропадает ping до ВМ,
      остановить эксперимент и оставить rollback playbook-а на исходный
      `nova_libvirt`.

   Это отдельное окно после burn-in, а не часть первичного cutover. В первичном
   cutover меняются control-plane agents; `nova_libvirt` относится к
   hypervisor management plane и должен переключаться только после отдельной
   проверки совместимости.

   OVS (`openvswitch_db`, `openvswitch_vswitchd`) также не входит в default
   scope. Его можно включить только отдельным флагом и отдельным окном:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/12-reconcile-target-host-containers.yml \
     -e target_host_container_reconcile_apply=true \
     -e target_host_container_reconcile_include_ovs=true
   ```

   Для текущей цели непрерывности ВМ OVS лучше не включать в первый прогон:
   пересоздание OVS containers может дать краткий разрыв dataplane.

13. source DB metadata cleanup делать только после закрытия rollback window и
    отдельного reviewed SQL/процедуры.

До подготовки metadata и target config не запускать cutover.
