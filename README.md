# OpenStack compute host re-home

Репозиторий содержит Ansible/runbook для контролируемого re-home compute host
с уже работающими libvirt/QEMU domains из vendor-modified source control plane
в target control plane. В текущем профиле source — `keystack-2025.1`, а
canonical target — живой vanilla OpenStack 2025.1 Epoxy:
`vanilla-openstack-2025.1-epoxy`.

Главный обязательный gate — read-only live discovery. Он строит resource graph
Nova/runtime, Neutron, Cinder и Glance по данным живых кластеров. Загруженная
schema/DB dump может быть только санитизированной fixture или справочным
примером и не является production source of truth.

## Что читать первым

1. [Поток live discovery](docs/live-discovery-data-flow-ru.md) — семь plays,
   signed API/DB phases, verify-before-SQL и границы доверия.
2. [Входные данные оператора](operator-inputs-ru.md) — inventory, exact vars,
   credentials, protected files, storage probes и preflight.
3. [Артефакты live discovery](docs/live-discovery-artifacts-ru.md) — восемь
   обычных файлов, contracts, verdict/exit codes и retention.
4. [Логика playbook-ов](playbook-logic-ru.md) — где выполняется и что меняет
   каждый playbook.
5. [Операционный runbook](lab-rehome-runbook-ru.md) — команды, cleanup,
   troubleshooting и порядок до cutover.
6. [Lab topology](docs/lab-topology-ru.md) — конкретный стенд os1 → os2;
   его NFS backend является только примером.
7. Готовность сервисов: [готовность Cinder](cinder-rehome-readiness-ru.md),
   [готовность Glance](glance-rehome-readiness-ru.md),
   [готовность Neutron](neutron-rehome-behavior-ru.md).

## Область и ограничения

Live discovery:

- читает source/target OpenStack API, `information_schema`, UUID-scoped SELECT,
  compute runtime, target capabilities и backing objects;
- не создаёт и не изменяет OpenStack objects;
- не импортирует SQL и не копирует Cinder/Glance data;
- не останавливает/перезапускает services или QEMU domains;
- не выполняет `nova-manage db online_data_migrations` и
  `cinder-manage db online_data_migrations`;
- не переносит Placement allocations; heal остаётся последующей отдельной
  фазой;
- полностью исключает Masakari и DRS из collectors, graph и verdict.

Остальные playbook-и репозитория могут менять состояние и запускаются только
после review артефактов discovery. Наличие этих playbook-ов не означает, что
реальный перенос уже выполнен.

## Обязательный первый запуск

Сначала адаптировать [generic inventory](inventory/hosts.yml) и
[`group_vars/all.yml`](group_vars/all.yml), затем выполнить:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/02b-discover-live-resource-graph.yml
```

Для lab используется отдельный пример:

```bash
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/02b-discover-live-resource-graph.yml
```

До этой команды должны быть подготовлены singleton groups
`source_control`, `target_control`, `rehome_compute`,
`target_reference_compute`, два clouds files, два разных Glance tokens,
HMAC key, probe configs, Kolla passwords и storage backend map. Generic empty
`live_discovery_storage_backends: {}` намеренно даёт `UNKNOWN` для требуемого
storage evidence.

Итоговые коды:

```text
READY=0
READY_WITH_WARNINGS=0
UNKNOWN=2
BLOCKED=3
```

`UNKNOWN` так же запрещает переход к import/cutover, как и `BLOCKED`.
Top-level Ansible play принимает только rc `0`.

## Рекомендуемый порядок выполнения

Команда discovery обязана предшествовать любому DB import/cutover. Следующий
список показывает полный общий порядок; state-changing шаги требуют отдельного
change review и явных apply flags:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/00-preflight.yml
ansible-playbook -i inventory/hosts.yml playbooks/01-freeze-source.yml
ansible-playbook -i inventory/hosts.yml playbooks/02-collect-inventory.yml
ansible-playbook -i inventory/hosts.yml playbooks/02a-build-rehome-manifest.yml
ansible-playbook -i inventory/hosts.yml playbooks/02b-discover-live-resource-graph.yml

# Продолжать только при READY/READY_WITH_WARNINGS и инженерном review.
ansible-playbook -i inventory/hosts.yml playbooks/03-backup-databases.yml
ansible-playbook -i inventory/hosts.yml playbooks/03a-check-db-schema-compat.yml
ansible-playbook -i inventory/hosts.yml playbooks/03b-normalize-schema-diff.yml
ansible-playbook -i inventory/hosts.yml playbooks/04a-plan-target-api-prep.yml
ansible-playbook -i inventory/hosts.yml playbooks/04b-plan-db-metadata-import.yml
ansible-playbook -i inventory/hosts.yml playbooks/04c-collect-source-db-rows.yml
ansible-playbook -i inventory/hosts.yml playbooks/04d-generate-target-sql-draft.yml
ansible-playbook -i inventory/hosts.yml playbooks/04e-target-preimport-guard.yml
ansible-playbook -i inventory/hosts.yml playbooks/04f-backup-target-db.yml
ansible-playbook -i inventory/hosts.yml playbooks/04g-apply-target-sql.yml -e target_db_import_apply=true
ansible-playbook -i inventory/hosts.yml playbooks/04h-normalize-target-metadata.yml -e target_metadata_normalize_apply=true
ansible-playbook -i inventory/hosts.yml playbooks/04j-ensure-neutron-ml2-binding-levels.yml -e target_neutron_ml2_binding_levels_apply=true
ansible-playbook -i inventory/hosts.yml playbooks/04k-ensure-nova-compute-service.yml -e target_nova_compute_service_apply=true
ansible-playbook -i inventory/hosts.yml playbooks/04l-normalize-target-project-visibility.yml -e target_project_visibility_normalize_apply=true
ansible-playbook -i inventory/hosts.yml playbooks/04i-prepull-target-images.yml
ansible-playbook -i inventory/hosts.yml playbooks/04-prepare-target-control-plane.yml
ansible-playbook -i inventory/hosts.yml playbooks/05-stage-compute-target-config.yml
ansible-playbook -i inventory/hosts.yml playbooks/05b-stage-target-kolla-config.yml
ansible-playbook -i inventory/hosts.yml playbooks/05a-disable-source-only-services.yml
ansible-playbook -i inventory/hosts.yml playbooks/06-cutover-compute.yml
ansible-playbook -i inventory/hosts.yml playbooks/07-rebind-network-ports.yml
ansible-playbook -i inventory/hosts.yml playbooks/08-heal-and-validate.yml
ansible-playbook -i inventory/hosts.yml playbooks/09-enable-target-service.yml
```

Rollback до необратимых target-side операций:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/90-rollback-to-source.yml
```

## Инварианты re-home

1. Source и target `nova-compute` не должны одновременно управлять одним host.
2. QEMU domains, libvirt runtime, dataplane и активные storage sessions не
   останавливаются во время cutover.
3. Сохраняются instance/domain UUID, port UUID/MAC/fixed IP, volume и
   attachment UUID.
4. Для Neutron нужны полные binding/segment/runtime facts, а не только API
   status `ACTIVE`.
5. Для Cinder нужно доказать каждое attachment и backing object. Поддержаны
   read-only size probes NFS/file, RBD и LVM; iSCSI, Fibre Channel и vendor
   backend остаются `UNKNOWN` без reviewed безопасного probe.
6. Для Glance нужны project/member/store provenance, hashes и one-byte Range
   probe, когда image обязателен.
7. Source DB/config остаются rollback authority до окончания burn-in.

## Файлы проекта

- [Generic variables](group_vars/all.yml) и [inventory example](inventory/hosts.yml).
- [Lab inventory](inventory/lab-os1-to-os2.yml) — конкретные адреса/пути,
  не переносить без адаптации.
- [`playbooks/02b-discover-live-resource-graph.yml`](playbooks/02b-discover-live-resource-graph.yml)
  — новый live read-only gate.
- [`inventory/live-discovery-schema-policy.json`](inventory/live-discovery-schema-policy.json)
  — reviewed directional schema policy.
- [Kolla image tags](kolla-image-tags.md),
  [Horizon visibility](horizon-rehome-visibility-ru.md),
  [Nova/OVS investigation](nova-ovs-rehome-investigation-ru.md).
- [SQL skeleton](sql-skeleton/README.md) — только последующий reviewed import,
  никогда не источник live discovery.

## Проверка реализации

В репозитории выполнены unit/fixture tests и Ansible `syntax-check`. Они
проверяют contracts, fail-closed ветки и структуру playbook-а, но не доказывают,
что discovery или re-home выполнялись на production/live кластере. Перед
change window оператор должен запустить playbook на своём inventory и проверить
`readiness-report.json`, `readiness-report.md` и `evidence-index.json`.

## Что не коммитить

Не коммитировать `artifacts/`, `.ansible/`, `__pycache__/`, `*.pyc`, реальные
`passwords.yml`, `clouds.yaml`, openrc, HMAC key, Glance tokens, Cinder
connection evidence, DB dumps и SQL apply artifacts. Правила normal/protected
retention описаны в [документе об артефактах](docs/live-discovery-artifacts-ru.md).
