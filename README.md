# OpenStack compute host re-home

Репозиторий содержит Ansible/runbook для контролируемого re-home compute host
между двумя OpenStack control planes. Сценарий рассчитан на host, где уже
работают libvirt/QEMU domains, поэтому главная цель - перевести управление
host в target control plane без остановки ВМ и без потери ее сетевой
доступности.

Это не универсальная кнопка миграции. Перед cutover target control plane должен
получить согласованную Nova/Neutron/Cinder metadata model для переносимых ВМ,
ports и volumes.

## Что читать первым

1. `docs/lab-topology-ru.md` - схема lab до и после re-home: Ansible host,
   source/target control plane, reference compute, re-home host, ВМ и сеть.
2. `operator-inputs-ru.md` - какие входные данные, secrets, clouds/configs и
   prerequisites нужно подготовить для другой инфраструктуры.
3. `playbook-logic-ru.md` - что делает каждый playbook, где он запускается,
   какие state-changing действия выполняет и какие guardrails применяет.
4. `lab-rehome-runbook-ru.md` - короткое описание текущего lab и фактического
   пути os1 -> os2.
5. `neutron-rehome-behavior-ru.md`,
   `horizon-rehome-visibility-ru.md`,
   `nova-ovs-rehome-investigation-ru.md` - отдельные failure modes, которые
   были найдены в ходе проверки.

## Термины

- `cp_a` / `source_control` - текущий владелец compute host.
- `cp_b` / `target_control` - новый владелец compute host.
- `rehome_compute` - compute host с running domains.
- `target_reference_compute` - штатный target compute, откуда берутся Kolla
  config bundles для target runtime containers.
- `rehome_host` - canonical Nova compute host identity; должен совпадать до и
  после cutover.
- `hypervisor_hostname` - значение Nova/libvirt для compute node; обычно равно
  `rehome_host`.

## Главные правила

1. Никогда не держать source и target `nova-compute` одновременно на одном
   host.
2. Не останавливать libvirt/QEMU domains во время cutover.
3. Сохранять instance UUID, libvirt domain UUID, Neutron port UUID, MAC, fixed
   IP, Cinder volume ID и attachment ID.
4. Для OVS/OVN недостаточно сохранить только MAC/IP: tap devices и logical
   ports завязаны на port UUID и binding metadata.
5. Первый target `nova_compute` запускать в safe-mode: без running-deleted
   cleanup, без power-state sync, без lifecycle events, service disabled.
6. Source DB/configs остаются rollback authority до завершения burn-in.
7. Для Kolla-Ansible target images нужно скачать до cutover, а активные
   Nova/network agent containers переключать на target tags именно в cutover,
   не после принятия ВМ.

## Быстрый запуск в lab

Команды запускаются с Ansible runner из каталога проекта:

```bash
cd migration_project/openstack-rehome-ansible
ansible-playbook -i inventory/lab-os1-to-os2.yml playbooks/<name>.yml
```

Для новой инфраструктуры не запускать lab inventory как есть. Сначала
адаптировать `inventory/hosts.yml`, `group_vars/all.yml` или отдельный
inventory по образцу `inventory/lab-os1-to-os2.yml`.

## Recommended execution order

Generic runbook order:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/00-preflight.yml
ansible-playbook -i inventory/hosts.yml playbooks/01-freeze-source.yml
ansible-playbook -i inventory/hosts.yml playbooks/02-collect-inventory.yml
ansible-playbook -i inventory/hosts.yml playbooks/02a-build-rehome-manifest.yml
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

Для Kolla-Ansible нужны дополнительные image-tag фазы вокруг cutover:

```text
Фаза 0   Предварительные проверки
Фаза 1   Заморозка source scheduling
Фаза 2   Backup и инвентаризация
Фаза 2a  Сбор host-scoped re-home manifest через Ansible playbook
Фаза 3   Backup DB и read-only проверка совместимости DB schema
Фаза 3a  Нормализация schema diff для отделения шумовых отличий от реальных
Фаза 3b  Target API prep report: что уже есть на CP-B, что можно создать через API, что требует DB import
Фаза 3c  DB metadata import review-pack: ordered SQL blocks, UUID filters, guardrails
Фаза 3d  Read-only source DB row collection по UUID filters
Фаза 3e  Hard-stopped target SQL import draft generation
Фаза 3f  Target pre-import guard: target rows по UUID должны отсутствовать или быть явно разобраны
Фаза 3g  Backup target DB immediately before metadata import
Фаза 3h  Apply reviewed target SQL import
Фаза 3i  Нормализация target-specific metadata: cell_id, service_uuid, volume_type_id и похожие UUID/FK
Фаза 3j  Нормализация Neutron ML2 binding levels для переносимых ports
Фаза 3k  Подготовка Nova compute service row для re-home host
Фаза 3l  Нормализация project/user visibility для target Horizon
Фаза 3m  Подготовка schema и metadata на CP-B
Фаза 4   Предварительная загрузка target images на re-home host
Фаза 5   Подготовка target Kolla configs на re-home host
Фаза 5a  Отключение явно подтвержденных source-only non-runtime сервисов
Фаза 6   Cutover:
         остановить source Nova/network containers
         запустить target-tag network containers
         запустить target-tag nova_compute в safe-mode
Фаза 7   Перепривязка Neutron ports
Фаза 8   Placement heal и проверка Nova
Фаза 9   Включение target compute service
Фаза 10  Burn-in / стабилизация
Фаза 11  Очистка старых source images и containers
```

Rollback before target-side VM operations:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/90-rollback-to-source.yml
```

## Files

- `docs/lab-topology-ru.md`: схема lab до и после re-home.
- `inventory/hosts.yml`: generic inventory example.
- `inventory/lab-os1-to-os2.yml`: рабочий lab inventory для Rocky `os1` -> Ubuntu `os2`; содержит lab-local paths и должен адаптироваться перед переносом.
- `group_vars/all.yml`: переменные, которые нужно адаптировать для своего окружения.
- `lab-rehome-runbook-ru.md`: краткий русский runbook и исходное состояние текущего lab.
- `operator-inputs-ru.md`: входные данные, секреты, конфиги и prerequisites для запуска в другой инфраструктуре.
- `playbook-logic-ru.md`: русское описание логики каждого playbook-а, где он выполняется и что меняет.
- `neutron-rehome-behavior-ru.md`: русское описание поведения Neutron/OVS во время re-home и failure mode `Device <port_uuid> is not bound`.
- `horizon-rehome-visibility-ru.md`: русское описание видимости ВМ в Horizon после re-home, включая source stale UI и target project scope.
- `playbooks/*.yml`: runbook playbooks.
- `playbooks/02a-build-rehome-manifest.yml`: read-only source/target/compute manifest collection.
- `playbooks/03a-check-db-schema-compat.yml`: read-only Nova/Neutron/Cinder/Placement schema compatibility report.
- `playbooks/03b-normalize-schema-diff.yml`: local normalization pass for collected schema compatibility artifacts.
- `playbooks/04a-plan-target-api-prep.yml`: report-first target API preparation from `rehome_manifest.json`.
- `playbooks/04b-plan-db-metadata-import.yml`: local DB metadata import review-pack generator.
- `playbooks/04c-collect-source-db-rows.yml`: read-only source DB row collection for metadata review.
- `playbooks/04d-generate-target-sql-draft.yml`: hard-stopped target SQL import draft generator.
- `playbooks/04e-target-preimport-guard.yml`: read-only target DB conflict guard before SQL import.
- `playbooks/04f-backup-target-db.yml`: Kolla-aware target DB backup before metadata import; defaults to the MariaDB socket inside the container.
- `playbooks/04g-apply-target-sql.yml`: explicit reviewed SQL import through the target MariaDB container socket.
- `playbooks/04h-normalize-target-metadata.yml`: explicit post-import normalization for target-specific metadata values such as Cinder volume type IDs.
- `playbooks/04j-ensure-neutron-ml2-binding-levels.yml`: explicit target Neutron ML2 binding-level normalization for re-home OVS ports.
- `playbooks/04k-ensure-nova-compute-service.yml`: explicit target Nova service-row normalization for the re-home compute host.
- `playbooks/04l-normalize-target-project-visibility.yml`: explicit target project/user normalization so imported instances can appear in target Horizon project scope.
- `playbooks/04i-prepull-target-images.yml`: pre-pulls target-tag Kolla runtime images on the re-home host and records image digests before cutover.
- `playbooks/05b-stage-target-kolla-config.yml`: copies full target Kolla runtime config bundle from a target reference compute, rewrites host-specific values for the re-home host, and stages it without restarting containers.
- `playbooks/05a-disable-source-only-services.yml`: guarded pre-cutover stop for explicitly approved source-only services.
- `templates/*.j2`: safe-mode compute config overlays.
- `scripts/*.sh`: source inventory and DB helper scripts.
- `sql-skeleton/README.md`: reference skeleton for the expected target SQL set; do not run it directly.
- `kolla-image-tags.md`: Kolla-specific описание image tags и переключения containers.

## Что не коммитить

В git не должны попадать runtime/generated данные:

- `artifacts/`;
- `.ansible/`;
- `__pycache__/`, `*.pyc`;
- реальные `passwords.yml`, `clouds.yaml`, `openrc`, DB dumps и SQL apply
  artifacts с production data.

Для review полезны docs, playbooks, scripts, templates, tests,
`sql-skeleton/` и inventory examples без секретов.
