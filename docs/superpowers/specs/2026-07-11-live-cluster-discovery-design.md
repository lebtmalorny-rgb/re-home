# Live discovery для re-home compute host

Дата: 2026-07-11

Статус: согласованный дизайн

Ветка: `feature/live-cluster-discovery`

## Контекст

Проект выполняет re-home compute host с работающими libvirt/QEMU domains из
source OpenStack control plane в target control plane. Существующий lab
проверял перенос между двумя Kolla-кластерами одной серии, но дальнейшая
доработка должна учитывать более общий сценарий:

- source использует vendor-modified Keystack;
- target использует vanilla OpenStack 2025.1 Epoxy;
- факты, schema и строки БД собираются с живых кластеров;
- приложенные schema-only dumps используются только как примеры и тестовые
  fixtures, но не как production source of truth;
- Masakari и DRS не переносятся и не входят в readiness verdict.

Одинаковое имя релиза не означает идентичность schema или data migration
state. Поэтому полное текстовое равенство source и target schema не может быть
обязательным условием. Требуется направленная проверка: все данные выбранного
compute host из vendor source должны быть представимы в canonical vanilla
target schema.

## Цели

Первая реализационная фаза должна:

1. Собирать live facts с source control plane, target control plane и re-home
   compute host без изменения их состояния.
2. Строить полный resource graph для ВМ на `rehome_host`.
3. Проверять не только OpenStack metadata, но и фактическую доступность Cinder
   backing objects с узлов, которые должны ими управлять или подключать их,
   Glance image objects и Neutron dataplane.
4. Выполнять направленный schema capability analysis
   `Keystack source -> vanilla Epoxy target` только для ресурсов графа.
5. Формировать машинные артефакты и инженерный Markdown-отчёт с доказательствами.
6. Завершаться ненулевым кодом при verdict `BLOCKED` или `UNKNOWN`, не позволяя
   оператору принять отсутствие данных за успешную проверку.
7. Обновить всю пользовательскую и инженерную документацию проекта.

## Не входит в первую фазу

- создание или изменение объектов через OpenStack API;
- SQL import, update, schema migration или online data migration;
- копирование Cinder volumes или Glance images;
- остановка, перезапуск или переключение containers/services;
- изменение Placement allocations;
- автоматизация cutover или rollback;
- сбор и перенос Masakari/DRS state;
- универсальный обход всех строк всех service DB.

Существующие state-changing playbook-и остаются отдельными последующими фазами.
Live discovery предоставляет обязательный readiness artifact и отдельный
fail-closed check, но не выполняет re-home самостоятельно.

## Canonical target profile

Target schema и runtime target-кластера являются канонической моделью
назначения. Collector фиксирует:

- OpenStack release и точные service package/container image versions;
- image digests, если deployment driver предоставляет их;
- Nova API DB и cell DB migration versions;
- Neutron Alembic heads/branches и активные ML2/core/service plugins;
- Cinder DB version, drivers, services и backend names;
- Glance DB version, enabled stores и default store;
- фактические таблицы, колонки, types, nullability, defaults, indexes и FK из
  `information_schema`;
- source profile считается доказанным только при совпадении live labels и
  digests четырёх service images с `keystack-2025.1`; policy лишь разрешает
  это значение, а отсутствие точного vendor signal даёт `UNKNOWN`/`BLOCKED`;
- Nova cell schema определяется по выбранному host через
  `nova_api.host_mappings`/`cell_mappings`; из connection URI сохраняется
  только проверенное имя schema, credentials никогда не сериализуются;
- конфигурацию только в объёме, необходимом для определения capabilities;
- признаки незавершённых data migrations, доступные без выполнения мутаций.

Команды `nova-manage db online_data_migrations` и
`cinder-manage db online_data_migrations` не запускаются: они могут изменять
данные. Если завершённость online migrations нельзя доказать read-only
способом или операторским артефактом, результат проверки получает
`UNKNOWN/BLOCKED`.

## Архитектура

### Orchestrator

Новый read-only playbook запускает collectors на соответствующих inventory
groups и собирает результаты на Ansible runner. Предлагаемое имя:

`playbooks/02b-discover-live-resource-graph.yml`

Он не содержит SQL/API mutations. Все remote commands имеют
`changed_when: false`, сохраняют return code и stderr и очищают временные
credentials после сбора.

### Collector package

Новые Python-компоненты размещаются в отдельном пакете, а не добавляются в
существующий монолитный collector:

```text
scripts/live_discovery/
  contract.py
  runner.py
  nova.py
  neutron.py
  cinder.py
  glance.py
  runtime.py
  schema.py
  graph.py
  verdict.py
  render.py
```

Каждый service collector имеет одну ответственность и возвращает общий
контракт:

- `facts` — нормализованные объекты;
- `dependencies` — направленные связи между ресурсами;
- `checks` — проверки, source command/query, return code и evidence;
- `unknowns` — сведения, которые не удалось установить;
- `blockers` — условия, запрещающие переход к import/cutover.

Collectors не знают о формате итогового Markdown и не управляют Ansible.
`graph.py` объединяет результаты, `verdict.py` вычисляет общий verdict, а
`render.py` создаёт артефакты.

## Поток данных

1. Nova source collector получает canonical `rehome_host`, compute service и
   список всех non-deleted instances на host.
2. Для каждой instance собираются project/user, flavor, image references,
   BDM, ports, volumes, cell/host mappings и request spec.
3. Neutron, Cinder и Glance collectors раскрывают зависимости от найденных
   UUID, не сканируя несвязанные tenant resources.
4. Runtime collector собирает libvirt domains, disks, interfaces, machine
   types и OVS/OVN state на compute host.
5. Target collectors ищут canonical UUID и соответствующие capabilities на
   vanilla Epoxy target.
6. Schema collector строит направленную compatibility matrix только для
   реально использованных таблиц и колонок.
7. Graph builder сопоставляет API, DB, backend и runtime evidence.
8. Verdict engine формирует итог и отдельный результат для каждой instance,
   port, volume и image.

## Resource graph

Минимальная структура графа:

```text
compute_host
  -> nova_service / compute_node / placement_provider
  -> instance
       -> project / user / flavor / request_spec / cell_mapping
       -> libvirt_domain / machine_type
       -> port
            -> network / subnet / segment
            -> security_group / qos / trunk / router / floating_ip
            -> ml2_binding / binding_levels / ovs_or_ovn_runtime
       -> volume
            -> attachment / volume_type / cinder_service / backend
            -> encryption / snapshot_source / backing_object
       -> image
            -> member / properties / locations / store / backing_object
```

Каждый node содержит `id`, `kind`, `side`, `source`, `observed_at`, `facts` и
ссылки на evidence. Каждое edge содержит тип зависимости и признак
обязательности для re-home.

## Nova и runtime coverage

Обязательный сбор:

- instances, instance mappings, host mappings и cell mapping;
- request specs, BDM, instance extra/info cache/system metadata;
- compute service, compute node и canonical service/compute UUID;
- flavor и extra specs;
- Placement resource provider и allocations только в read-only режиме;
- libvirt domain UUID, instance name, machine type, disks и interfaces;
- сопоставление libvirt disks с Cinder volume IDs;
- сопоставление tap/vif devices с Neutron port UUID;
- target image/container versions и поддержку используемых machine types.

Placement не импортируется. Discovery только доказывает, что target имеет
необходимые capabilities и что последующая heal phase может быть выполнена.

## Neutron coverage

Collector строится schema-capability-driven и поддерживает только активные
зависимости выбранных ports:

- ports, fixed IP, MAC, device owner/id и port security;
- networks, subnets, allocation pools, DNS, routes и service types;
- network segments и segment ranges;
- `ml2_port_bindings`, distributed bindings и все binding levels;
- security groups/rules/RBAC и allowed-address-pairs;
- extra DHCP options и port DNS;
- QoS policies и network/port/FIP/router bindings;
- trunks и subports;
- routers, router ports/routes, floating IP и port forwarding;
- address groups/scopes при фактической зависимости;
- active agents и host/segment mappings;
- OVS ports/bridges/flows либо OVN logical ports/chassis bindings;
- target physical network, network type и segmentation ID compatibility.

Наличие plugin-таблицы само по себе не делает её обязательной. Она включается,
если config/API/DB показывают активную зависимость от переносимого UUID.

## Cinder coverage

Обязательный сбор:

- volumes и все active attachments;
- volume type, extra specs, QoS и project visibility;
- cinder service UUID, backend host и cluster name;
- encryption provider/control location и key UUID;
- snapshot, source volume и group dependencies;
- volume metadata и volume image metadata;
- connector/connection info в защищённом evidence artifact;
- фактическое наличие backing object;
- доступность backing object с re-home compute и с target-side storage
  service/backend host, который должен управлять или подключать volume;
- классификация shared/non-shared storage;
- target backend capability и направленные mappings для `service_uuid`,
  `volume_type_id`, host/backend identifiers.

Secrets из connection info не попадают в Markdown и обычные JSON/YAML
артефакты. Полные значения при необходимости сохраняются только в отдельном
файле с mode `0600` и `no_log`.

## Glance coverage

Обязательный сбор:

- images, properties, tags, members и visibility;
- locations, stores и store-specific identifiers;
- фактическая доступность image object read-only способом;
- checksum/hash/size без скачивания полного объекта, если backend/API это
  позволяет;
- volume image metadata и связь boot-from-volume с исходным image;
- определение, нужен ли image для дальнейшего жизненного цикла ВМ.

Отсутствующий image блокирует re-home, если он нужен для local ephemeral/root
disk, rebuild, rescue или иной обязательной операции. Для уже работающей
volume-backed instance историческая ссылка может стать warning, но такое
решение должно быть доказано BDM и runtime disk graph.

Vendor-specific Glance tables, например дополнительные node/reference
таблицы, анализируются только при наличии связи с выбранным image UUID.

## Направленная schema compatibility

Полное сравнение source и target schema заменяется resource-scoped mapping.
Для каждой использованной таблицы строится матрица:

```text
source column -> target column | target default | normalization | ignored
```

Классы результата:

- `COMMON_COMPATIBLE` — target принимает source значение без преобразования;
- `NORMALIZATION_REQUIRED` — нужен явный target-specific mapping;
- `SOURCE_ONLY_IGNORED` — vendor field не нужен target и разрешён policy;
- `TARGET_DEFAULT` — target безопасно заполняет значение default/null;
- `TARGET_VALUE_REQUIRED` — значение должно быть получено из target facts;
- `SEMANTIC_MISMATCH` — типы совместимы синтаксически, но семантика различна;
- `BLOCKED` — данные нельзя представить в target schema безопасно.

Правила:

1. Source-only schema/table/column игнорируется только по явному allowlist и
   только если не содержит обязательную зависимость выбранного UUID.
2. Target-only nullable/default column совместима при документированном
   поведении default.
3. Target-only NOT NULL column без default требует target-derived значения.
4. Auto-increment IDs никогда не считаются переносимыми автоматически.
5. UUID/FK mappings (`cell_id`, `compute_id`, `service_uuid`,
   `volume_type_id`, backend IDs) всегда отражаются явно.
6. Column order source не используется для будущего SQL; canonical order
   задаёт target schema.
7. Unknown vendor semantics блокирует переход, а не отбрасывается молча.

Первая фаза только формирует mapping report. Применение mappings относится к
последующей отдельной фазе.

## Verdict model

Общий и per-resource verdict принимает одно из значений:

- `READY` — все обязательные зависимости подтверждены;
- `READY_WITH_WARNINGS` — есть только явно классифицированные неблокирующие
  различия;
- `BLOCKED` — найдена несовместимость или недоступный обязательный ресурс;
- `UNKNOWN` — доказательств недостаточно.

`UNKNOWN` является fail-closed состоянием и возвращает ненулевой exit code.

Обязательные blockers:

- canonical host/instance/cell identity не подтверждена;
- runtime domain/disk/interface расходится с OpenStack metadata;
- Cinder backing object, attachment, backend или encryption dependency
  недоступны/неизвестны;
- обязательный Glance image/store object недоступен;
- Neutron binding/segment/dataplane не сопоставим с target;
- target schema не может представить обязательное source поле;
- API, DB, backend или runtime probe завершился ошибкой;
- collector вернул неполный результат без явного `UNKNOWN`.

## Evidence и артефакты

Артефакты размещаются под
`artifacts/<rehome_host>/live-discovery/<run_id>/`:

- `resource-graph.json` — полный нормализованный граф;
- `resource-graph.yml` — Ansible-friendly представление;
- `readiness-report.json` — машинный verdict;
- `readiness-report.md` — инженерный отчёт;
- `schema-capabilities.json` — source/target capabilities;
- `schema-mapping.json` — направленная mapping matrix;
- `uuid-filters.json` — UUID и DB filters для следующих фаз;
- `evidence-index.json` — индекс команд, запросов, rc, stderr и raw artifacts;
- `sensitive/` — отдельные защищённые evidence files, если нужны.

Каждый check фиксирует command/query kind, cluster side, timestamp, return
code, нормализованный вывод, affected UUID и ссылку на raw evidence.
Индекс обязательно содержит observed timestamp, return code, sanitized failure
class, SHA-256 stderr и protected raw-artifact reference. Ожидаемый 404 на
пустом pre-import target становится typed absence check, тогда как 403,
отсутствующий endpoint и invalid JSON остаются fail-closed ошибками.

Storage probes группируются по delegate отдельно для source и target. Каждая
группа имеет собственную HMAC-bound phase и provenance; результаты нескольких
NFS/RBD/LVM hosts объединяются только детерминированно после проверки общего
scope.

## Ошибки и безопасность

- Ошибка команды не заменяется `{}` или `[]`.
- JSON parse error, missing field, permission error и timeout имеют разные
  error codes и сохраняют stderr.
- Optional capability отличается от failed probe.
- Query filters строятся только из валидированных UUID/host identity.
- DB users должны иметь только SELECT к нужным service schema и
  `information_schema`.
- OpenStack credentials должны быть admin read-only policy, если среда это
  поддерживает.
- Временные `clouds.yaml` удаляются на success и failure через Ansible
  `always` blocks.
- Secrets не логируются и не попадают в обычные artifacts.
- Collector не выполняет команды с `create`, `set`, `update`, `delete`,
  `sync`, `migrate`, `heal`, `rebind`, `stop`, `restart` или SQL DML/DDL.

## Документация

Документация является обязательной частью реализации. Обновляются:

- `README.md` — новый execution order и роль live discovery;
- `operator-inputs-ru.md` — read-only credentials, target vanilla Epoxy и
  backend prerequisites;
- `playbook-logic-ru.md` — логика каждого нового playbook/task/collector;
- `lab-rehome-runbook-ru.md` — команды запуска и интерпретация verdict;
- `docs/lab-topology-ru.md` — data-flow/evidence схема без изменения физической
  topology;
- `neutron-rehome-behavior-ru.md` — расширенные dependency checks;
- новый `cinder-rehome-readiness-ru.md`;
- новый `glance-rehome-readiness-ru.md`;
- описание resource graph, artifact contract и schema mapping;
- явное указание, что Masakari/DRS исключены из scope.

Тест документации проверяет, что каждый top-level playbook описан и включён в
execution order.

## Тестирование

### Unit tests

- parser/normalizer каждого collector;
- resource graph assembly и edge cardinality;
- verdict aggregation и fail-closed behavior;
- source vendor -> target vanilla column mapping;
- redaction sensitive fields;
- Markdown/JSON/YAML renderers;
- запрет mutation command classes.

### Fixtures

- vanilla Epoxy target schema capabilities;
- vendor source schema с source-only columns/tables;
- OVS и OVN variants;
- Cinder shared и non-shared backends;
- encrypted и unencrypted volumes;
- boot-from-image и boot-from-volume instances;
- Neutron QoS/trunk/router/FIP optional dependencies;
- truncated, malformed и permission-denied outputs.

Приложенный schema-only dump может использоваться как источник структуры для
санитизированной fixture, но сам dump не коммитится.

### Integration checks

- `python3 -m unittest discover -s tests`;
- Ansible syntax-check всех playbook-ов;
- local fixture smoke, не требующий кластера;
- live read-only smoke с mutation audit;
- negative smoke, где failed probe обязательно даёт `UNKNOWN/BLOCKED`.

## Этапы реализации

1. Artifact contract, runner и fail-closed error model.
2. Nova source root discovery и runtime graph.
3. Target vanilla Epoxy profile и directional schema capabilities.
4. Neutron dependency collector и dataplane probes.
5. Cinder dependency/backend collector.
6. Glance dependency/store collector.
7. Graph/verdict/rendering и fail-closed playbook.
8. Полное обновление документации.
9. Fixture/unit/syntax/integration verification.

Каждый этап остаётся read-only. Любая будущая автоматизация import/cutover
проектируется отдельно после проверки live-discovery artifacts на реальном
source/target стенде.

## Критерии готовности

Фаза считается завершённой, когда:

1. Для всех instances на `rehome_host` построен связный Nova/Neutron/Cinder/
   Glance/runtime graph.
2. Каждый обязательный edge имеет evidence или явный blocker.
3. Keystack-specific различия классифицированы относительно live vanilla
   Epoxy target schema.
4. Ошибка любого обязательного probe не может дать `READY`.
5. Collector не выполняет mutations и это подтверждено тестами/audit.
6. JSON/YAML/Markdown artifacts согласованы одним contract version.
7. Обновлена вся перечисленная документация.
8. Unit tests и Ansible syntax-check проходят.

## Официальные ориентиры

- OpenStack 2025.1 Epoxy releases: <https://releases.openstack.org/epoxy/>
- Nova database migrations:
  <https://docs.openstack.org/nova/2025.1/reference/database-migrations.html>
- Nova management commands:
  <https://docs.openstack.org/nova/2025.1/cli/nova-manage.html>
- Neutron Alembic migrations:
  <https://docs.openstack.org/neutron/latest/contributor/alembic_migrations.html>
- Cinder upgrades:
  <https://docs.openstack.org/cinder/latest/admin/upgrades.html>
- Cinder 2025.1 release notes:
  <https://docs.openstack.org/releasenotes/cinder/2025.1.html>
- Glance database migrations:
  <https://docs.openstack.org/glance/latest/contributor/database_migrations.html>
