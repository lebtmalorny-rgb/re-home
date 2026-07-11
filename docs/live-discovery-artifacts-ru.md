# Артефакты live discovery

Финальный каталог одного запуска:

```text
{{ local_artifact_dir }}/live-discovery/<run-id>/
```

Assembler записывает набор атомарно. При ошибке валидации старый полный набор
сохраняется; частичный новый набор не публикуется. Один writer удерживает
sibling lock, а orchestration отдельно владеет
`.control/owners/<run-id>`. Успешный run сохраняет completion marker без
секретных bytes. Повторный или concurrent запуск с тем же `run-id` отклоняется.
После atomic install финальный run-каталог — `0700`, восемь normal files —
`0644`. Опциональный `sensitive/` остаётся `0700`, а его файл — `0600`.

## Обычные файлы

| Файл | Contract | Назначение |
| --- | --- | --- |
| `resource-graph.json` | `openstack-rehome-resource-graph/v1alpha1` | Канонический граф nodes, required edges, checks и `graph_sha256` |
| `resource-graph.yml` | тот же graph contract | Детерминированное YAML-представление графа |
| `readiness-report.json` | `openstack-rehome-readiness-verdict/v1alpha1` | Итоговый verdict, exit code, counts, reasons и проверки |
| `readiness-report.md` | тот же verdict | Инженерный отчёт без raw secrets |
| `schema-capabilities.json` | `openstack-rehome-schema-capabilities/v1alpha1` | Live source/target capabilities и использованные schema columns |
| `schema-mapping.json` | `openstack-rehome-directional-schema-mapping/v1alpha1` | Направленный mapping `keystack-2025.1` → `vanilla-openstack-2025.1-epoxy` |
| `uuid-filters.json` | `openstack-rehome-uuid-filters/v1alpha1` | Точные resource-scoped фильтры live DB запросов |
| `evidence-index.json` | `openstack-rehome-evidence-index/v1alpha1` | Типизированный индекс API/DB/runtime/storage/Glance evidence без raw stdout |

Это точный обычный набор из восьми файлов. `source-control.json`,
`target-control.json`, `runtime.json`, phase triplets и
`*-information-schema.tsv` — промежуточные run-local inputs assembler, а не
часть окончательного нормального набора.

Дополнительные внутренние контракты: collector
`openstack-rehome-live-discovery/v1alpha1` и control bundle
`openstack-rehome-control-bundle/v1alpha1`. Версии нельзя угадывать или
смешивать: неизвестная/лишняя структура отклоняется fail-closed.

## Точный evidence index

Каждый entry всегда содержит common fields `evidence_id`, `kind`, `side`,
`service`. Допустимы только следующие kinds и exact дополнительные поля:

| Kind | Обязательные дополнительные поля |
| --- | --- |
| `openstack-json` | `command` (непустой argv list) |
| `runtime-command` | `command` (непустой argv list) |
| `db-jsonl` | `schema`, `table`, непустой `filters` |
| `storage-probe` | `resource_id`, `backend_kind`, `backend_identity`, `resource_identity`, `resource_fingerprint`, `scope`, `expected_size`, `observed_size`, `status` |
| `glance-range` | `resource_id`, `endpoint_origin`, `expected_size`, `observed_size`, `required`, непустой `store_ids`, `status` |
| `cinder-connection` | `volume_id`, `attachment_id`, `backend_kind`, `backend_id`, `resource_identity`, `resource_fingerprint` |

`side` равен только `source` или `target`; storage `scope` — только
`source-compute`/`target-storage`. Status probe — `PASS`, `WARN`, `UNKNOWN` или
`BLOCKED`. Raw stdout/stderr, tokens и connection data в index отсутствуют.

## Защищённый файл

Если действительно есть sensitive Cinder evidence, создаётся опциональный:

```text
sensitive/evidence.json
```

Каталог имеет mode `0700`, файл — `0600`. В нём могут находиться полные
connector/connection data, необходимые для привязки backing object. Он не
должен публиковаться в тикетах, Markdown, CI output или общем archive.
Отсутствие каталога допустимо, если sensitive evidence не передавалось.

## Verdict и exit code

```text
READY=0
READY_WITH_WARNINGS=0
UNKNOWN=2
BLOCKED=3
```

`UNKNOWN` — блокирующее fail-closed состояние для дальнейшего import/cutover,
несмотря на отличие причины от `BLOCKED`. Top-level playbook принимает только
rc `0`; поэтому оба ненулевых verdict останавливают Ansible. Некорректный input
также отклоняется, а не становится READY.

## Что входит и не входит

Граф охватывает Nova/runtime, Neutron, Cinder и Glance для ВМ выбранного host.
Masakari и DRS не входят в collectors, graph, evidence index и readiness
verdict. Placement только читается; heal не выполняется. Discovery не создаёт
API objects, не импортирует SQL, не копирует volume/image data, не останавливает
services и не запускает `online_data_migrations`.

## Хранение и удаление

- Обычные восемь файлов хранить вместе с `run-id`, inventory revision и
  change record до окончания burn-in/rollback window; затем — по принятой
  политике аудита.
- `sensitive/evidence.json` хранить минимально необходимое время в защищённом
  хранилище, отдельно от normal archive; удаление фиксировать в change record.
- HMAC key, clouds files, Glance tokens, probe configs и другие caller-owned
  originals никогда не изменяются и не удаляются. Orchestration удаляет только
  собственные frozen/staged owned copies после success либо
  ownership-checked cleanup.
- Незавершённый owned lock можно удалить только штатным cleanup; не применять
  рекурсивное удаление к общему `live-discovery` каталогу.
- Runtime/generated `artifacts/` не коммитить.

Fixture tests и `syntax-check` проверяют формат/порядок, но не доказывают
готовность конкретного live кластера. Операционный порядок приведён в
[`lab-rehome-runbook-ru.md`](../lab-rehome-runbook-ru.md), поток данных — в
[`live-discovery-data-flow-ru.md`](live-discovery-data-flow-ru.md).
