# Готовность Glance для live discovery

Документ описывает Glance-часть resource graph, которую собирает
[`02b-discover-live-resource-graph.yml`](playbooks/02b-discover-live-resource-graph.yml).
Живые API, store capabilities и byte probe являются источником истины;
загруженный dump может быть только санитизированной fixture.

## Когда image обязателен

Collector связывает Nova image reference, BDM и runtime disks и отдельно
классифицирует требуемость image:

- для ephemeral/local root, rebuild, rescue и других последующих операций
  доступность image обязательна;
- для доказанно `volume-backed` running instance историческая ссылка может
  быть warning, только если BDM и runtime graph доказывают отсутствие
  зависимости текущего root disk от Glance object;
- отсутствие достаточных BDM/runtime facts даёт `UNKNOWN`, а не предположение.

## Метаданные и доступ проекта

Для каждого требуемого image проверяются UUID, status `active`, size, disk и
container format, owner/project, `visibility`, tags, locations/stores,
properties по allowlist, `members` и их status. Private/shared/community/public
семантика оценивается вместе с target project access: наличие image в backend
не доказывает, что нужный `project` имеет право его использовать.

Хэши `os_hash_algo` и `os_hash_value`, checksum и ожидаемый size сохраняются как
целостностные факты. Секретные location credentials и произвольные свойства не
переносятся в обычные артефакты.

## Происхождение store

Store ID из image locations должен совпасть с независимо собранным inventory
enabled stores/default store. Endpoint для probe привязывается к независимо
полученному service catalog origin. Нельзя подменить Glance URL, store ID или
image UUID данными самого probe config.

Для нескольких stores проверяется фактическая зависимость конкретного image.
Vendor-specific tables/locations включаются только при UUID-связи с выбранным
image; наличие таблицы само по себе не является доказательством использования.

## Однобайтовая проверка

При `live_discovery_glance_range_probe_enabled: true` выполняется read-only GET
с заголовком:

```text
Range: bytes=0-0
```

HTTP 206 с exact `Content-Range: bytes 0-0/<expected_size>`,
`Content-Length: 1` и одним прочитанным байтом даёт `PASS`. Если сервер
игнорирует Range и отвечает HTTP 200, exact `Content-Length: <expected_size>`
плюс один прочитанный байт дают `WARN`, а не `PASS`: collector не считывает
оставшееся тело. Несогласованный 200/206 даёт `BLOCKED`. `403`, `404`, `416` и
`204` для обязательного image дают `BLOCKED`; transport/TLS/endpoint
uncertainty даёт `UNKNOWN`. Source и target используют разные token files:
`live_discovery_source_glance_token_file_local` и
`live_discovery_target_glance_token_file_local`; их содержимое не должно
совпадать и не попадает в normal artifacts.

## Fail-closed результат

PASS требует одновременно корректных metadata, project/member access, store
provenance, size/hash facts и byte probe для обязательного image. Ошибка одного
источника не заменяется пустым списком. Итоговые проверки и evidence IDs можно
сопоставить по [`evidence-index.json`](docs/live-discovery-artifacts-ru.md).

На текущем этапе реализация подтверждена fixture-тестами и Ansible
`syntax-check`; этот документ не заявляет, что probe уже выполнен на реальном
production/live кластере.
