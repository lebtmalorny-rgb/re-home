# Готовность Cinder для live discovery

Документ описывает, какие доказательства должен собрать
[`02b-discover-live-resource-graph.yml`](playbooks/02b-discover-live-resource-graph.yml)
для Cinder volume, связанного с ВМ на `rehome_host`. Источник истины — живые
source и target кластеры. SQL/schema dumps допустимы только как
санитизированные fixture для тестов и не заменяют live API, БД и storage probe.

## Что входит в граф

Для каждого volume из Nova BDM раскрывается полная активная зависимость:

- volume UUID, размер, status, attach status и bootable flag;
- каждая attachment, включая отдельное доказательство для каждого подключения
  `multiattach` volume;
- Nova instance/BDM и Cinder attachment identity;
- volume type, extra specs, project visibility и QoS specs/associations;
- `service_uuid`, `cinder-volume` service, `host`, backend name и cluster;
- encryption type/provider/control location и UUID ключа Barbican;
- snapshot, source volume, group и group snapshot;
- metadata и volume image metadata по безопасному allowlist;
- storage backend и фактический backing object.

Required edge не может указывать на отсутствующий node. Несогласованность API и
БД, неоднозначная attachment, отсутствующий `service_uuid`, неизвестный
encryption key или несовпадение backend identity закрывают проверку как
`BLOCKED` либо `UNKNOWN`, а не превращаются в пустой успешный результат.

## Подключения, multiattach и секреты

Connection evidence привязывается к паре `(volume_uuid, attachment_uuid)`.
Для `multiattach` одной сводки на volume недостаточно: каждое активное
подключение должно иметь собственную доказанную связь с тем же backing object.
Collector сверяет instance, host, mode/state, driver kind, backend ID,
производный resource identity, fingerprint и размер.

Полные `connection_info` и `connector` содержат чувствительные поля. Они не
попадают в обычный граф, JSON/YAML/Markdown или test output. В обычном artifact
остаются только типизированная сводка и `[REDACTED]`; полные данные допускаются
только в защищённом `sensitive/evidence.json` с mode `0600` внутри каталога
`0700`. Значения password, token, CHAP secret, secret UUID и аналогичные поля в
обычных артефактах запрещены.

`live_discovery_source_cinder_sensitive_evidence_file_local` и target-аналог
условно обязательны: если на стороне есть active attachment, защищённый
envelope `openstack-rehome-cinder-sensitive-evidence/v1alpha1` должен содержать
отдельный entry для каждой пары volume/attachment. Пустой path допустим только
когда таких attachments действительно нет; иначе readiness закрывается
fail-closed. Caller-owned файл не удаляется — cleanup касается только
замороженной/staged копии текущего run.

## Backing object и типы хранилищ

NFS не является обязательным или единственным backend. Переменная
`live_discovery_storage_backends` задаёт типизированную карту backend-ов и
delegate для обеих сторон. Реализованы только неразрушающие проверки размера:

| Тип | Read-only probe | Что запрещено |
| --- | --- | --- |
| `nfs` / `file` | `stat --format %s` для пути под разрешённым root | mount, copy, rename, delete |
| `rbd` | `rbd info --format json` для разрешённых pool/image | map, clone, import, resize |
| `lvm` | `lvs --reportformat json --units b --nosuffix` для разрешённых VG/LV | activate, snapshot, extend |

Для NFS/file, RBD и LVM PASS требует совпадения volume UUID, attachment
evidence, backend kind/ID, точного resource identity, fingerprint и размера в
GiB/bytes. Проверка выполняется как минимум в нужном scope:
`source-compute` и `target-storage`.

iSCSI, Fibre Channel и vendor backend не скрываются и не считаются NFS. Их
driver/connector facts сохраняются в типизированном виде, но без отдельно
reviewed read-only probe template итог — `UNKNOWN`. Discovery не устанавливает
iSCSI session, не выполняет FC login, не монтирует filesystem и не активирует
LV. Неизвестный driver — это не разрешение импровизировать команду.

Пустая карта `live_discovery_storage_backends: {}` также намеренно даёт
`UNKNOWN` для требуемого storage evidence. Generic inventory именно так и
настроен; NFS в lab inventory — только пример конкретного стенда.

## Общие и локальные хранилища

Признак shared/non-shared выводится из живых backend и attachment facts, а не
из имени backend. Для shared storage нужно доказать, что тот же backing object
доступен с требуемых source/target ролей. Для non-shared storage отсутствие
target-side объекта или безопасного пути переноса блокирует готовность. Сам
discovery ничего не копирует и не создаёт.

## Encryption и Barbican

Для encrypted volume проверяются тип шифрования, provider, control location,
key UUID и метаданные ключа Barbican без чтения payload. `403`/`404` для
обязательного ключа — `BLOCKED`; отсутствующий endpoint или недоказанная
доступность — `UNKNOWN`. Ключевой материал и полный secret href не выводятся.

## Интерпретация результата

- `PASS`: metadata closure полна, attachment-ы согласованы, target capability
  доказана, backing object доступен и размер совпадает.
- `WARN`: только явно классифицированное неблокирующее отклонение.
- `UNKNOWN`: отсутствует безопасный probe, capability или достаточное evidence.
- `BLOCKED`: обязательный объект недоступен, противоречив или несовместим.

Общий verdict и коды выхода описаны в
[`docs/live-discovery-artifacts-ru.md`](docs/live-discovery-artifacts-ru.md).
На текущем этапе проверены fixture/syntax tests; реальный production/live
запуск этой документацией не утверждается.
