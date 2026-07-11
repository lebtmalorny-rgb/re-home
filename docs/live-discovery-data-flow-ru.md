# Поток данных live discovery

Live discovery — отдельный read-only gate перед любым DB import или cutover.
Source profile фиксирован как `keystack-2025.1`, canonical target — живой
`vanilla-openstack-2025.1-epoxy`. Загруженная schema/DB dump не является
источником истины; dump допустим только как санитизированная fixture тестов.

## Схема

```mermaid
flowchart LR
  A["Ansible runner\nowner lock, HMAC, assembler"]
  S["source_control\nAPI + information_schema + UUID SELECT"]
  T["target_control\nAPI + information_schema + UUID SELECT"]
  C["rehome_compute\nlibvirt + OVS/OVN runtime"]
  R["target_reference_compute\nlibvirt/QEMU capabilities"]
  PS["source storage/image delegate\nCinder backing + Glance Range"]
  PT["target storage/image delegate\nCinder backing + Glance Range"]
  G["local assembler\nresource graph + verdict"]

  A -->|"signed --phase api"| S
  A -->|"signed --phase api"| T
  S -->|"root UUID manifest"| A
  A -->|"--phase verify\nverify-before-SQL"| S
  A -->|"--phase verify\nverify-before-SQL"| T
  S -->|"scoped JSONL"| A
  T -->|"scoped JSONL"| A
  A --> C
  A --> R
  A --> PS
  A --> PT
  PS -->|"HMAC-bound phase triplet"| S
  PT -->|"HMAC-bound phase triplet"| T
  S -->|"--phase combine"| G
  T -->|"--phase combine"| G
  C --> G
  R --> T
  G -->|"8 normal artifacts\noptional protected evidence"| A
```

## Семь plays и зависимый порядок

Playbook содержит ровно семь plays; этот порядок определяется данными и не
может быть распараллелен произвольно:

1. `localhost` фиксирует singleton roles, переменные, `run-id`, случайный owner
   token и защищённые inputs; затем атомарно захватывает owner lock.
2. `source_control` выполняет первую `--phase api`, live
   `information_schema`, `--phase verify`, после чего — только с проверенным
   plan digest — UUID-scoped SELECT и JSONL.
3. `target_control` повторяет API/schema/verify/SQL на canonical target и
   собирает live DB revisions/container evidence.
4. `rehome_compute` собирает libvirt domains/disks/interfaces и OVS/OVN runtime.
5. `target_reference_compute` собирает target virsh/QEMU capabilities.
6. `localhost` делегирует Cinder backing и Glance one-byte probes на явно
   заданные source/target hosts, повторно подписывает API phase, возвращает
   точные phase triplets контроллерам и вызывает `--phase combine` для каждой
   стороны.
7. `localhost` запускает assembler, принимает только exit `0`, публикует
   artifacts и завершает owner marker с удалением frozen secrets.

Таким образом, это подписанный двухфазный API/DB acquisition: API определяет
живые roots и scope, DB phase выполняется только после `--phase verify`.
`verified-plan.json` привязан к canonical plan SHA-256 непосредственно перед
SQL. SQL разрешён только как SELECT; API/SQL mutations отсутствуют.

Каждый configured source/target storage delegate выполняет обе семьи:
Cinder backing probes и Glance Range probes. Поэтому delegate должен иметь
сетевой доступ к соответствующему Glance endpoint/token и локальный read-only
доступ к заявленным NFS/file, RBD или LVM resources.

## Доверие и границы

- Root manifest выводится из первой source API phase, а не подаётся оператором
  и не строится из dump.
- Phase artifacts привязаны HMAC к side, API facts, UUID filters, query plan и
  probe results. Fixture и live signatures разделены.
- Source и target Glance tokens раздельны и обязаны иметь разные checksums.
- Caller files mode `0600` открываются один раз без symlink-follow, копируются
  в owned каталог `0700`, после чего исходные пути повторно не читаются.
- Raw DB stderr, failed command stdout, container inspect и Cinder secrets не
  становятся normal artifacts; сохраняются только safe class/hash/typed facts.
- `online_data_migrations` не запускаются. Допустим только свежий защищённый
  operator evidence о ранее выполненных Nova/Cinder проверках с точными live
  revisions; отсутствие или несовпадение даёт `UNKNOWN`/`BLOCKED`.
- Masakari/DRS исключены.

## Сбой, cleanup и повторный запуск

Каждый последующий play проверяет `run-id` и owner token. Rescue/unreachable
cleanup удаляет только собственный незавершённый lock и защищённые временные
данные; чужой или completed owner не затрагивается. Для повторного запуска
использовать новый автоматически сгенерированный `run-id` либо явно новый ID.
Не переиспользовать ID concurrent запуска и не удалять `.control/owners`
вручную без проверки completion marker.

Fixture/syntax tests подтверждают контракт и Ansible структуру, но не являются
результатом реального live deployment. Exact operator inputs описаны в
[`operator-inputs-ru.md`](../operator-inputs-ru.md), финальные файлы — в
[`live-discovery-artifacts-ru.md`](live-discovery-artifacts-ru.md).
