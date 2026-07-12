# Каркас импорта SQL

Каталог намеренно содержит пустые placeholders. Перед любым планированием
import нужно запустить read-only live discovery:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/02b-discover-live-resource-graph.yml
```

Источником истины служат live API, `information_schema`, UUID-scoped SELECT и
runtime/probe evidence. Schema-only dump допустим только как санитизированная
fixture/справочный пример и не заменяет discovery. Эти файлы нельзя запускать
непосредственно.

Правила последующего reviewed import:

1. Не импортировать целиком Nova/Neutron/Cinder/Placement DB в живой target.
2. Не использовать `INSERT ... SELECT *` между разными patch/vendor schema.
3. Использовать `schema-mapping.json`, `uuid-filters.json` и live
   `information_schema`; затем отдельно review generated SQL.
4. Сохранять UUID instances, ports, volumes, attachments, request specs и
   instance mappings.
5. Переназначать auto-increment integer IDs только явно и с FK review.
6. Если target Nova schema содержит `instances.compute_id`, связать его с
   target `compute_nodes` для `rehome_host`.
7. Placement не импортировать автоматически: target `nova-compute` создаёт
   provider, а heal выполняется отдельной последующей фазой.
8. Перед каждым import делать target DB backup и pre-import conflict guard.
9. `UNKNOWN`/`BLOCKED` live discovery запрещают import.
