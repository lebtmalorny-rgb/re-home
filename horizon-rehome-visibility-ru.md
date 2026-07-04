# Видимость ВМ в Horizon после re-home

Этот документ фиксирует отдельный failure mode: ВМ уже принята target Nova, но
не видна на странице target Horizon `Project -> Compute -> Instances`
(`/project/instances/`).

## Главный вывод

`openstack server show` и `openstack server list --all-projects` проверяют
admin/API-level видимость. Страница Horizon `/project/instances/` показывает
только instances текущего project scope пользователя.

Поэтому после re-home возможна такая ситуация:

- target Nova API видит ВМ как `ACTIVE`;
- target Nova DB содержит instance, mapping, compute node и placement
  allocation;
- ВМ доступна по сети;
- но target Horizon `/project/instances/` не показывает эту ВМ.

Это не сетевой сбой и не обязательно сбой `nova_compute`. Чаще всего причина -
несовпадение identity scope: `project_id`/`user_id` импортированной ВМ взяты из
source Keystone, а в target Keystone такого project/user нет или Horizon открыт
в другом project.

## Наблюдение в lab

В lab `os1 -> os2` target Nova API видит переносимую ВМ:

```text
id: d6015a8d-e41f-4c8f-8765-b73c83f7f159
name: os1-vm-100
status: ACTIVE
project_id: 4c5867676d6048af9f03bb846d4bdf70
host: os1-compute-02.example.local
addresses: lab-net=192.168.10.100
```

`openstack server list --all-projects` на target тоже показывает эту ВМ.

Но target Keystone не содержит project
`4c5867676d6048af9f03bb846d4bdf70`. В target уже есть собственный project
`admin` с другим UUID:

```text
target admin project: b901604b49304f2bb64c42bd3bcf5512
source admin project: 4c5867676d6048af9f03bb846d4bdf70
```

Именно поэтому target `/project/instances/` для target `admin` project не
показывает ВМ: instance принадлежит source project UUID, которого нет в target
Keystone.

## Что проверять

После cutover нужно проверять видимость на трех разных уровнях:

1. **Nova DB/cell mapping**

   ```bash
   nova-manage cell_v2 verify_instance --uuid <instance_uuid>
   ```

2. **Target Nova API admin visibility**

   ```bash
   openstack server show <instance_uuid>
   openstack server list --all-projects --long --name <instance_name>
   ```

3. **Target Keystone project visibility**

   ```bash
   openstack project show <project_id_from_server_show>
   openstack role assignment list --project <project_id_from_server_show> --names
   ```

Если первые два пункта работают, а `project show` возвращает "No project", то
Horizon `/project/instances/` не сможет показать ВМ в project scope.

## Source Horizon после cutover

Старая source Horizon может продолжать показывать ВМ, потому что source Nova DB
metadata еще не очищена. Это stale/control-plane metadata, а не доказательство,
что source compute agent все еще управляет ВМ.

Опасность в другом: пока source metadata сохранена для rollback, в старой
консоли нельзя выполнять actions над этой ВМ:

- delete;
- reboot;
- stop/start;
- detach volume;
- migrate/live migrate;
- rebuild/rescue;
- изменение security groups/ports.

До закрытия rollback window source-side запись должна быть либо явно
quarantined/read-only организационно, либо защищена отдельной процедурой
source quarantine.

## Стратегии исправления target Horizon visibility

Нужно выбрать одну стратегию до production cutover.

### Вариант A: сохранить source project UUID в target

Создать или импортировать в target Keystone project/user/role assignments так,
чтобы `project_id` ВМ существовал в target.

Подходит, если tenant identity должна переехать как есть. Нельзя слепо
импортировать project с тем же `name/domain`, если в target уже есть project с
таким именем: например, в lab оба кластера имеют project `admin`, но с разными
UUID. В таком случае нужен новый target project name или заранее согласованная
identity migration.

### Вариант B: нормализовать resources на существующий target project

Изменить imported metadata на target project/user UUID:

- Nova: `instances.project_id`, `instances.user_id`,
  `instance_mappings.project_id`, `request_specs.spec`;
- Neutron: `networks.project_id`, `subnets.project_id`, `ports.project_id`,
  `securitygroups.project_id`, `securitygrouprules.project_id`;
- Cinder: `volumes.project_id`, `volumes.user_id` и связанные attachment
  records, если schema это хранит;
- service-specific quotas/usages, если они импортировались.

Для lab это обычно удобнее: ВМ появится в target `admin` project. Но такая
нормализация должна быть явной, идемпотентной и покрывать все сервисы, иначе
получится mixed-tenant состояние.

В текущем наборе playbook-ов этот вариант оформлен как
`04l-normalize-target-project-visibility.yml`. По умолчанию он работает в
report-only режиме и меняет target DB только с явным флагом
`target_project_visibility_normalize_apply=true`.

## Правило для метода

Re-home считается принятой target control plane только после двух проверок:

- admin/API-level видимость: `server show` и `server list --all-projects`
  показывают ВМ на target;
- project-level видимость: `project show <server.project_id>` проходит, а
  Horizon user имеет role assignment на этот project.

Если project-level visibility не готова, это нужно фиксировать как отдельный
post-cutover gap. Runtime ВМ при этом может быть корректным, но операторская
видимость в Horizon будет неполной.
