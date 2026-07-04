# Поведение Neutron/OVS во время re-home

Этот документ фиксирует важный failure mode, обнаруженный в lab `os1 -> os2`.

## Главный вывод

Одинаковая сеть в source и target cluster, одинаковый CIDR и сохраненный
`fixed_ip` ВМ недостаточны для непрерывности сети.

Для OVS cutover порт считается готовым не тогда, когда `openstack port show`
показывает `ACTIVE`, а тогда, когда target Neutron plugin при RPC-запросе от
target `neutron_openvswitch_agent` возвращает этот port как bound на
`rehome_host`.

Для running VM нужно, чтобы target Neutron не только показывал через API:

- тот же port UUID;
- тот же MAC;
- тот же fixed IP;
- `binding_host_id = rehome_host`;
- `binding_vif_type = ovs`;
- `status = ACTIVE`.

Target Neutron OVS agent при первом sync должен получить от target Neutron
plugin полноценный bound-port. Если plugin отвечает, что port не bound, agent
считает локальный tap/OVS port невалидным и может почистить flows в `br-int`,
`br-ex` и `br-tun`. QEMU domain и tap-интерфейс при этом остаются живыми, но L2
dataplane ВМ падает.

Практическое правило: для OVS target DB должна содержать согласованный набор
строк `ports`, `ipallocations`, `ml2_port_bindings`,
`ml2_port_binding_levels`, `networksegments` и security group bindings для
каждого переносимого port UUID. В нашем lab отсутствие
`ml2_port_binding_levels` было достаточным условием для обрыва ping после
старта target OVS agent.

## Наблюдение в lab

Во время запуска target `neutron_openvswitch_agent` на re-home host:

1. Source `nova_compute` и source `neutron_openvswitch_agent` были остановлены.
2. Target `neutron_openvswitch_agent` стартовал с target config и target image.
3. Target Neutron API показывал port ВМ как `ACTIVE`, с сохраненным
   `192.168.10.100`, MAC и `binding_host_id`.
4. Но в логах target OVS agent появилась диагностическая картина:
   - `Device <port_uuid> is not bound`;
   - `Device <port_uuid> not defined on plugin or binding failed`;
   - затем `Cleaning stale br-int flows`, `Cleaning stale br-ex flows`,
     `Cleaning stale br-tun flows`.
5. После этого ping до ВМ пропал, хотя libvirt domain и `domiflist` не
   изменились.
6. После rollback на source `neutron_openvswitch_agent` связь восстановилась.

Практический смысл: target API-visible binding и target agent RPC-visible
binding - не одно и то же. Для cutover нужен второй вариант.

## Что именно нужно проверять

Перед реальным cutover недостаточно команды уровня API:

```bash
openstack port show <port_uuid>
```

Она полезна, но не доказывает, что OVS agent сможет безопасно принять port.
Нужно дополнительно проверить target ML2/runtime состояние:

- в target DB есть корректные `ml2_port_bindings` для port UUID и
  `host = rehome_host`;
- в target DB есть `ml2_port_binding_levels` для этого port UUID;
- `segment_id` в binding level указывает на target `networksegments` того же
  network UUID/provider mapping;
- target Neutron знает OVS agent на `rehome_host`;
- при тестовом старте target OVS agent он получает `Port <uuid> updated`, а не
  `Device <uuid> is not bound`;
- runtime guard проверяет не только libvirt domain/interface snapshot, но и
  ping/ARP после первого full sync OVS agent.

В текущем наборе playbook-ов эту проверку и нормализацию закрывает
`04j-ensure-neutron-ml2-binding-levels.yml`. Он должен выполняться после
target DB metadata import/normalization и до запуска `06-cutover-compute.yml`.
Report-only режим показывает, есть ли binding level, а применение требует
явного флага `target_neutron_ml2_binding_levels_apply=true`.

Важно: `07-rebind-network-ports.yml` или ручной `openstack port set
--host <rehome_host>` не заменяет `04j`. Rebind меняет API-visible binding, но
не доказывает, что ML2 binding level уже существует и что OVS agent получит
port как bound через RPC.

## Почему это влияет на непрерывность

OVS agent при full sync не является пассивным наблюдателем. Он сверяет локальные
OVS ports с ответами Neutron plugin и перепрограммирует flows/security filters.
Если target plugin не возвращает active binding для уже существующего tap, agent
может удалить flows, созданные source agent. В этом состоянии:

- IP внутри guest остается тем же;
- Neutron port UUID и MAC могут сохраняться в target API;
- QEMU продолжает работать;
- но внешний трафик до ВМ не идет.

Поэтому re-home должен сохранять не только адресацию, но и полноценную
Neutron/ML2 binding model.

## Правило для playbook-ов

`06-cutover-compute.yml` не должен продолжать запуск target `nova_compute`, если
после target network agent ВМ потеряла ping или logs показывают `not bound`.
Корректное действие в этом случае:

1. остановить target network agent;
2. вернуть source `/etc/kolla/neutron-openvswitch-agent` и source
   `/etc/kolla/nova-compute`;
3. запустить source `neutron_openvswitch_agent` и source `nova_compute`;
4. подтвердить восстановление ping;
5. исправить target ML2 metadata/binding до следующего cutover.

Повторный cutover без исправления target binding приведет к тому же обрыву
dataplane.

## Что нужно доработать в методе

Нужен отдельный pre-cutover Neutron binding guard, который работает до остановки
source agents и проверяет target DB/API consistency по каждому port UUID:

- `ports`;
- `ml2_port_bindings`;
- `ml2_port_binding_levels`;
- `networksegments`;
- `ipallocations`;
- security group bindings/rules;
- target OVS agent registration for `rehome_host`.

Для production-процедуры этот guard должен быть обязательным. В lab можно
продолжать только после того, как target OVS agent перестает писать
`Device <port_uuid> is not bound` и после старта target network agent ping до ВМ
остается непрерывным.
