# Готовность Neutron и dataplane при re-home

Документ объединяет обнаруженный в lab OVS failure mode и требования нового
read-only live discovery. Одинаковый CIDR, MAC/fixed IP и API status `ACTIVE`
не доказывают, что target agent безопасно примет уже существующий tap/logical
port.

## Главный вывод

Для каждого selected Nova port должен быть закрыт полный required dependency
graph. Target должен иметь exact port/network UUID и единственный совместимый
segment tuple `(network_type, physical_network, segmentation_id)`, а runtime
evidence обязано соответствовать выбранному backend OVS или OVN. Любая
отсутствующая/противоречивая обязательная связь даёт `BLOCKED`/`UNKNOWN`.

Перед import/cutover выполняется
[`02b-discover-live-resource-graph.yml`](playbooks/02b-discover-live-resource-graph.yml).
Source/target live API и UUID-scoped DB queries — источник истины; dump может
быть только fixture.

## Замыкание основных зависимостей порта

Для каждого port собираются и сопоставляются API и DB facts:

- `ports`: UUID, network UUID, project, MAC, status, device owner/id,
  `binding_host_id`, vif type/details/profile и port security;
- fixed IP и `ipallocations`, network, subnet, allocation pools, host routes,
  DNS/DHCP/service types;
- `networksegments`, network type, physical network и segmentation ID;
- обязательные `ml2_port_bindings`, distributed bindings и все
  `ml2_port_binding_levels`;
- security group bindings/rules/RBAC и `allowed-address-pairs`;
- port DNS и `extra DHCP options`;
- active agents, host/segment mappings.

Наличие binding level не заменяет `ml2_port_bindings`. Каждый binding level
обязан ссылаться на существующий segment той же network. Missing/malformed
host, level, tuple или API/DB network mismatch блокирует readiness даже тогда,
когда одинаково ошибочные source/target значения формально совпадают.

## Полное замыкание дополнительных зависимостей

Optional schema family включается только при live schema capability и
фактической UUID-связи с выбранным root. После активации её required edge уже не
optional:

- QoS policy и port/network/FIP/router bindings;
- trunks и `subports`; parent раскрывает child ports рекурсивно, а выбранный
  child раскрывает parent и core dependencies;
- routers, router ports/routes, floating IP, router/FIP `port forwarding`;
- security rules с remote `address groups`, address group RBAC и address
  scopes;
- DNS, DHCP и service-type зависимости.

Unrelated tenant rows не сканируются и не попадают в graph. DB acquisition
сразу получает явные UUID filters; отфильтровать полный table dump постфактум
недопустимо. Bare mappings без Task 2 JSONL provenance отклоняются.

## Готовность OVS

Для OVS target API должен показать exact port, но этого недостаточно. Discovery
проверяет:

```bash
openstack port show <port_uuid>
```

Команда полезна как API-диагностика, но сама по себе не доказывает
RPC/agent-visible binding и безопасный dataplane sync.

- `ml2_port_bindings.host = rehome_host` и корректный `vif_type`;
- все `ml2_port_binding_levels` и unique compatible segment;
- target OVS agent registration/capability;
- exact пары bridge и port/interface для выбранного Neutron port;
- source и target runtime evidence независимо; нельзя собрать совпадение из
  bridge одного node kind и interface другого.

Missing source OVS evidence — `UNKNOWN`; target blocker/unknown propagates в
итог. Unsupported network backend не превращается в пустой PASS.

## Готовность OVN

Для OVN требуются source и target logical port binding, правильный chassis и
связь port UUID → logical port → chassis. Наличие chassis где-либо в target не
компенсирует отсутствующий source binding. Malformed/missing logical port,
chassis или edge даёт `UNKNOWN/BLOCKED`.

## Наблюдение в lab: `Device <port_uuid> is not bound`

При первом запуске target `neutron_openvswitch_agent`:

1. Source Nova/network agents были остановлены.
2. Target API показывал VM port как `ACTIVE` с прежними UUID, MAC, fixed IP и
   host binding.
3. В target DB не хватало согласованного `ml2_port_binding_levels`.
4. Agent получил `Device <port_uuid> is not bound` / `binding failed`, затем
   очистил stale flows в `br-int`, `br-ex`, `br-tun`.
5. QEMU domain/tap остались, но ping пропал; rollback source agent восстановил
   связь.

OVS agent при full sync активно сверяет local ports с plugin и
перепрограммирует flows/security filters. Поэтому API-visible и
RPC/agent-visible binding — разные доказательства.

## Связь discovery и legacy normalization

Live discovery ничего не исправляет. Он должен завершиться до
`04j-ensure-neutron-ml2-binding-levels.yml` и показать, какие dependencies
отсутствуют. Legacy `04j` выполняется после reviewed target DB import и только
с отдельным apply flag. `07-rebind-network-ports.yml` или ручной
`openstack port set --host` не заменяет `04j` и не заменяет
binding-level/segment/runtime proof.

Перед `06-cutover-compute.yml` нужны одновременно:

- target graph без Neutron `UNKNOWN/BLOCKED`;
- exact API/DB UUID identity и полный required closure;
- compatible unique segment tuples;
- корректный OVS/OVN runtime evidence;
- runtime guard с domain/interface snapshot и reachability;
- отсутствие `not bound`/binding failure в controlled validation.

## Действие при потере dataplane

Cutover не должен продолжать запуск target `nova_compute`, если после target
network agent пропал ping или появились binding errors:

1. остановить target network agent по утверждённой rollback процедуре;
2. вернуть source Nova/network configs и agents;
3. подтвердить неизменность domain/interfaces и восстановление ping;
4. исправить target dependency/segment/runtime readiness;
5. выполнить новый live discovery с новым `run-id`;
6. повторять cutover только после rc `0` и review.

Masakari/DRS не участвуют в этой проверке. Итоговые contracts/exit codes
описаны в [документе об артефактах](docs/live-discovery-artifacts-ru.md), а
общий поток — в [схеме live discovery](docs/live-discovery-data-flow-ru.md).
Текущая автоматическая проверка использует fixture/unit tests и Ansible
`syntax-check`; она не заявляет о выполненном production/live cutover.
