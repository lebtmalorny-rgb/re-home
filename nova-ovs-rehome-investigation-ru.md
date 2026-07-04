# Исследование nova_libvirt и OVS после re-home

Дата исследования: 2026-07-04.

## Текущее состояние

Re-home host: `os1-compute-02.example.local` / `192.168.10.74`.

Контейнеры control-plane agents уже работают из target Ubuntu images:

- `nova_compute`: `quay.io/openstack.kolla/nova-compute:2025.1-ubuntu-noble`;
- `neutron_openvswitch_agent`:
  `quay.io/openstack.kolla/neutron-openvswitch-agent:2025.1-ubuntu-noble`;
- `fluentd`: `quay.io/openstack.kolla/fluentd:2025.1-ubuntu-noble`.
- `cron`: `quay.io/openstack.kolla/cron:2025.1-ubuntu-noble`;
- `kolla_toolbox`: `quay.io/openstack.kolla/kolla-toolbox:2025.1-ubuntu-noble`;
- `nova_ssh`: `quay.io/openstack.kolla/nova-ssh:2025.1-ubuntu-noble`.

Контейнеры hypervisor/dataplane оставлены на source Rocky images:

- `nova_libvirt`: `quay.io/openstack.kolla/nova-libvirt:2025.1-rocky-9`;
- `openvswitch_db`:
  `quay.io/openstack.kolla/openvswitch-db-server:2025.1-rocky-9`;
- `openvswitch_vswitchd`:
  `quay.io/openstack.kolla/openvswitch-vswitchd:2025.1-rocky-9`.

ВМ `instance-00000004` продолжает работать, `virsh list --all` через текущий
`nova_libvirt` показывает домен `running`, ping до `192.168.10.100` проходит.

## nova_ssh и mount entries

При переключении `nova_ssh` на target Ubuntu image контейнер сначала упирался в
Docker/runc mount failure:

```text
no space left on device
```

Это не было связано с disk space или inode. На re-home host в
`/proc/self/mountinfo` обнаружены duplicate mount entries:

```text
8192 /var/lib/nova/mnt/d84d85231d8c1d1c606822903d890d99
8191 /var/lib/nova/mnt
```

`mount entries` - это записи kernel mount table, видимые в mount namespace
процесса. Их большое количество замедляет Docker `run`/`exec` и может ломать
подготовку bind mounts. Reference `nova_ssh` содержит shared bind:

```text
/var/lib/nova/mnt:/var/lib/nova/mnt:shared
```

На host с таким leak этот bind для `nova_ssh` небезопасен. В lab он исключен
через `target_host_container_reconcile_drop_mount_destinations` только для
`nova_ssh`. После этого `nova_ssh` работает в target Ubuntu image и Docker
health стал `healthy`.

Root cause leak оказался не в `nova_ssh`. `nova_ssh` первым показал симптом,
потому что Docker/runc не смог снова примонтировать `/var/lib/nova/mnt`.
Причина была в cutover: после остановки Docker container `nova_compute`
systemd unit `kolla-nova_compute-container.service` продолжил перезапускать
source `nova_compute`. В journal виден restart loop с `13:12:39` до
`13:17:54`, restart counter `1..19`. Каждый старт шел с Kolla volume:

```text
/var/lib/nova/mnt:/var/lib/nova/mnt:shared
```

Так как под этим shared mount уже был Cinder NFS volume, propagation размножил
mount tree до бинарной структуры:

```text
8191 /var/lib/nova/mnt
8192 /var/lib/nova/mnt/d84d85231d8c1d1c606822903d890d99
```

В `06-cutover-compute.yml` добавлена защита: до `docker stop` playbook
останавливает `kolla-<container>-container.service` для source runtime
containers, а preflight читает `/proc/1/mountinfo` и отказывается выполнять
cutover, если entries под `/var/lib/nova/mnt` уже выше порога.

Сам существующий mount leak не устранен этим изменением. Это отдельная
remediation-задача: его нельзя чистить слепым `umount -l`, потому что такой
unmount может временно убрать management path к Cinder NFS volume file, даже
если running QEMU продолжает держать ВМ живой.

## nova_libvirt

Docker spec у source Rocky `nova_libvirt` и target Ubuntu `nova_libvirt` почти
одинаковый: `host` network, `pid=host`, `privileged=true`, те же Kolla volumes
`libvirtd`, `nova_compute`, `nova_libvirt_qemu`, `/run`, `/dev`, `/lib/modules`.
Проблема не в Docker mounts.

Критичная разница в содержимом image:

- Rocky `nova_libvirt`: libvirt `11.10.0`, QEMU `10.1.0`;
- Ubuntu `nova_libvirt`: libvirt `10.0.0`, QEMU `8.2.2`.
- Rocky 10 candidate `quay.io/openstack.kolla/nova-libvirt:2025.1-rocky-10`:
  libvirt `11.10.0`, QEMU `10.1.0`.

Текущая ВМ запущена с machine type:

```text
pc-i440fx-rhel7.6.0
```

Rocky QEMU image поддерживает этот RHEL-specific machine type. Ubuntu target
image его не показывает в `qemu-system-x86_64 -machine help`.

Rocky 10 candidate выглядит лучше Ubuntu по версиям libvirt/QEMU, но для этой
ВМ он тоже не является безопасной live-заменой: в его `-machine help` нет
`pc-i440fx-rhel7.6.0`. Там есть новые RHEL machine types, например
`pc-i440fx-rhel10.0.0`, но это не помогает уже запущенному домену с RHEL 7.6
machine type.

Практический тест подтвердил риск: при запуске target Ubuntu `nova_libvirt` на
live host runtime guard не увидел running domain даже после retry. Playbook
автоматически откатил `nova_libvirt` на Rocky image, после чего домен снова был
виден и ping до ВМ сохранился.

В период попытки в `nova-compute.log` также было:

```text
libvirt.libvirtError: authentication failed
nova.exception.HypervisorUnavailable
```

После rollback связь Nova с libvirt восстановилась.

Вывод: live-переключение `nova_libvirt` с Rocky на Ubuntu для уже запущенной ВМ
нельзя считать безопасным. Это не просто задержка старта libvirt. Есть
несовместимость уровня hypervisor userspace: target image содержит более старые
libvirt/QEMU и не поддерживает machine type уже запущенного домена.

Для проверки любых новых candidate images в `12-reconcile-target-host-containers.yml`
добавлен preflight `nova_libvirt`:

- собирает machine types реально запущенных libvirt domains;
- собирает текущие версии libvirt и QEMU из работающего `nova_libvirt`;
- запускает target image одноразово через `docker run --rm --entrypoint /bin/bash`;
- собирает версии libvirt/QEMU target image и `qemu -machine help`;
- падает до `apply`, если target image не поддерживает machine type текущих
  доменов или делает downgrade libvirt/QEMU.

Rocky 10 можно проверять без изменения inventory так:

```bash
ansible-playbook -i inventory/lab-os1-to-os2.yml \
  playbooks/12-reconcile-target-host-containers.yml \
  -e target_host_container_reconcile_include_libvirt=true \
  -e target_host_container_reconcile_nova_libvirt_image=quay.io/openstack.kolla/nova-libvirt:2025.1-rocky-10
```

Ожидаемый результат для текущей ВМ: preflight должен остановиться до
пересоздания контейнера и показать отсутствующий machine type
`pc-i440fx-rhel7.6.0`.

Если preflight чистый для другого candidate image, рабочий путь такой:

1. Зафиксировать candidate image и digest, который прошел report-only
   проверку. Между проверкой и apply нельзя незаметно менять tag.
2. Убедиться, что compatibility report показывает пустой список missing
   machine types и не фиксирует downgrade libvirt/QEMU относительно текущего
   `nova_libvirt`.
3. Запустить apply только для `nova_libvirt`:

   ```bash
   ansible-playbook -i inventory/lab-os1-to-os2.yml \
     playbooks/12-reconcile-target-host-containers.yml \
     -e target_host_container_reconcile_apply=true \
     -e target_host_container_reconcile_include_libvirt=true \
     -e target_host_container_reconcile_nova_libvirt_image=<candidate-image>
   ```

4. Принять переключение только после `runtime guard`: running domain set не
   изменился, libvirt domain interfaces не изменились, внешний network probe
   до ВМ проходит.
5. Если новый `nova_libvirt` не видит уже running domains, если `virsh`
   недоступен, если Nova получает `HypervisorUnavailable` или если ВМ теряет
   сеть, это не частичный успех. Нужно оставить rollback на предыдущий
   `nova_libvirt` и не продолжать cleanup старого image.

Этот шаг не часть первичного cutover. Он допустим только как отдельное окно
после burn-in, когда уже доказано, что re-home принят target control plane и
что сама ВМ переживает штатные runtime guard проверки.

## OVS

Docker spec source/target OVS containers совпадает по ключевым параметрам:

- `openvswitch_db`: host network, non-privileged, volume `openvswitch_db`,
  `/run/openvswitch`;
- `openvswitch_vswitchd`: host network, privileged, `/run/openvswitch`.

Версии:

- source Rocky OVS: `3.4.4-99.el9s`;
- target Ubuntu OVS: `3.5.1`;
- DB schema на обоих: `8.8.0`.

На re-home host есть активный dataplane:

- bridges: `br-int`, `br-ex`, `br-tun`;
- VM port: `qvo0333a723-8f` на `br-int`;
- flow entries есть на `br-int`, `br-ex`, `br-tun`;
- controller connections к local OVS agent активны.

Report-only запуск `12-reconcile-target-host-containers.yml` с
`target_host_container_reconcile_include_ovs=true` успешно скачал target OVS
images и подтвердил runtime guard. Контейнеры при этом не менялись.

При первом apply strict OVS guard остановил переключение после
`openvswitch_db`: сразу после restart snapshot OVS ports был пустой. Playbook
откатил `openvswitch_db` на Rocky image, после rollback OVS ports и ping
восстановились. Внешний ping-monitor при этом показал `300/300`, `0% packet
loss`, то есть dataplane не прерывался, но management snapshot был еще не
готов.

После этого runtime guard был усилен:

- `runtime_guard_ovs_vsctl_command` указывает на containerized
  `docker exec openvswitch_db ovs-vsctl`;
- OVS port snapshot делает retry и требует непустой результат перед diff.

Повторный apply прошел успешно:

- `openvswitch_db` переключен на
  `quay.io/openstack.kolla/openvswitch-db-server:2025.1-ubuntu-noble`;
- `openvswitch_vswitchd` переключен на
  `quay.io/openstack.kolla/openvswitch-vswitchd:2025.1-ubuntu-noble`;
- `ovs-vsctl` и `ovs-vswitchd` показывают Open vSwitch `3.5.1`;
- DB schema осталась `8.8.0`;
- controllers на `br-int`, `br-ex`, `br-tun` подключены;
- VM port `qvo0333a723-8f` остался на `br-int`;
- ping-monitor во время второго apply: `300/300`, `0% packet loss`.

Старые Rocky OVS containers оставлены как stopped backup containers:

- `openvswitch_db_rehome_backup_<timestamp>`;
- `openvswitch_vswitchd_rehome_backup_<timestamp>`.

Вывод: OVS выглядит более совместимым, чем `nova_libvirt`, потому что DB schema
совпадает. Но OVS является dataplane. Перезапуск `openvswitch_db` или
`openvswitch_vswitchd` может дать краткий разрыв контроллеров, flows или port
processing, поэтому strict continuity ВМ не гарантируется.

## Рекомендация

Для текущего re-home результата:

1. Оставить `nova_libvirt` на Rocky image до остановки/пересоздания ВМ или до
   отдельного host-level upgrade пути, который не делает downgrade libvirt/QEMU.
2. OVS можно переключать отдельным guarded шагом, но только с retry-enabled
   strict OVS runtime guard и внешним ping-monitor. В lab такой прогон прошел
   без packet loss.
3. Порядок OVS: сначала `openvswitch_db`, затем `openvswitch_vswitchd`.
   Если OVS port snapshot не восстанавливается, playbook должен откатывать
   container из backup.
4. Для production runbook считать `nova_compute`/Neutron agents control-plane
   agents, а `nova_libvirt`/OVS - hypervisor/dataplane layer, который не обязан
   менять image tag в том же live cutover.
