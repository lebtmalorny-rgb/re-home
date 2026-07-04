# Lab topology: re-home os1-compute-02 из os1 в os2

Документ фиксирует лабораторный стенд, на котором проверялся re-home compute
host с уже запущенной ВМ. Цель схемы - быстро показать, где запускается
Ansible, какие hosts указаны в inventory, какой host переносится, где остается
ВМ и какая сеть используется для проверки непрерывности.

## Узлы и роли

| Inventory group | Host | IP | Роль |
| --- | --- | --- | --- |
| Ansible runner | локальная машина оператора | не фиксируется | Запускает `ansible-playbook` из этого репозитория |
| `source_control` | `os1-ctrl-01` | `192.168.10.70` | Control plane CP-A/source, VIP `192.168.10.90` |
| `target_control` | `os2-ctrl-01` | `192.168.10.75` | Control plane CP-B/target, VIP `192.168.10.91` |
| `target_reference_compute` | `os2-compute-01` | `192.168.10.78` | Эталонный compute CP-B, источник target Kolla configs |
| `rehome_compute` | `os1-compute-02` | `192.168.10.74` | Compute host, который переносится между control planes |
| VM | `os1-vm-100` | `192.168.10.100` | ВМ, которая должна оставаться running и доступной по сети |
| NFS/Cinder | NFS server | `192.168.10.80` | Backend Cinder volume для ВМ |

## Состояние до re-home

```mermaid
flowchart LR
    runner["Ansible runner\nlocal workstation\nansible-playbook"]:::runner

    subgraph net["Provider / lab network 192.168.10.0/24"]
      subgraph os1["CP-A source: os1 Rocky/Kolla\nVIP 192.168.10.90"]
        os1ctrl["source_control\nos1-ctrl-01\n192.168.10.70"]
        os1compute["rehome_compute\nos1-compute-02\n192.168.10.74\nsource nova_compute\nsource neutron/OVS agent\nsource nova_libvirt"]
        vm["VM os1-vm-100\n192.168.10.100\nUUID d6015a8d-e41f-4c8f-8765-b73c83f7f159"]
      end

      subgraph os2["CP-B target: os2 Ubuntu/Kolla\nVIP 192.168.10.91"]
        os2ctrl["target_control\nos2-ctrl-01\n192.168.10.75"]
        os2ref["target_reference_compute\nos2-compute-01\n192.168.10.78\nsource for target configs"]
      end

      nfs["NFS/Cinder backend\n192.168.10.80\n/srv/openstack-nfs/os1/cinder"]
    end

    runner -->|SSH / Ansible| os1ctrl
    runner -->|SSH / Ansible| os2ctrl
    runner -->|SSH / Ansible| os2ref
    runner -->|SSH / Ansible| os1compute
    os1ctrl -->|owns services and metadata| os1compute
    os1compute -->|libvirt/QEMU domain| vm
    vm -->|volume file| nfs

    classDef runner fill:#f4f4f4,stroke:#555,color:#111;
```

До cutover host `os1-compute-02` полностью принадлежит source control plane:
source Nova знает compute service, source Neutron обслуживает port binding, а
source Kolla containers задают runtime. Target control plane существует рядом,
но еще не управляет этим host.

## Состояние после re-home

```mermaid
flowchart LR
    runner["Ansible runner\nlocal workstation\nansible-playbook"]:::runner

    subgraph net["Provider / lab network 192.168.10.0/24"]
      subgraph os1["CP-A source: os1 Rocky/Kolla\nVIP 192.168.10.90"]
        os1ctrl["source_control\nos1-ctrl-01\n192.168.10.70\nsource compute disabled/quarantined"]
      end

      subgraph os2["CP-B target: os2 Ubuntu/Kolla\nVIP 192.168.10.91"]
        os2ctrl["target_control\nos2-ctrl-01\n192.168.10.75\ntarget metadata/API owner"]
        os2ref["target_reference_compute\nos2-compute-01\n192.168.10.78\nreference configs"]
      end

      os1compute["rehome_compute\nos1-compute-02\n192.168.10.74\ntarget nova_compute\ntarget neutron_openvswitch_agent\ntarget OVS containers\nnova_libvirt left on Rocky image"]
      vm["VM os1-vm-100\n192.168.10.100\nmust stay reachable"]
      nfs["NFS/Cinder backend\n192.168.10.80\nexisting volume path remains mounted"]
    end

    runner -->|SSH / Ansible| os1ctrl
    runner -->|SSH / Ansible| os2ctrl
    runner -->|SSH / Ansible| os1compute
    os2ctrl -->|owns Nova/Neutron/Cinder metadata| os1compute
    os1compute -->|same running QEMU domain| vm
    vm -->|same volume file| nfs

    classDef runner fill:#f4f4f4,stroke:#555,color:#111;
```

После cutover control-plane agents на `os1-compute-02` работают с target
конфигурацией и target image tags:

- `nova_compute`;
- `neutron_openvswitch_agent`;
- `openvswitch_db` и `openvswitch_vswitchd`;
- support containers `fluentd`, `cron`, `kolla_toolbox`, `nova_ssh`.

`nova_libvirt` в lab оставлен на Rocky image, потому что target Ubuntu image и
Rocky 10 candidate не поддержали machine type уже запущенной ВМ
`pc-i440fx-rhel7.6.0`. Это допустимое промежуточное состояние: ВМ продолжает
работать, а смена `nova_libvirt` вынесена в отдельный guarded шаг после
прохождения machine type preflight.

## Проверочная сеть ВМ

В обоих кластерах создана одинаковая provider/self-service сеть без DHCP для
проверки непрерывности адреса ВМ:

- адрес ВМ: `192.168.10.100`;
- проверочный диапазон: `192.168.10.100-192.168.10.110`;
- runtime guard проверяет reachability с `os2-ctrl-01`.

Важное ограничение: одинаковая адресация в target cluster не заменяет перенос
Neutron metadata. Для OVS нужно сохранить/нормализовать port UUID, binding
levels, MAC и fixed IP, иначе target Neutron может видеть port через API, но
dataplane агент получит "port is not bound".

## Что менять при переносе в другую инфраструктуру

В `inventory/lab-os1-to-os2.yml` заменить:

- IP и DNS names всех hosts;
- `source_vip`, `target_vip`;
- `rehome_host` и `hypervisor_hostname`;
- пути к локальным `clouds.yaml`, `passwords.yml`, artifacts;
- target image tags и base distro;
- `runtime_guard_probe_targets`;
- source-only services, которых нет в target cluster;
- Cinder/NFS metadata normalizations, если storage backend отличается.

Перед адаптацией inventory обязательно пройти `operator-inputs-ru.md`: там
перечислены входные секреты, clouds/configs, DB prerequisites и guardrails.
