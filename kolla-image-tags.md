# Теги образов Kolla при re-home compute-хоста

Этот документ дополняет общий runbook re-home для окружений на Kolla-Ansible.

Если CP-A и CP-B используют разные теги container images, re-home compute-хост
должен переключить активные OpenStack agent containers на теги целевого control
plane во время окна cutover. Смена tag не является финальной cleanup-операцией.
После burn-in остается только удалить старые source images/containers.

## Главный принцип

Нельзя оставлять хост в смешанном состоянии, где CP-B уже считает compute-хост
своим, но на самом хосте продолжают работать агенты с source-tag. Во время
cutover нужно остановить source containers Nova/network agents и запустить
target-tag containers с конфигурацией CP-B.

Безопасная последовательность:

1. До cutover скачать target images на re-home host и сохранить digests.
2. До cutover подготовить target Kolla configuration, но не перезапускать
   активные service containers.
3. Во время cutover остановить source control-plane agent containers.
4. Во время cutover сначала запустить target-tag network agent containers.
5. Во время cutover запустить target-tag `nova_compute` в safe-mode.
6. После validation и burn-in удалить старые source-tag containers/images.

## Порядок фаз

Для развертываний Kolla используем такой порядок:

```text
Фаза 0   Предварительные проверки
Фаза 1   Заморозка source scheduling
Фаза 2   Backup и инвентаризация
Фаза 3   Подготовка schema и metadata на CP-B
Фаза 4   Предварительная загрузка target images на re-home host
Фаза 5   Подготовка target Kolla configs на re-home host
Фаза 5a  Остановить явно подтвержденные source-only non-runtime containers
Фаза 6   Cutover:
         остановить source Nova/network containers
         запустить target-tag network containers
         запустить target-tag nova_compute в safe-mode
Фаза 7   Перепривязка Neutron ports
Фаза 8   Placement heal и проверка Nova
Фаза 9   Включение target compute service
Фаза 10  Burn-in / стабилизация
Фаза 11  Очистка старых source images и containers
```

## Политика по компонентам

| Компонент | Когда менять tag | Комментарий |
| --- | --- | --- |
| `nova_compute` | Во время cutover | Должен стартовать уже с CP-B `transport_url`, database, Keystone, Placement и Neutron config. |
| `neutron_openvswitch_agent` или `ovn_controller` | Во время cutover, перед `nova_compute` | Сначала поднимаем target networking, потом Nova наблюдает VIF. |
| `openvswitch_vswitchd`, `openvswitch_db` | Лучше не менять в первом cutover, если версии совместимы | Dataplane критичен. Если перенос OVS/OVN base services нужен, делать отдельным окном после стабилизации. |
| `nova_libvirt` / libvirt container | Лучше не менять в первом cutover, если возможно | Running QEMU domains должны остаться нетронутыми. Libvirt обычно умеет переподключаться к QEMU, но для re-home это лишний риск. |
| `iscsid`, `multipathd`, RBD, storage helpers | Не менять во время cutover | Storage sessions должны оставаться стабильными. |
| `fluentd`, exporters, monitoring agents | После burn-in | Они не нужны для принятия ВМ target control plane. |

Принцип: во время re-home переключаем только OpenStack control-plane agents,
которые нужны для принятия хоста. Hypervisor dataplane не трогаем: running QEMU
processes, tap interfaces, OVS bridges, storage sessions и local instance disks
должны пережить cutover без изменений.

Source-only containers, которых нет в target cluster и которые не участвуют в
runtime ВМ, можно останавливать до cutover только через отдельный guarded шаг.
Такие containers должны быть явно перечислены оператором в allowlist, например
`source_only_containers`. После остановки каждого container нужно проверить, что
libvirt domains, VIF snapshot и доступность ВМ по сети не изменились. Если
проверка не прошла, container возвращается обратно и re-home останавливается.

## Первый старт в safe-mode

Контейнер target-tag `nova_compute` нужно запускать с защитными параметрами:

```ini
[DEFAULT]
enable_new_services = false
running_deleted_instance_action = noop
running_deleted_instance_poll_interval = 0
sync_power_state_interval = -1

[workarounds]
handle_virt_lifecycle_events = false
```

Эти настройки уменьшают риск, что первый target-side старт Nova отреагирует на
временную рассинхронизацию metadata изменением состояния гостевых ВМ. Safe-mode
снимается только после проверки Nova, Placement, Neutron и libvirt.

## Предварительная загрузка target images

Этот этап выполняется до cutover. Он не должен перезапускать работающие service
containers.

Пример логики:

```yaml
---
- name: Скачать target OpenStack images на re-home compute
  hosts: rehome_compute
  become: true
  vars:
    target_registry: "registry-b.example.net"
    target_tag: "epoxy-2025.1-cp-b"
    target_images:
      - "kolla/ubuntu-source-nova-compute"
      - "kolla/ubuntu-source-neutron-openvswitch-agent"
      - "kolla/ubuntu-source-ovn-controller"
  tasks:
    - name: Скачать target images
      ansible.builtin.command: >
        docker pull {{ target_registry }}/{{ item }}:{{ target_tag }}
      loop: "{{ target_images }}"
      changed_when: true

    - name: Сохранить digests скачанных images
      ansible.builtin.command: >
        docker image inspect {{ target_registry }}/{{ item }}:{{ target_tag }}
        --format '{{ "{{" }} .RepoDigests {{ "}}" }}'
      loop: "{{ target_images }}"
      register: image_digests
      changed_when: false

    - name: Записать отчет по image digests
      ansible.builtin.copy:
        dest: "/var/tmp/openstack-rehome/target-image-digests.txt"
        content: |
          {% for r in image_digests.results %}
          {{ r.item }}:
          {{ r.stdout }}
          {% endfor %}
```

В реальном workflow Kolla лучше использовать штатную механику Kolla-Ansible для
images/config там, где это безопасно: pull images и генерация config должны быть
отделены от cutover. Нельзя использовать full deploy или upgrade command, который
может пересоздать unrelated services во время re-home window.

## Переключение containers во время cutover

Логический порядок во время cutover:

1. Снять список running libvirt domain UUIDs.
2. Остановить source `nova_compute` и source network agent containers.
3. Убедиться, что набор libvirt domain UUIDs не изменился.
4. Запустить target-tag network containers с CP-B config.
5. Запустить target-tag `nova_compute` с CP-B config и safe-mode options.
6. Еще раз убедиться, что набор libvirt domain UUIDs не изменился.

Не нужно воспринимать это как готовый `docker run` recipe. Kolla containers имеют
сгенерированный `config.json`, bind mounts, labels, health checks, bootstrap
behavior, permissions и service-specific volume layout. Реализация должна
использовать ту же container model Kolla, что и развернутый кластер.

## Почему не полный `kolla-ansible upgrade --limit`

Нельзя использовать слепой full Kolla-Ansible upgrade с `--limit` как механизм
re-home для непустого compute-хоста. Kolla upgrade workflow скачивает images,
запускает prechecks, применяет database schema upgrades и пересоздает containers
как часть deployment-level upgrade. Re-home - другой процесс: CP-B schema и
metadata должны быть подготовлены заранее, а во время cutover должны
переключаться только control-plane agents выбранного compute-хоста.

Если CP-A и CP-B отличаются не только image tag policy внутри одной серии
OpenStack, сначала нужно выровнять CP-B и проверить совместимость DB schema, а
уже потом пытаться делать compute re-home.

## Очистка

Очистка - единственная image-tag операция после burn-in. Старые source-tag images
нужно сохранить до закрытия rollback window.

Пример защитной проверки:

```yaml
---
- name: Удалить старые source OpenStack images после успешного burn-in
  hosts: rehome_compute
  become: true
  vars:
    source_tag: "epoxy-2025.1-cp-a"
    cleanup_allowed: false
  tasks:
    - name: Запретить cleanup без явного разрешения
      ansible.builtin.assert:
        that:
          - cleanup_allowed | bool
        fail_msg: "Set cleanup_allowed=true only after burn-in and rollback window is closed"

    - name: Показать старые source images
      ansible.builtin.shell: >
        docker images --format '{{ "{{" }}.Repository{{ "}}" }}:{{ "{{" }}.Tag{{ "}}" }} {{ "{{" }}.ID{{ "}}" }}'
        | grep {{ source_tag | quote }} || true
      register: old_images
      changed_when: false

    - name: Сохранить список старых images перед cleanup
      ansible.builtin.copy:
        dest: /var/tmp/openstack-rehome/old-source-images-before-cleanup.txt
        content: "{{ old_images.stdout }}\n"
```
