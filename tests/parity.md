# Paridad con el aridi de 2019

Cada funcionalidad de `docs/MVP.md` (medición de 2019, commit `4ab279e`) con lo que la
cubre en el colector nuevo, o con el motivo por el que se abandona (`docs/CAMBIO.md`).

**Cómo se verifica:** cada fila nombra pruebas concretas. `tests/test_parity_doc.py`
comprueba que todas existen y que no falta ninguna funcionalidad de `MVP.md`, y
`tests/run.sh all` las ejecuta. **Ninguna fila se da por buena leyendo código.**

Formato de las pruebas: `módulo:Clase.método` para las de `unittest` (el módulo es un
fichero `tests/**/módulo.py`), y `run.sh collector` para las del script en todas las
imágenes (`tests/collector/test_script.sh`).

## Regresión final contra 2019

`tests/parity/` guarda lo que vieron el aridi de 2019 (sin modificar) y el colector nuevo
en el mismo contenedor, uno detrás de otro: Debian 12 y CentOS 7, cada uno en tres
variantes:

- **`plain`:** la imagen sin escenario y sin red;
- **`none`:** con el escenario del corpus (`tests/corpus/scenario.sh`) y sin red;
- **`bridge`:** con el escenario, en una red *bridge* interna (`eth0@ifN`, sin Internet).

La genera `tests/legacy/reference.sh` (en la historia de git desde la fase 4.2) y la
compara `tests/test_parity.py`: todo valor que 2019 daba bien sale igual en el nuevo.
Donde 2019 se equivocaba, la prueba lo dice y comprueba el valor correcto.

**Lo que la regresión observó en 2019 por primera vez** (además de lo de `MVP.md`):

- Con un `nameserver` IPv6 en `resolv.conf`, **2019 no escribe ningún informe**: la clave
  `None` del mapa de relaciones rompe la ordenación (`'<' not supported between instances
  of 'NoneType' and 'IPv4Address'`). `MVP.md` n.º 9 lo daba como observado solo en
  Python. Para tener algo que comparar, `reference.sh` quita esa línea antes de ejecutar
  los dos programas.
- **2019 cuenta como SUID los enlaces simbólicos** a un fichero SUID (`/usr/bin/sg` →
  `newgrp`; en CentOS 7, también el *helper* de dbus): por eso daba 9 SUID frente a 8 en
  Debian 12. El nuevo no sigue enlaces (`find ! -type l`).
- Con el escenario (un grupo con un miembro sin cuenta), **el apartado de usuarios se
  pierde también en Debian 12 y CentOS 7**, no solo en Alpine (n.º 12).
- Con `eth0@ifN`, **2019 pierde la red y además clasifica `127.0.0.1` como dirección
  remota** en la vista de infraestructura.

**Lo que la regresión hizo corregir en el nuevo:**

- **El *uptime*:** se recogía (`/proc/uptime`), pero no salía en la fotografía ni en el
  informe. Ahora está en `load.uptime_seconds` y en la vista de texto.
- **Una versión tomada por IP:** `anaconda 21.48.22.159-1` (registros de CentOS 7). 2019
  descartaba una IPv4 seguida de `-`; el nuevo no podía distinguir ese carácter. Ahora el
  script clasifica el guion (`h`) y el analizador lo trata como número de versión.

## Funcionalidades que funcionaban (MVP.md 1-10)

| N.º | Funcionalidad de 2019 | Qué la cubre ahora | Pruebas |
|---|---|---|---|
| 1 | Ejecución local completa (*entregada con limitaciones*) | Script POSIX `sh` sin dependencias (`collector/aridi-collect.sh`) más el núcleo (`aridi report`). Termina con 0 en las 10 imágenes, con cada shell, como root y como uid 65534, sin escribir nada y sin terminal. No depende del directorio de trabajo (`services.csv` va dentro del paquete). **Cambio:** pasa a ser de dos pasos, e interpretar exige Python 3.12 en algún equipo (`CAMBIO.md`, *Qué se pierde*). | `run.sh collector`; `test_cli:CliTest.test_report_summary_and_detail`; `test_cli:CliTest.test_complete_exit_code`; `test_ports:TableTest.test_names_used_by_the_connections` |
| 2 | Distribución, kernel y libc (*con limitaciones*) | Área `system`. Alpine sale con versión; CentOS 6 sin `os-release`, por sus ficheros de *release*. | `test_system:CorpusTest.test_matches_facts_in_every_sample`; `test_system:CorpusTest.test_alpine_shows_point_release`; `test_system:CorpusTest.test_centos6_without_os_release`; `test_system:LegacyRegressionTest.test_same_as_legacy`; `test_parity:ParityTest.test_kernel`; `test_parity:ParityTest.test_distribution`; `test_parity:ParityTest.test_libc` |
| 3 | Paquetes de Debian y Red Hat (*con limitaciones*) | Área `packages`: dpkg, rpm, apk, pacman y zypper (rpm), con la versión binaria y aparte las claves `gpg-pubkey`. | `test_packages:CorpusTest.test_exactly_the_packages_of_facts`; `test_packages:CorpusTest.test_debian_binary_version`; `test_packages:LegacyRegressionTest.test_counts_same_as_legacy`; `test_parity:ParityTest.test_packages_same_names`; `test_parity:ParityTest.test_rpm_versions`; `test_parity:ParityTest.test_dpkg_versions_where_2019_was_right` |
| 4 | Memoria, CPU en uso, carga y *uptime* (*entregada*) | Área `load` (memoria, *swap*, carga, CPU desde el arranque y en un segundo, *uptime*), más el total de `hardware`. | `test_volatile:LoadTest.test_every_sample`; `test_volatile:LoadTest.test_memory_like_legacy`; `test_parity:ParityTest.test_ram_and_swap`; `test_parity:ParityTest.test_total_memory_in_mb`; `test_parity:ParityTest.test_uptime`; `test_text:TextTest.test_human_duration` |
| 5 | Permisos peligrosos → `aridi.badfiles` (*con limitaciones*) | Área `permissions`, sin preguntar, solo en el sistema de ficheros raíz (`-xdev`) y sin escribir ningún fichero. Mismos ficheros que 2019 salvo los enlaces simbólicos que 2019 contaba de más. | `test_permissions:CorpusTest.test_same_files_as_find_in_facts`; `test_permissions:CorpusTest.test_scenario_files_appear`; `test_permissions:LegacyRegressionTest.test_suid_count_against_legacy`; `test_parity:ParityTest.test_permissions` |
| 6 | Identidad y *banners* (*con limitaciones*) | Área `identity`. El dominio es el dominio DNS, nunca el hostname; los *banners* se neutralizan en la vista. | `test_identity:CorpusTest.test_hostname_and_banner_in_every_sample`; `test_identity:CorpusTest.test_banner_neutralized_in_the_text_view`; `test_identity:LegacyRegressionTest.test_same_hostname_as_legacy`; `test_identity:SyntheticTest.test_domain_is_not_the_hostname`; `test_parity:ParityTest.test_hostname_hostid_and_banners` |
| 7 | IPs en `/etc` y `/var/log` (*carving*) (*con limitaciones*) | Área `carving`: IPv4 e IPv6, `/etc`, `/var/log` y journal (recuentos), sin enviar el texto de las líneas ni leer ficheros protegidos de `/etc`. **Se abandona** la resolución DNS de los FQDN (`CAMBIO.md`; aparcada en `FUTURE.md`): los nombres se listan, no se resuelven. | `test_carving:CarvingCorpusTest.test_scenario_addresses_in_every_sample`; `test_carving:CarvingCorpusTest.test_protected_files_are_never_read`; `test_carving:CarvingCorpusTest.test_no_line_text_leaves_the_machine`; `test_carving:CarvingLegacyTest.test_debian12_same_ipv4_in_etc_as_legacy`; `test_carving:CarvingSyntheticTest.test_exclusions`; `test_carving:CarvingSyntheticTest.test_journal_counts`; `test_parity:ParityTest.test_carving` |
| 8 | Escaneo de puertos TCP desde la máquina (*con limitaciones*) | **Se abandona en la máquina** (`CAMBIO.md`): el colector es pasivo. El escaneo pasa al central, acotado a redes autorizadas (fase 7 de `TODO.md`; **todavía no existe**). El papel `scan_open_port` está reservado y solo se prueba con datos sintéticos. | `test_relations:RelationsTest.test_every_role_comes_from_a_sample_or_is_tested_elsewhere` |
| 9 | Informes resumido, detallado, completo y de infraestructura; fichero y log (*con limitaciones*) | `aridi report` (resumen y `--detail`), `aridi interpret` (fotografía JSON), vista de infraestructura, «What could not be seen», ficheros nuevos con modo 0600 sin sobrescribir ni seguir enlaces, y `logging` por stderr (`-v`). El mapa nunca tiene claves nulas: las IPs son objetos `ipaddress`. | `test_text:TextTest.test_golden_corpus_report`; `test_text:TextTest.test_every_area_and_the_gaps_section`; `test_cli:CliTest.test_interpret_to_new_file_0600`; `test_cli:CliTest.test_interpret_never_overwrites_nor_follows_symlinks`; `test_cli:CliTest.test_verbose_logging`; `test_relations:RelationsTest.test_infrastructure_view_like_legacy_oi`; `test_network:CorpusTest.test_ipv6_dns_server_is_not_null`; `test_parity:ParityTest.test_infrastructure` |
| 10 | Ejecución sin privilegios, en una terminal (*con limitaciones*) | El script termina con 0 como uid 65534, sin preguntar, y marca `denied` lo que no puede leer; el núcleo lo declara como hueco. | `run.sh collector`; `test_users:SyntheticTest.test_shadow_denied`; `test_permissions:SyntheticTest.test_search_not_possible_is_a_gap` |

## Funcionalidades a medias (MVP.md 11-21)

| N.º | Fallo de 2019 | Qué lo cubre ahora | Pruebas |
|---|---|---|---|
| 11 | CPU sin fabricante, modelo ni núcleos en arm64 | Área `hardware`: `cpuinfo` de ARM (implementador y pieza) y topología de `/sys`; x86_64 en la VM amd64. | `test_hardware:CorpusTest.test_matches_facts_in_every_sample`; `test_hardware:CorpusTest.test_arm64_has_cores_and_model`; `test_hardware:CorpusTest.test_x86_64_vm`; `test_hardware:SyntheticTest.test_arm_known_and_unknown_parts`; `test_parity:ParityTest.test_cpu_architecture_and_sockets` |
| 12 | `$y$` sin contraseña; un miembro sin cuenta anula usuarios; MD5 siempre 0 | Área `users`: estado y algoritmo de cada cuenta (el hash nunca sale de la máquina), miembros sin cuenta declarados aparte. | `test_users:CorpusTest.test_alice_has_a_password_never_empty`; `test_users:CorpusTest.test_locked_bob_and_orphan_member`; `test_users:CorpusTest.test_alpine_kvm_member_without_account`; `test_users:SyntheticTest.test_algorithm_counts_including_md5`; `test_users:CorpusTest.test_no_bundle_contains_a_full_hash`; `test_users:LegacyRegressionTest.test_debian12_users_and_groups_like_legacy` |
| 13 | `lsblk` actual rompe discos; % de carga cien veces menor | Áreas `storage` (`mountinfo`, `lsblk -P`, `df`) y `load` (carga de disco). | `test_storage:CorpusTest.test_current_lsblk_does_not_break`; `test_storage:CorpusTest.test_mounts_and_usage_match_facts`; `test_storage:CorpusTest.test_centos6_without_lsblk`; `test_storage:LegacyRegressionTest.test_centos7_same_disks_and_mounted_partition`; `test_volatile:LoadTest.test_disk_busy_percent`; `test_parity:ParityTest.test_disks` |
| 14 | Sin paquetes en Fedora (dnf5) ni Alpine (apk) | Área `packages` lee las bases de datos con `rpm`, `apk`, `pacman` y `dpkg-query`, no con el gestor de alto nivel. | `test_packages:CorpusTest.test_fedora_and_alpine_have_packages`; `test_packages:CorpusTest.test_exactly_the_packages_of_facts` |
| 15 | `eth0@ifN` anula toda la red; solo IPv4 | Área `network`: interfaces con su par, IPv4 e IPv6, rutas y DNS, con o sin `ip`. | `test_network:CorpusTest.test_bridge_eth0_at_ifn`; `test_network:SyntheticTest.test_ip_link_and_addr_with_peer_names`; `test_network:SyntheticTest.test_addresses_without_ip_tool`; `test_parity:ParityTest.test_hosts_interfaces_and_dns`; `test_parity:ParityTest.test_bridge_network_that_2019_lost` |
| 16 | Sin `tcp6`; UDP en escucha como `CLOSE`; un uid sin usuario anula las conexiones | Área `network` (sockets en escucha con su proceso) y `connections`. | `test_network:CorpusTest.test_scenario_listeners_tcp6_udp_and_local`; `test_network:CorpusTest.test_same_ports_as_ss`; `test_network:SyntheticTest.test_udp_connected_is_not_listening`; `test_network:SyntheticTest.test_socket_owner_with_unknown_uid_and_dead_pid`; `test_volatile:ConnectionsTest.test_ipv6_connection`; `test_parity:ParityTest.test_listening_sockets` |
| 17 | Procesos: se pierden con menos de 10 con CPU | Área `processes`, con cualquier número de procesos y uid sin cuenta. | `test_volatile:ProcessesTest.test_every_sample_any_number_of_processes`; `test_volatile:ProcessesTest.test_uid_without_account_shows_the_uid`; `test_volatile:ProcessesTest.test_long_lived_processes_like_ps` |
| 18 | Cortafuegos: solo `iptables -S`, sin nftables, ip6tables, firewalld ni ufw; FORWARD ignorado | Área `firewall`: nftables, iptables e ip6tables (*legacy*), firewalld y ufw, sin cargar módulos; sin permiso, hueco `denied` con el motivo. | `test_firewall_timesync:FirewallCorpusTest.test_scenario_nftables_rules_in_the_vms`; `test_firewall_timesync:FirewallCorpusTest.test_firewalld_in_rocky9`; `test_firewall_timesync:FirewallCorpusTest.test_container_without_cap_net_admin_says_why`; `test_firewall_timesync:FirewallCorpusTest.test_scenario_iptables_rules_in_centos_vms`; `test_firewall_timesync:FirewallSyntheticTest.test_iptables_save`; `test_firewall_timesync:FirewallSyntheticTest.test_ufw` |
| 19 | Servicios: `systemctl` sin systemd anula el apartado | Área `services`: systemd en marcha, SysV, OpenRC y runit; `systemctl` sin systemd recurre a los enlaces de `rc`. | `test_services:CorpusTest.test_area_never_fails`; `test_services:CorpusTest.test_vms_with_systemd_show_the_failed_service`; `test_services:CorpusTest.test_centos7_container_systemctl_without_systemd`; `test_services:CorpusTest.test_centos6_sysv`; `test_services:CorpusTest.test_centos6_vm_sysv_runlevels`; `test_services:CorpusTest.test_alpine_openrc` |
| 20 | USB: sin `lsusb` se pierde | Área `hardware` lee `/sys/bus/usb`; sin él, `na`, no error. | `test_hardware:SyntheticTest.test_usb_devices_and_hubs`; `test_hardware:SyntheticTest.test_without_sys_bus_usb_is_na_not_error` |
| 21 | Sin terminal se pierden apartados (7 `input()`) | Nada pregunta: el script lee de `/dev/null` en cada comando y se prueba por `sh -s`. | `run.sh collector` |

## Implementadas, sin verificar (MVP.md)

| Funcionalidad de 2019 | Qué la cubre ahora | Pruebas |
|---|---|---|
| Barrido ARP de la red local | **Se abandona** el barrido activo (`CAMBIO.md`). Lo sustituye la tabla de vecinos (pasiva, área `neighbours`). | `test_carving:NeighboursTest.test_every_sample`; `test_carving:NeighboursTest.test_vms_see_their_gateway`; `test_carving:NeighboursTest.test_synthetic_tables` |
| Servicios con systemd en marcha o con SysV | Ver n.º 19: VMs con systemd y CentOS 6 con SysV. | `test_services:CorpusTest.test_vms_with_systemd_show_the_failed_service`; `test_services:CorpusTest.test_centos6_sysv` |
| Sesiones activas, últimos accesos y accesos fallidos | Área `sessions` (`who`, `utmpdump`/`last`/`wtmpdb`, journal y `auth.log`/`secure`), con sesiones SSH reales en las VMs. | `test_volatile:SessionsTest.test_vm_sessions`; `test_volatile:SessionsTest.test_utmpdump_new_and_old_formats`; `test_volatile:SessionsTest.test_resolved_host_name_uses_the_record_address`; `test_volatile:SessionsTest.test_wtmpdb_is_preferred_to_last`; `test_volatile:SessionsTest.test_journal_syslog_relations_and_counts`; `test_volatile:ConnectionsTest.test_vm_ssh_session_is_an_incoming_connection`; `test_parity:ParityTest.test_failed_logins` |
| `iptables` con reglas, como root | Ver n.º 18. Reglas reales de `iptables` e `ip6tables` en las VMs de CentOS 7 y 6 (desde el 2026-10-17), además de la entrada sintética. | `test_firewall_timesync:FirewallCorpusTest.test_scenario_iptables_rules_in_centos_vms`; `test_firewall_timesync:FirewallSyntheticTest.test_iptables_save` |
| USB con `lsusb` | Ver n.º 20: se lee `/sys`, no hace falta `lsusb`. | `test_hardware:SyntheticTest.test_usb_devices_and_hubs` |
| Grafo de red con `graphviz` | **Se abandona** (`CAMBIO.md`): el mapa pasa a la web del central (**todavía no existe**). La fotografía lleva las relaciones para dibujarlo. | `test_relations:RelationsTest.test_corpus_map_has_v4_and_v6` |
| Paquetes con zypper o pacman | openSUSE Leap 15.6 y Arch en el corpus. | `test_packages:CorpusTest.test_exactly_the_packages_of_facts` |
| CPU en x86_64 | VM Debian 12 amd64 y datos sintéticos. | `test_hardware:CorpusTest.test_x86_64_vm`; `test_hardware:SyntheticTest.test_x86_cpuinfo_and_topology` |
| RHEL/CentOS 6 | CentOS 6 en el corpus: el script funciona con su `sh` (bash 4.1) y sin Python. | `run.sh collector`; `test_system:CorpusTest.test_centos6_without_os_release`; `test_services:CorpusTest.test_centos6_sysv` |

## Abandonadas en 2019 (MVP.md)

| Funcionalidad de 2019 | Qué la cubre ahora | Pruebas |
|---|---|---|
| Lectura de NTP | Área `timesync`: chrony, systemd-timesyncd y ntpd, configurados y en uso. | `test_firewall_timesync:TimesyncTest.test_chrony_in_el_vms`; `test_firewall_timesync:TimesyncTest.test_ntpd_in_centos6`; `test_firewall_timesync:TimesyncTest.test_timesyncd_in_debian`; `test_firewall_timesync:TimesyncTest.test_chronyc_and_ntpq_sources` |
| Permisos de `passwd`, `group`, `shadow` y `gshadow` (`dangerousperm()`) | `permissions.account_files`, con los modos recomendados. | `test_permissions:CorpusTest.test_account_files`; `test_permissions:SyntheticTest.test_account_files_recommended_modes` |
| Registro de vulnerabilidades (`view_vulns`) | **Se abandona** (`CAMBIO.md`): nunca funcionó y no hay un sustituto previsto en el colector. | — |
| Categorías de ficheros interesantes (0 a 18) | **Se abandonan:** cada fuente es una sección con nombre en el paquete (`docs/FORMATO.md`). | `test_interpret:InterpretTest.test_seventeen_areas_in_2019_order` |
| Uso como paquete importable | El núcleo es una librería (`aridi.bundle`, `aridi.interpret`) sin dependencias. | `test_interpret:InterpretTest.test_corpus_bundles_interpret_with_registry`; `test_core_isolation:CoreIsolationTest.test_only_stdlib_imports` |
