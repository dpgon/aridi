# aridi: alcance entregado (estado a 2026-10-16)

> Este documento **mide** lo que aridi entrega hoy; no lo diseña. Lo decidido está en
> [`CAMBIO.md`](CAMBIO.md) y [`FORMATO.md`](FORMATO.md), el plan en [`TODO.md`](../TODO.md)
> y lo que vendrá después en [`FUTURE.md`](FUTURE.md). Cada afirmación dice si está
> **observada** (una prueba la ve pasar), **deducida** (de lo observado) o es una
> **suposición**.

## Qué es hoy

aridi es hoy un **colector local en dos pasos** para una máquina Linux:

1. **Recogida:** `collector/aridi-collect.sh`, un script POSIX `sh` sin dependencias, se
   ejecuta en la máquina (como root o sin privilegios), no escribe nada en disco y saca
   por stdout un **paquete en bruto** con 134 secciones de 17 áreas.
2. **Interpretación:** el núcleo en Python 3.12 (`src/aridi`, solo librería estándar)
   lee el paquete en cualquier equipo y produce una **fotografía** JSON
   (`aridi interpret`) o un informe de texto (`aridi report`), con un mapa de relaciones
   IPv4 e IPv6 y una lista de **lo que no se pudo ver**, con su estado y su motivo.

Ya le sirve a un administrador o a un auditor que quiera una **fotografía fiable y
legible de una máquina Linux**, de CentOS 6 a Fedora 44, incluidas Alpine, Arch y
openSUSE, y también de contenedores sin Python: el script corre allí y el informe se
genera en otro equipo con Python 3.12.

**No hay** componente central, ejecución por SSH, histórico, comparación entre
ejecuciones, alertas ni escaneo (ver *Fuera de lo entregado*).

**El aridi de 2019 ya no está en el repositorio.** Se retiró en la fase 4, al alcanzar
la paridad (`tests/parity.md`). Queda en la historia de git: en la raíz hasta el commit
`4ab279e` y en `legacy/` entre `6f749d6` y `037284e`. Su medición, con las mismas
categorías que este documento, está en la versión de este fichero de esos commits.

## Cómo se ha medido

Todo se mide con **pruebas automáticas** sobre muestras reales (`tests/run.sh`). Nada de
este documento se ha dado por bueno leyendo código.

| Parte | Qué hace | Dónde |
|---|---|---|
| `unit` | Pruebas `unittest` del núcleo en `python:3.12-slim`: cada área contra el corpus, contra la «verdad de referencia» de cada muestra y con entradas sintéticas | `tests/test_*`, `tests/test_core/`, `tests/test_parsers/` |
| `collector` | El script en las 10 imágenes, con cada shell presente (`dash`, `bash`, busybox `ash`, el `sh` de CentOS 6), como root y como uid 65534, por `sh -s`: código de salida 0, ningún fichero creado o modificado (`find / -xdev -newer`) y los estados esperados | `tests/collector/test_script.sh` |
| Regresión contra 2019 | El aridi de 2019 sin modificar y el script nuevo en el mismo contenedor, uno detrás de otro: todo lo que 2019 daba bien sale igual | `tests/parity/`, `tests/test_parity.py`, `tests/parity.md` |

**El corpus** (`tests/corpus/`, ver su `README.md`):

- **10 imágenes de contenedor** fijadas por digest: Debian 12 y 13, Ubuntu 24.04,
  Rocky 9, Fedora 44, Alpine 3.20, openSUSE Leap 15.6, Arch, CentOS 7 y CentOS 6. Arch y
  CentOS 6 son amd64 emuladas; el resto, arm64.
- **3 variantes por imagen:** `minimal` (la imagen tal cual, sin red), `server` (con
  `iproute2`, `procps`, `nftables`, `iptables`, `socat`…, sin red) y `bridge` (la
  `server` en una red Docker interna, con `eth0@ifN`).
- **3 VMs de Lima** con systemd, cortafuegos y sesiones SSH reales: Debian 12 arm64,
  Rocky 9 arm64 y Debian 12 amd64 (emulada). No montan nada del anfitrión.
- **Un escenario común** (`tests/corpus/scenario.sh`) con los casos que rompían 2019:
  `alice` con contraseña del algoritmo por defecto (yescrypt o SHA-512), `bob`
  bloqueado, un grupo con un miembro sin cuenta, un SUID de prueba, un directorio
  escribible sin *sticky bit*, un *banner* con ANSI y `<script>`, entradas de `hosts` y
  un `nameserver` IPv6, IPs en `/etc` y `/var/log`, servidores en `[::]:8080`,
  `127.0.0.1:8081` y UDP `0.0.0.0:5514`, y un proceso con uid 4242 sin cuenta.
- **Una verdad de referencia** por muestra (`facts.txt`, obtenida con las herramientas
  del propio sistema), con la que se comparan paquetes, cuentas, montajes, SUID, puertos…

**Resultado observado** (`aridi report` sobre las 33 muestras): 12 completas y 21 con
huecos declarados; **ningún área en `error`** (`test_relations:GlobalRegressionTest`).
Duración del script: de 1 a 2 s en arm64 nativo, hasta 7 s en Alpine, de 13 a 21 s en
las amd64 emuladas y 14 s en la VM x86_64; ninguna supera los 60 s.

**Límites de la medición:**

- Son contenedores y 3 VMs, no un parque real. No hay discos físicos, USB reales, red
  local con otros equipos ni carga real.
- Todo corre en un Mac arm64 con Docker Desktop; x86_64 se ve solo emulado (2 imágenes
  y 1 VM).
- Ninguna muestra tiene `wtmpdb` (sistemas sin `wtmp`), un dominio DNS configurado ni
  `iptables` con reglas en modo *legacy*.
- Lo que no se ha podido observar está en *Implementadas, sin verificar*.

**Categorías y criterio** (los mismos que la medición de 2019, decididos con el usuario):

- **Entregada:** funciona y da datos correctos en todas las muestras.
- **Entregada con limitaciones:** funciona y da datos correctos, pero tiene huecos en
  casos poco comunes o fuera de la configuración por defecto.
- **A medias:** da **datos erróneos sin avisar**, o desaparece entera en la configuración
  por defecto de alguna distribución o entorno dentro del alcance de `IDEA.md`.
- **Implementada, sin verificar:** hay código, pero ninguna muestra real lo ejercita. No
  cuenta como entregada.
- **Abandonada:** hay código, pero nunca se ejecuta.

---

## Funcionalidades que funcionan hoy

Las pruebas se citan como `módulo:Clase.método` (fichero `tests/**/módulo.py`).

### 1. Recogida local sin dependencias y sin escribir en disco — *entregada*

- **Observado:**
  - `sh aridi-collect.sh` termina con 0 en las 10 imágenes, con cada shell, como root y
    como uid 65534, también sin terminal (`run.sh collector`).
  - No crea ni modifica ningún fichero (`find / -xdev -newer`). Para conseguirlo, `rpm`
    se ejecuta como uid 65534, porque como root escribe en `/var/lib/rpm` al consultar, y
    `nft`/`iptables` solo se consultan si el motor ya está en el kernel, para no cargar
    módulos (`FORMATO.md`).
  - Cada comando tiene un límite de 60 s y 4 MiB; lo que no se puede recoger sale como
    `denied`, `missing`, `na`, `timeout` o `error`, con su código y su nota.
- **Casos no cubiertos:** sistemas fuera del corpus (por ejemplo, otros `sh` o busybox
  muy antiguos).

### 2. Interpretación, fotografía e informe — *entregada con limitaciones*

- **Observado:**
  - `aridi validate|interpret|report` sobre las 33 muestras; la fotografía JSON y el
    informe resumido o detallado (`test_cli:CliTest.test_report_summary_and_detail`,
    `test_text:TextTest.test_golden_corpus_report`).
  - Código de salida 0 si la fotografía está completa y 1 si tiene huecos
    (`test_cli:CliTest.test_complete_exit_code`).
  - Los ficheros nuevos se crean con modo 0600, sin sobrescribir ni seguir enlaces
    (`test_cli:CliTest.test_interpret_never_overwrites_nor_follows_symlinks`).
  - El texto no fiable (*banners*, nombres) se neutraliza en el informe
    (`test_text:TextTest.test_untrusted_text_is_escaped`).
  - Un analizador que falla no arrastra a los demás
    (`test_interpret:InterpretTest.test_failing_parser_does_not_take_others_down`).
  - El núcleo solo importa la librería estándar (`test_core_isolation`).
- **Limitaciones:**
  - **Dos pasos:** el informe exige Python 3.12 en algún equipo. En una máquina sin él,
    el paquete hay que llevarlo a otro sitio para leerlo.
  - Solo texto y JSON; no hay otra vista.
  - **Observado:** `pip install .` descarga `setuptools` de PyPI para construir el
    paquete (falla sin red en `python:3.12-slim`). Ejecutar el núcleo con
    `PYTHONPATH=src python3 -m aridi.cli` no descarga nada (probado sin red).

### 3. Sistema: distribución, kernel y libc — *entregada*

- **Observado:** coinciden con `facts.txt` en las 33 muestras
  (`test_system:CorpusTest.test_matches_facts_in_every_sample`). Alpine sale con su
  versión (`3.20.x`), CentOS 6 se identifica sin `os-release`, y se distinguen glibc y
  musl. En Debian 12 y CentOS 7 coinciden con 2019 (`test_parity:ParityTest.test_kernel`,
  `test_distribution`, `test_libc`).

### 4. Hardware: CPU, memoria y USB — *entregada con limitaciones*

- **Observado:** CPU con fabricante, modelo y núcleos en arm64 (el fallo n.º 11 de 2019)
  y en x86_64 (VM amd64); memoria y *swap* iguales que 2019 al kB
  (`test_hardware:CorpusTest.test_arm64_has_cores_and_model`,
  `test_hardware:CorpusTest.test_x86_64_vm`, `test_parity:ParityTest.test_ram_and_swap`).
  USB se lee de `/sys/bus/usb`, sin `lsusb`.
- **Limitaciones:** USB solo con datos sintéticos y con lo que ve un contenedor; ninguna
  muestra tiene un dispositivo USB real. Los modelos de CPU ARM que no están en la tabla
  salen como «part 0x…», no inventados (`test_hardware:SyntheticTest.test_arm_known_and_unknown_parts`).

### 5. Paquetes — *entregada*

- **Observado:** **exactamente** los mismos paquetes que `facts.txt` en las 33 muestras,
  con dpkg, rpm (Red Hat, Fedora con dnf5 y openSUSE), apk y pacman
  (`test_packages:CorpusTest.test_exactly_the_packages_of_facts`). Versión binaria en
  Debian, no la del paquete fuente. Las claves `gpg-pubkey` se cuentan aparte. Contra
  2019: Debian 12 da 141 y CentOS 7 161, los mismos nombres y, en CentOS 7, las mismas
  versiones (`test_parity:ParityTest.test_packages_same_names`, `test_rpm_versions`).

### 6. Almacenamiento: montajes, discos y ocupación — *entregada*

- **Observado:** montajes y ocupación iguales a `df` en las 33 muestras; el `lsblk`
  actual no rompe nada (n.º 13); CentOS 6, sin `lsblk`, saca los discos de
  `/sys/class/block`
  (`test_storage:CorpusTest.test_mounts_and_usage_match_facts`,
  `test_current_lsblk_does_not_break`, `test_centos6_without_lsblk`). Ningún montaje del
  anfitrión aparece en las muestras (`test_no_host_directory_in_any_sample`).

### 7. Permisos peligrosos — *entregada*

- **Observado:** SUID, SGID, ficheros escribibles por todos y directorios sin *sticky
  bit* del sistema de ficheros raíz, iguales a `find` de `facts.txt`, sin preguntar y sin
  escribir ningún fichero (`test_permissions:CorpusTest.test_same_files_as_find_in_facts`).
  Además, los permisos de `passwd`, `group`, `shadow` y `gshadow`. Contra 2019, los
  mismos ficheros, salvo los enlaces simbólicos que 2019 seguía y contaba dos veces
  (`/usr/bin/sg` → `newgrp`; `test_parity:ParityTest.test_permissions`).
- **Deducido:** solo el sistema de ficheros raíz (`-xdev`): otros montajes no se recorren.

### 8. Identidad y *banners* — *entregada con limitaciones*

- **Observado:** hostname, hostid, `issue`, `issue.net`, `motd` y `motd.d`, iguales a 2019
  (`test_parity:ParityTest.test_hostname_hostid_and_banners`). El dominio es el dominio
  DNS, nunca el hostname (el error de 2019).
- **Limitaciones:**
  - **Hueco `missing`:** en 9 muestras (Arch, Fedora 44 y openSUSE Leap 15.6, las tres
    variantes) no está `dnsdomainname`, así que el dominio queda sin ver.
  - **Sin hueco (`na`):** en otras 10 muestras sin red, el hostname no resuelve; ahí la
    máquina no tiene un dominio que conocer, así que no se cuenta como hueco.
  - Ninguna muestra tiene un dominio configurado: ese caso solo se prueba con datos
    sintéticos (`test_identity:SyntheticTest.test_domain_configured_empty_and_unknown`).

### 9. Usuarios, grupos y contraseñas — *entregada*

- **Observado:** las mismas cuentas y grupos que `facts.txt` en las 33 muestras; `alice`
  sale con contraseña y su algoritmo (yescrypt o SHA-512), `bob` bloqueado, y los
  miembros sin cuenta (`ghostuser`, el `kvm` de Alpine) se declaran sin anular nada
  (`test_users:CorpusTest.*`). **El hash nunca sale de la máquina:** el script reduce el
  campo a su prefijo, y una prueba lo busca en todo el corpus
  (`test_users:CorpusTest.test_no_bundle_contains_a_full_hash`).

### 10. Servicios — *entregada*

- **Observado:** systemd en marcha (las VMs, con el servicio fallido del escenario),
  `systemctl` sin systemd (CentOS 7 en contenedor), SysV (CentOS 6) y OpenRC (Alpine
  `server`); el área nunca falla (`test_services:CorpusTest.*`).
- **Limitaciones:** runit solo con datos sintéticos.

### 11. Red: interfaces, rutas, DNS, `hosts` y puertos en escucha — *entregada*

- **Observado:** `eth0@ifN` con su par en las 10 muestras `bridge` (n.º 15); IPv4 e IPv6;
  sin `ip`, con `/proc` y `/sys`; un `nameserver` IPv6 sin claves nulas; los mismos
  puertos en escucha que `ss`, TCP, TCP6 y UDP, con su proceso, también con un uid sin
  cuenta (`test_network:CorpusTest.*`, `test_parity:ParityTest.test_listening_sockets`).

### 12. Cortafuegos — *entregada con limitaciones*

- **Observado:** reglas de nftables en las 3 VMs, firewalld en Rocky 9, cadenas
  `forward` incluidas (`test_firewall_timesync:FirewallCorpusTest.*`). En contenedores
  sin `CAP_NET_ADMIN`, hueco `denied` con el motivo («Operation not permitted»).
- **Limitaciones (huecos que quedan en el corpus):**
  - `firewall nft_json denied` en 15 muestras de contenedor;
  - `iptables_legacy` e `ip6tables_legacy denied` en 6;
  - `nftables rules missing` en 2: el `nft` 0.8 de CentOS 7 no tiene salida JSON, y las
    reglas no se interpretan desde su texto.
  - **`iptables` con reglas** y **ufw** solo se han visto con datos sintéticos
    (`FirewallSyntheticTest`).

### 13. Sincronización horaria — *entregada con limitaciones*

- **Observado:** chrony en Rocky 9 y systemd-timesyncd en las VMs Debian, con sus
  servidores configurados; sin servicio, hueco `na` (`test_firewall_timesync:TimesyncTest.*`).
- **Limitaciones:** ntpd (`ntpq`) solo con datos sintéticos. Los nombres de servidor se
  guardan como texto, sin resolver.

### 14. Procesos — *entregada con limitaciones*

- **Observado:** cualquier número de procesos (2019 se perdía con menos de 10 con CPU),
  el uid sin cuenta como número, zombis, y los de más memoria y CPU
  (`test_volatile:ProcessesTest.*`).
- **Limitaciones:** la línea de órdenes se corta a 512 bytes y se ocultan en origen los
  valores con aspecto de secreto (`--password=…`, `--token …`). **No cubre todas las
  formas:** `mysql -pSECRETO` saldría tal cual (`FORMATO.md`). La alternativa segura,
  no enviar la línea de órdenes, está pendiente de decisión.

### 15. Carga: memoria, CPU, disco, *uptime* — *entregada*

- **Observado:** memoria, *swap*, carga, CPU desde el arranque y en un segundo, carga de
  disco (con el cálculo corregido de 2019) y *uptime* en las 33 muestras; total en MB y
  *uptime* iguales a 2019 (`test_volatile:LoadTest.*`,
  `test_parity:ParityTest.test_total_memory_in_mb`, `test_uptime`).

### 16. Sesiones y accesos — *entregada con limitaciones*

- **Observado:** en las 3 VMs, la sesión SSH activa de `alice`, sus accesos por IPv4 e
  IPv6, el acceso fallido de `nosuchuser` y la IP del anfitrión de Lima como relación
  (`test_volatile:SessionsTest.test_vm_sessions`). En contenedores, el área sale bien,
  sin sesiones.
- **Limitaciones:**
  - Ninguna imagen tiene `wtmpdb`: esa vía solo se prueba con datos sintéticos.
  - Los accesos fallidos del corpus vienen de *loopback*, así que el papel
    `failed_login_source` solo se ve con datos sintéticos.
  - Las fechas en otro idioma salen como desconocidas, no se adivinan
    (`test_dates_in_another_language_are_unknown_not_wrong`).

### 17. Conexiones con su proceso — *entregada*

- **Observado:** dirección (entrante o saliente), servicio por puerto (`services.csv`),
  IPv6 y la sesión SSH de las VMs como conexión entrante (`test_volatile:ConnectionsTest.*`).

### 18. IPs y nombres en `/etc`, `/var/log` y el journal (*carving*) — *entregada con limitaciones*

- **Observado:** las direcciones IPv4 e IPv6 del escenario en las 33 muestras, con fichero
  y línea; se descartan números de versión, redes, *link-local* y líneas comentadas
  (`test_carving:CarvingCorpusTest.test_scenario_addresses_in_every_sample`). Contra 2019,
  las mismas IPv4 en `/etc` y `/var/log` (`test_parity:ParityTest.test_carving`).
- **Limitaciones (decididas por seguridad):**
  - **No sale el texto de la línea**, solo la ruta, el número de línea, la dirección y
    marcas de contexto (`test_no_line_text_leaves_the_machine`).
  - En `/etc` solo se leen los ficheros legibles por cualquier usuario, así que nunca
    `shadow` ni claves privadas (`test_protected_files_are_never_read`).
  - Del journal solo salen recuentos por dirección.
  - Los nombres de host se listan, pero no se resuelven.

### 19. Vecinos de red — *entregada*

- **Observado:** la tabla de vecinos (pasiva) en las 33 muestras; la pasarela en las 3
  VMs; sin `ip`, `/proc/net/arp` (solo IPv4) (`test_carving:NeighboursTest.*`).

### 20. Mapa de relaciones y «lo que no se pudo ver» — *entregada*

- **Observado:** cada papel de relación es un código enumerado; IPv4 e IPv6 se ordenan
  juntas, las locales primero. Todos los papeles salen de alguna muestra, salvo
  `failed_login_source` (sintético) y `scan_open_port` (reservado para el escaneo del
  central, que todavía no existe)
  (`test_relations:RelationsTest.test_every_role_comes_from_a_sample_or_is_tested_elsewhere`).
  Cada área declara sus huecos parciales con estado y motivo, y el informe los reúne en
  «What could not be seen».

---

## Funcionalidades a medias

**Ninguna observada.** Ningún área da datos erróneos sin avisar ni desaparece en las 33
muestras: lo que falta sale como hueco con su motivo. Los 11 fallos de 2019 que estaban
en esta categoría tienen cada uno su prueba (`tests/parity.md`, n.º 11 a 21).

**Suposición:** en máquinas fuera del corpus aparecerán formatos que el corpus no
contiene. La regla es declararlos como hueco, no encajarlos (`CLAUDE.md`, reglas 10 a 12),
pero solo las pruebas sobre muestras nuevas lo demostrarán.

## Implementadas, sin verificar

Hay código, pero ninguna muestra real lo ejercita; solo datos sintéticos. **No cuentan
como entregadas.**

| Funcionalidad | Por qué no se ha observado | Prueba sintética |
|---|---|---|
| `iptables`/`ip6tables` con reglas (modo *legacy*) | Las VMs usan nftables; los contenedores no tienen permiso | `test_firewall_timesync:FirewallSyntheticTest.test_iptables_save` |
| ufw | Ninguna muestra lo tiene | `test_firewall_timesync:FirewallSyntheticTest.test_ufw` |
| ntpd (`ntpq`) | Ninguna muestra lo tiene | `test_firewall_timesync:TimesyncTest.test_chronyc_and_ntpq_sources` |
| runit | Ninguna muestra lo tiene | `test_services:SyntheticTest.test_openrc_and_runit` |
| `wtmpdb` | Ninguna imagen lo trae | Solo sintética: `wtmpdb` se prefiere a `last` y se lee con el mismo formato de `last -F` (`test_volatile:SessionsTest.test_wtmpdb_is_preferred_to_last`) |
| Dominio DNS configurado | Ningún hostname del corpus resuelve con dominio | `test_identity:SyntheticTest.test_domain_configured_empty_and_unknown` |
| Dispositivos USB reales | No hay USB en contenedores ni VMs | `test_hardware:SyntheticTest.test_usb_devices_and_hubs` |
| Accesos fallidos desde IPs remotas | Los del corpus vienen de *loopback* | `test_volatile:SessionsTest.test_journal_syslog_relations_and_counts` |

## Abandonadas

**Ninguna.** No hay código del colector que no se ejecute.

---

## Qué se perdió respecto a 2019

Lo decidido está en [`CAMBIO.md`](CAMBIO.md) (*Qué se pierde*) y lo comprobado, fila a
fila, en [`tests/parity.md`](../tests/parity.md). En resumen:

- **El modo local de una sola pieza:** ahora son dos pasos, e interpretar exige
  Python 3.12 en algún equipo.
- **La CLI y el formato del informe de 2019** (`-g -s -v -c -a -os -od -of -oi`).
- **El escaneo de puertos y el barrido ARP desde la máquina:** el colector es pasivo.
- **El grafo `--graph`.**
- **La resolución DNS de los FQDN** encontrados en `/etc` y `/var/log`.
- **El texto de las líneas del *carving***, que 2019 mostraba (decisión de seguridad).

La regresión contra 2019 también encontró fallos de 2019 que la medición anterior no
había visto (por ejemplo, que un `nameserver` IPv6 impide escribir el informe entero, o
que contaba como SUID los enlaces simbólicos). Están en `tests/parity.md`.

## Fuera de lo entregado

Para que la frontera no admita dudas, aridi **no** hace hoy nada de lo siguiente. Todo
está previsto en las fases 5 a 7 de `TODO.md` y **todavía no existe**:

- **Ejecución remota por SSH.** El script se lleva y se ejecuta a mano.
- **Componente central, inventario, histórico o búsqueda en el parque.** Nada se guarda
  entre ejecuciones; `src/aridi_central/` no existe.
- **Comparación entre ejecuciones y alertas.**
- **Programación de recogidas.**
- **Interfaz web, usuarios o roles.**
- **Escaneo de puertos** desde el central, acotado a redes autorizadas.
- **Mapa gráfico** de relaciones.

## Definición de terminado

La que se aplica desde la reescritura (`CLAUDE.md`, `TODO.md`):

- **Pruebas:** toda tarea que cambia comportamiento trae su prueba, y nada se da por
  hecho sin verlo pasar en `tests/run.sh`.
- **Calidad:** ningún error se omite en silencio; lo que no se puede recoger o
  interpretar es un hueco con estado y motivo. Un dato incorrecto es peor que uno que
  falta.
- **Seguridad:** el script es de solo lectura y filtra lo sensible en origen; el núcleo
  no tiene dependencias de terceros.
- **Documentación:** el contrato del paquete y de la fotografía está versionado en
  `FORMATO.md`.
- **Versionado:** `2.0.0.dev0` en el script y en el núcleo; todavía no hay versión
  publicada ni etiquetas.
