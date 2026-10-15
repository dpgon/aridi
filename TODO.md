# TODO: reescritura de aridi

Este archivo es la lista de tareas para llevar a cabo el cambio de rumbo decidido en
[`docs/CAMBIO.md`](docs/CAMBIO.md) el 2026-10-15. Está ordenada para que **cada fase deje
el proyecto funcionando**. Hasta la fase 4, el aridi de 2019 sigue disponible en
`legacy/`.

**Cómo usarlo**

- Marca cada tarea al terminarla (`- [x]`). Si una tarea cambia o se divide, edítala aquí
  en lugar de dejarla desfasada.
- **Las pruebas forman parte de cada tarea.** Una tarea que cambia comportamiento no está
  hecha hasta que sus pruebas existen y pasan con `tests/run.sh`.
- No pases a la siguiente fase sin cumplir el **criterio de aceptación** de la actual.
- Las tareas marcadas **[decisión]** necesitan al usuario. Plantéalas con un menú de
  opciones y anota aquí lo que se decida.
- Los commits solo se hacen cuando el usuario lo pida (`CLAUDE.md`, *Flujo de git*). El
  momento natural es al cerrar una subfase.
- Rutas: `src/aridi/` es el núcleo (solo la librería estándar);
  `src/aridi_central/` es el central (Django); `collector/aridi-collect.sh` es el script
  de recogida.

**Decisiones de planificación** (2026-10-15, además de las de `CAMBIO.md`):

- **No hay CI remota.** Todo se verifica en local con `tests/run.sh`, que usa Docker.
  macOS solo tiene Python 3.9, así que las pruebas de Python también corren en
  contenedores `python:3.12-slim`.
- **Las áreas del colector se construyen en el orden del código de 2019:**
  general → específica → volátil → carving → vecinos.
- **Las muestras que los contenedores no pueden dar** (systemd, sesiones reales, x86_64)
  se capturan con **Lima 1.x**.

---

## Fase 0: base del repositorio

Prepara el repositorio para el código nuevo sin cambiar el comportamiento de 2019.

### 0.1 Línea base de `legacy` (antes de mover nada)

- [x] Crear `tests/legacy/baseline.sh`. Debe ejecutar el aridi actual, desde la raíz y en
  contenedores `--network none`, con Debian 12 y CentOS 7: `debian:12` con `python3`
  instalado y `centos:7` con repositorios *vault*. El comando es
  `printf 'y\nn\nn\nn\nm\n' | python3 aridi.py -a --scan -V 3 -of report.txt`. El script
  guarda en `tests/legacy/baseline/<distro>/` tres cosas: la lista de líneas `ERROR` de
  `aridi.log`, las cabeceras de sección de `report.txt` y el código de salida.
- [x] Ejecutar `tests/legacy/baseline.sh` y versionar la salida. Comprobar que coincide
  con lo descrito en `docs/MVP.md`: en Debian 12, 5 errores (usb, disk, iptables,
  processes, Disk live); en CentOS 7, 4 errores.

### 0.2 Mover el código de 2019 a `legacy/`

- [x] `git mv` de `aridi.py`, `gathering0.py`, `gathering1.py`, `gathering2.py`,
  `gathering3.py`, `gathering4.py`, `graph.py`, `reporting.py`, `scan.py`, `utils.py`,
  `services.csv` y `__init__.py` a `legacy/`, sin modificar su contenido. `LICENSE`,
  `README.md`, `CLAUDE.md` y `docs/` se quedan en la raíz.
- [x] Añadir `legacy/README.md` (en inglés, como el original), con estas indicaciones:
  - es el aridi de 2019;
  - está obsoleto;
  - se ejecuta con `cd legacy && sudo python3 aridi.py …`;
  - se borrará al alcanzar la paridad (fase 4);
  - su estado está en `docs/MVP.md`.
- [x] **Regresión:** adaptar `tests/legacy/baseline.sh` para que ejecute desde `legacy/`,
  y comprobar que sus tres salidas son idénticas a la línea base de 0.1.

### 0.3 Ficheros de soporte

- [x] Crear `.gitignore` con `__pycache__/`, `*.pyc`, `.venv/`, `aridi.log`,
  `aridi.badfiles`, `network.dot`, `network.dot.*`, `report.txt`, `*.aridi` (salvo
  `tests/corpus/**`), `/data/`, `*.sqlite3`, `*.db` y `.lima/`.
- [x] **[decisión]** Preguntar al usuario si `.m-terminal/` (sin seguimiento hoy) va al
  `.gitignore`. **Decidido (2026-10-15): sí, se ignora.**
- [x] Crear `pyproject.toml` en la raíz:
  - distribución `aridi`, `requires-python = ">=3.12"`, código en `src/`, **sin
    dependencias**, *script* de consola `aridi = "aridi.cli:main"`;
  - extra opcional `central` con `Django>=5.2,<5.3` y `gunicorn>=23,<24`;
  - licencia GPL-3.0-only.
- [x] Crear `requirements/central.in` (`Django~=5.2.0`, `gunicorn~=23.0`) y
  `requirements/central.txt`, fijado con hashes para `pip install --require-hashes`.
  Generarlo dentro de un contenedor `python:3.12-slim` con
  `pip-compile --generate-hashes`. `pip-tools` se usa solo para generar el fichero; no
  entra en el producto. Documentar el comando en el propio `.in`.
- [x] Comprobar que `requirements/central.txt` solo contiene `Django`, `asgiref`,
  `sqlparse`, `gunicorn` y `packaging`. Si aparece otro paquete, parar y avisar al
  usuario.

### 0.4 Esqueleto del código nuevo

- [x] Crear `src/aridi/__init__.py` con `__version__ = "2.0.0.dev0"` y la constante
  `BUNDLE_FORMAT_VERSION = 1`.
- [x] Crear `src/aridi/cli.py` con `main()` y `argparse`, y los subcomandos `report`,
  `interpret` y `validate`, que de momento responden «no implementado» con código 2.
- [x] Crear `collector/aridi-collect.sh` vacío, con cabecera `#!/bin/sh`, licencia y
  versión.
- [x] Crear `tests/test_parsers/__init__.py` y `tests/test_parsers/test_smoke.py` (importa
  `aridi` y comprueba `__version__`).
- [x] Crear `tests/test_core_isolation.py`: recorre `src/aridi/**/*.py` con `ast` y falla
  si algún módulo importa algo que no sea de la librería estándar o de `aridi`. Se usa
  `sys.stdlib_module_names`.

### 0.5 `tests/run.sh`

- [x] Crear `tests/run.sh` (POSIX `sh`) con los subcomandos `unit`, `collector`,
  `central`, `legacy` y `all`.
  - `unit` ejecuta `python -m unittest discover -s tests -t .` dentro de
    `python:3.12-slim`, con el repositorio montado en solo lectura.
  - `legacy` ejecuta `tests/legacy/baseline.sh` y compara con la línea base.
  - `collector` y `central` quedan como «sin pruebas aún», con código 0.
- [x] Hacer que `tests/run.sh all` devuelva un código distinto de 0 si falla cualquier
  parte e imprima un resumen por parte.
- [x] Ejecutar `tests/run.sh all` y comprobar que pasa.

### 0.6 Documentación de la fase

- [x] `CLAUDE.md`:
  - la estructura nueva (`legacy/`, `collector/`, `src/aridi/`, `src/aridi_central/`,
    `tests/`);
  - «ejecutar desde la raíz» pasa a «ejecutar `legacy/` desde `legacy/`»;
  - la regla de Python 3.6 queda limitada a `legacy/`;
  - el núcleo exige Python ≥ 3.12 y solo librería estándar;
  - el comando de pruebas es `tests/run.sh all`;
  - el `.gitignore` ya existe.
- [x] `README.md` (en inglés): avisar de que el programa de 2019 está en `legacy/` y de
  cómo ejecutarlo, que hay una reescritura en curso (enlace a `docs/CAMBIO.md` y a
  `TODO.md`), y añadir `docs/CAMBIO.md` al índice de documentos.
- [x] `docs/CAMBIO.md`: añadir una nota bajo *Aspectos transversales → Pruebas* que diga
  que la CI es local (`tests/run.sh`), por decisión del 2026-10-15.

**Criterio de aceptación de la fase 0:**

- `tests/run.sh all` termina con código 0;
- `legacy/` produce exactamente la línea base de 0.1;
- `src/aridi` se importa en Python 3.12;
- la prueba de aislamiento del núcleo pasa;
- no hay ningún fichero de 2019 fuera de `legacy/`.

---

## Fase 1: corpus de muestras reales

Esta fase consigue los datos con los que se probará todo el colector.

**Depende de:** fase 0. Para capturar las muestras hace falta al menos el esqueleto de
`collector/aridi-collect.sh`, así que la captura definitiva se repite al cerrar cada
área de la fase 3. Aquí se monta la maquinaria y se capturan los «hechos de referencia».

### 1.1 Maquinaria de captura en contenedores

- [ ] Crear `tests/corpus/images.txt` con una imagen por línea, fijada por *digest*:
  - `debian:12`, `debian:13`, `ubuntu:24.04`, `rockylinux:9`, `fedora:44`,
    `alpine:3.20`, `opensuse/leap:15.6`;
  - `archlinux:latest`, `centos:7` (con *vault*) y `centos:6` (con *vault*), estas tres
    en `--platform linux/amd64` emulada si no hay arm64.
- [ ] Crear `tests/corpus/scenario.sh` (POSIX `sh`, se ejecuta dentro del contenedor).
  Reproduce los casos de `docs/MVP.md`:
  - el usuario `alice` con contraseña (que dará yescrypt donde sea el valor por defecto);
  - una cuenta bloqueada;
  - un grupo con un miembro sin usuario;
  - un servidor TCP en `[::]:8080` y otro en `127.0.0.1:8081`;
  - un UDP en `0.0.0.0:5353`;
  - un proceso con uid 4242 sin entrada en `passwd`;
  - un montaje *bind*;
  - un fichero SUID de prueba y un directorio escribible por todos sin *sticky bit*.

  Para los servidores usa la herramienta que haya (`busybox nc`, `socat`, `python3`) y,
  si no hay ninguna, lo omite y lo anota.
- [ ] Crear `tests/corpus/facts.sh`. Se ejecuta en el mismo contenedor tras
  `scenario.sh` y escribe `facts.txt` con la «verdad de referencia» obtenida con las
  herramientas del sistema:
  - número y lista de paquetes (`dpkg-query -W`, `rpm -qa`, `apk info -v`, `pacman -Q`);
  - usuarios y grupos;
  - prefijos de hash por usuario;
  - sockets en escucha (`ss -lntup` o `netstat`, si existen);
  - interfaces y direcciones;
  - montajes (`/proc/self/mountinfo`);
  - kernel y libc.
- [ ] Crear `tests/corpus/capture.sh <imagen> <variante>`, con dos variantes:
  - `minimal`: la imagen tal cual, **sin Python**;
  - `server`: con `iproute2`/`iproute`, `procps`, `util-linux`, `nftables` e
    `iptables`.

  Ejecuta `scenario.sh`, después `sh -s < collector/aridi-collect.sh` (con
  `--network none`, salvo una ejecución en red *bridge* para obtener `eth0@ifN`) y
  después `facts.sh`. Guarda todo en `tests/corpus/<distro>/<variante>/`
  (`bundle.aridi`, `facts.txt`, `meta.txt` con imagen, *digest*, fecha y arquitectura).
- [ ] Probar `capture.sh` con `debian:12 minimal` y el script vacío: tiene que producir
  los tres ficheros sin dejar nada fuera de `tests/corpus/`.

### 1.2 VMs con Lima para lo que no dan los contenedores

- [ ] Crear `tests/lima/debian12-arm64.yaml`, `tests/lima/rocky9-arm64.yaml` y
  `tests/lima/debian12-amd64.yaml` (QEMU, emulado), cada uno con systemd, `openssh-server`,
  `nftables`, `chrony` (Rocky) o `systemd-timesyncd` (Debian), un usuario sin privilegios
  y un usuario `aridi` con `sudo -n` (según la decisión de 5.0; hasta entonces, NOPASSWD
  completo, **solo en la VM de prueba**).
- [ ] Crear `tests/lima/scenario-vm.sh`, que añade a `tests/corpus/scenario.sh` lo
  propio de una VM:
  - inicios de sesión SSH reales a `localhost`, que generan `wtmp`/`lastlog` o
    `wtmpdb`;
  - inicios fallidos, que generan `btmp` o entradas en journald;
  - reglas nftables con INPUT, OUTPUT y FORWARD, y en Rocky reglas firewalld;
  - un servicio systemd que falle a propósito;
  - un subvolumen btrfs si la imagen lo admite (si no, se anota).
- [ ] Crear `tests/lima/capture-vm.sh <vm>`, que hace `limactl start`, ejecuta el
  escenario, ejecuta `limactl shell <vm> sudo sh -s < collector/aridi-collect.sh` y
  `facts.sh`, guarda el resultado en `tests/corpus/vm-<vm>/` y hace `limactl delete`.
- [ ] Documentar en `tests/corpus/README.md` cómo se regenera cada muestra, qué cubre cada
  una y qué **no** cubre (por ejemplo, ningún USB real).

**Criterio de aceptación de la fase 1:**

- `capture.sh` y `capture-vm.sh` funcionan para todas las imágenes y VMs de 1.1 y 1.2;
- cada muestra tiene `facts.txt` y `meta.txt`;
- `tests/corpus/README.md` describe la cobertura.

Los paquetes en bruto todavía están casi vacíos: se rellenan en la fase 3.

---

## Fase 2: contrato del formato

Fija el formato del paquete en bruto y de la fotografía antes de escribir ninguna área.
**Desde aquí, el formato es un contrato versionado** (`docs/CAMBIO.md`, *Riesgos*).

**Depende de:** fase 1 (captura).

### 2.1 Especificación

- [ ] Crear `docs/FORMATO.md` con la especificación del **paquete en bruto v1**:
  - cabecera `ARIDI-BUNDLE 1 <versión_script>`;
  - frontera aleatoria por ejecución;
  - por sección: nombre, estado (`ok`, `denied`, `missing`, `na`, `timeout`, `error`),
    código de salida, bytes y contenido;
  - cierre con número de secciones;
  - reglas de escape;
  - lo que el script **nunca** emite (hashes completos de `shadow`, contenido de claves
    privadas).
- [ ] En `docs/FORMATO.md`, especificar también la **fotografía v1**: `schema_version`,
  `machine` (`machine_id`, `hostname`), `collected_at`, `collector_version`,
  `sections.<área>` con `status`, `reason` y `data`, la marca `volatile`, y la lista
  `relations` con códigos de papel **enumerados**, no frases. Por ejemplo: `local`,
  `dns_server`, `ntp_server`, `login_source`, `failed_login_source`, `fw_allowed_in`,
  `fw_allowed_out`, `peer_in`, `peer_out`, `named_in_file`, `neighbour`, `scan_open_port`.
- [ ] En `docs/FORMATO.md`, la política de versiones: qué cambio sube la versión,
  compatibilidad hacia atrás de `aridi interpret` con paquetes antiguos y qué pasa con
  una versión desconocida (error explícito).

### 2.2 Script de recogida: armazón

- [ ] En `collector/aridi-collect.sh`, implementar el armazón:
  - funciones `section <nombre> <comando…>`, `section_file <nombre> <ruta>` y
    `have <herramienta>`;
  - estados según el resultado: `missing` si falta la herramienta, `denied` si no hay
    permiso de lectura y `timeout` si se agota el tiempo (con `timeout` si existe; si
    no, sin límite y anotado);
  - límite de bytes por sección (`head -c`);
  - `umask 077`;
  - **ninguna escritura en disco**: todo por stdout, sin ficheros temporales;
  - `LC_ALL=C`.
- [ ] Añadir las secciones de identidad que necesita la cabecera de la fotografía:
  `/etc/machine-id` (o `/var/lib/dbus/machine-id`), `hostname`, `uname -a`, `id -u` y la
  fecha UTC.
- [ ] Pruebas en `tests/collector/test_script.sh`, ejecutadas por
  `tests/run.sh collector` en **todas** las imágenes de `tests/corpus/images.txt`, en
  variante `minimal`:
  - el script termina con código 0;
  - la salida empieza por `ARIDI-BUNDLE 1`;
  - **no se crea ni se modifica ningún fichero**: se comprueba con
    `find / -xdev -newer <marca>` antes y después, excluyendo `/proc`, `/sys` y `/dev`;
  - funciona con `dash`, `bash`, `busybox ash` y el `sh` de CentOS 6.
- [ ] Prueba con un usuario sin privilegios (`--user 65534`): termina igual y marca como
  `denied` lo que no puede leer.

### 2.3 Núcleo: lectura, modelo y CLI

- [ ] `src/aridi/bundle.py`: leer un paquete v1 y devolver las secciones (nombre, estado,
  código, bytes); rechazar una versión desconocida o un paquete truncado con una
  excepción propia. **Pruebas** en `tests/test_parsers/test_bundle.py`: paquetes del
  corpus, uno truncado, una versión desconocida y una frontera que aparezca dentro del
  contenido.
- [ ] `src/aridi/model.py`, con `dataclasses`:
  - `Snapshot`, `Section` (`status`, `reason`, `data`, `volatile`), `Relation` (IP como
    `ipaddress.ip_address`, v4 y v6, y papel enumerado);
  - serialización a JSON y desde JSON;
  - `schema_version = 1`.

  **Pruebas:** ida y vuelta a JSON, papeles desconocidos rechazados, IPs v4 y v6.
- [ ] `src/aridi/interpret.py`: de paquete a `Snapshot`, con un registro de analizadores
  por área. Un área sin analizador o con la sección en un estado distinto de `ok`
  produce `Section(status=…, reason=…)`; **nunca desaparece**. Una excepción en un
  analizador produce `status="error"` con el motivo, y el resto continúa. **Pruebas:**
  un analizador que lanza una excepción no tumba los demás.
- [ ] `src/aridi/views/text.py`: informe legible con resumen y detalle por área (los dos
  niveles se conservan de 2019) y una sección final **«Lo que no se ha podido ver»**,
  con área, estado y motivo. **Pruebas:** salida estable (*golden*) para un paquete del
  corpus.
- [ ] `src/aridi/cli.py`:
  - `aridi validate <paquete>`;
  - `aridi interpret <paquete> [-o fichero.json]`;
  - `aridi report <paquete> [--detail]`;
  - códigos de salida 0 = completa, 1 = con huecos, 2 = fallida o paquete inválido;
  - logging con el módulo `logging` hacia stderr, con `-v`;
  - salida de ficheros solo donde se indique, creada con permisos `0600` y sin seguir
    enlaces simbólicos (`os.open` con `O_CREAT|O_EXCL|O_NOFOLLOW`).

  **Pruebas** de cada subcomando y código de salida, y de que `-o` sobre un enlace
  simbólico falla.

**Criterio de aceptación de la fase 2:**

- `aridi validate` acepta todos los paquetes del corpus;
- `aridi report` produce para cada uno un informe en el que **todas** las áreas aparecen
  como «no recogido / sin analizador»;
- el script no deja rastro en ninguna imagen;
- `docs/FORMATO.md` está escrito;
- `tests/run.sh all` pasa, incluida la línea base de `legacy/`.

---

## Fase 3: colector, área por área

**El patrón es el mismo en todas las subfases** y se aplica a cada una:

- **(a)** secciones en `collector/aridi-collect.sh`, con varias fuentes ordenadas: primero
  ficheros de `/proc`, `/sys` o `/etc` y, si no, binarios;
- **(b)** analizador en `src/aridi/parsers/<área>.py`;
- **(c)** vista en `src/aridi/views/text.py`;
- **(d)** recaptura del corpus (`tests/corpus/capture.sh` y `tests/lima/capture-vm.sh`)
  y pruebas en `tests/test_parsers/test_<área>.py`, contrastadas con `facts.txt` y con
  los casos de `docs/MVP.md`;
- **(e)** regresión frente a `legacy/`: lo que el código de 2019 daba bien en Debian 12 y
  CentOS 7 (`docs/MVP.md`, *Funcionalidades que funcionan hoy*) el nuevo lo da igual o
  mejor. Se comprueba comparando el informe nuevo con `tests/legacy/baseline/` y con el
  informe de 2019 en la misma muestra.

**Al cerrar cada subfase, el área queda utilizable en modo local**
(`sh aridi-collect.sh > m.aridi` y `aridi report m.aridi`).

**Depende de:** fase 2.

### General

#### 3.1 Sistema: distribución, kernel y libc

- [ ] (a) Secciones `os_release` (`/etc/os-release` o `/usr/lib/os-release`) y
  `release_files`. Las rutas son las **correctas**: `/etc/centos-release`,
  `/etc/redhat-release`, `/etc/fedora-release`, `/etc/SuSE-release`,
  `/etc/debian_version`, `/etc/slackware-version`, `/etc/alpine-release` y
  `/etc/lsb-release`. Además `uname -a`, `/proc/version` y la libc (`ldd --version`;
  musl con `ldd` a secas o `/lib/ld-musl-*`).
- [ ] (b) `parsers/system.py`:
  - nombre, versión, `VERSION_ID`, `ID`/`ID_LIKE`, kernel y libc (glibc o musl, con su
    versión);
  - **con `VERSION_ID` cuando no hay `VERSION`** (Alpine);
  - respaldo a los ficheros de release si no hay `os-release` (CentOS 6).
- [ ] (c) Vista de sistema.
- [ ] (d) Pruebas: Alpine muestra `3.20.x`; CentOS 6 se identifica sin `os-release`;
  musl frente a glibc; las 10 imágenes coinciden con `facts.txt`.
- [ ] (e) Regresión: los nombres de distribución de Debian 12 y CentOS 7 coinciden con los
  de `legacy/`.

#### 3.2 Hardware: CPU, memoria y USB

- [ ] (a) Secciones `/proc/cpuinfo`, `/sys/devices/system/cpu/` (`online` y
  `topology/*`), `lscpu` si existe, `/proc/meminfo` y `/sys/bus/usb/devices/*/`
  (`idVendor`, `idProduct`, `product`, `manufacturer`, `bDeviceClass`). **Sin depender de
  `lsusb`.**
- [ ] (b) `parsers/hardware.py`:
  - arquitectura, sockets, núcleos y hilos (por topología de `/sys`, no por campos de x86);
  - fabricante y modelo en **x86_64** (`vendor_id` y `model name`) y en **ARM**
    (`CPU implementer`, `CPU part`, con una tabla mínima de fabricantes ARM);
  - flags y *bugs*;
  - memoria y swap totales;
  - dispositivos USB y concentradores.
- [ ] (c) Vista de hardware.
- [ ] (d) Pruebas:
  - en arm64, la muestra **no** da «0 cores» ni modelo vacío (fallo n.º 11 de
    `MVP.md`);
  - x86_64 con la VM `debian12-amd64`;
  - sin `/sys/bus/usb` se obtiene `na` y no `error`;
  - USB con datos sintéticos en `tests/test_parsers/data/usb/`.
- [ ] (e) Regresión: la memoria total coincide con la de `legacy/`.

#### 3.3 Paquetes instalados

- [ ] (a) Leer **las bases de datos directamente cuando existan**, sin depender del
  gestor:
  - `/var/lib/dpkg/status`;
  - `/lib/apk/db/installed`;
  - `/var/lib/pacman/local/*/desc`;

  y para RPM, `rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'`
  (RPM no tiene un formato de base de datos legible). Si no hay `rpm`, se marca
  `missing`.
- [ ] (b) `parsers/packages.py`:
  - nombre, versión **del paquete binario** (no la del fuente), arquitectura y gestor;
  - excluir y contar aparte los `gpg-pubkey`;
  - en dpkg, solo los paquetes en estado `install ok installed`.
- [ ] (c) Vista: el resumen muestra el total por gestor y el detalle la lista.
- [ ] (d) Pruebas: el recuento y los nombres coinciden **exactamente** con `facts.txt`
  en las 10 imágenes, incluidas **Fedora 44** (fallo n.º 14), **Alpine** (n.º 14),
  openSUSE y Arch, y Debian con la versión binaria.
- [ ] (e) Regresión: Debian 12 da 141 y CentOS 7 el mismo número que `rpm -qa` sin
  `gpg-pubkey`. `legacy/` daba 141 y 161.

#### 3.4 Almacenamiento

- [ ] (a) Secciones `/proc/partitions`, `/proc/self/mountinfo`, `/sys/block/*/`
  (`size`, `removable`, `dm/name` y `holders`), `/proc/swaps`, `df -P -k` y
  `lsblk -P -b -o NAME,TYPE,SIZE,MOUNTPOINTS` si existe. **Nunca por columnas
  separadas por espacios.**
- [ ] (b) `parsers/storage.py`:
  - discos, particiones, LVM y dm;
  - montajes con sistema de ficheros y opciones, **incluidos los montajes múltiples, los
    *bind* y los subvolúmenes btrfs**;
  - tamaño y uso **en bytes**, con el porcentaje calculado sobre bytes;
  - swap.
- [ ] (c) Vista: unidades legibles calculadas a partir de bytes.
- [ ] (d) Pruebas:
  - las muestras con el `lsblk` actual (Debian 12, Ubuntu 24.04, Rocky 9, Fedora 44)
    **no** fallan (n.º 13);
  - montaje *bind*;
  - btrfs (VM, si está disponible);
  - porcentaje de uso igual a `df` con ±1 punto;
  - CentOS 6 sin `lsblk`.
- [ ] (e) Regresión: CentOS 7, donde `legacy/` funcionaba, da los mismos montajes.

#### 3.5 Permisos peligrosos

- [ ] (a) Sección `find / -xdev \( -perm -4000 -o -perm -2000 -o -perm -0002 \)
  -printf …`, con alternativa sin `-printf` para busybox. Tiene tiempo máximo y límite
  de entradas, y emite propietario, grupo, modo y tipo. Además, una sección con
  `stat`/`ls -ln` de `/etc/passwd`, `/etc/group`, `/etc/shadow` y `/etc/gshadow`: es la
  comprobación recuperada de `dangerousperm()` (`legacy/gathering0.py:193-208`).
- [ ] (b) `parsers/permissions.py`:
  - directorios escribibles por todos sin *sticky bit*;
  - ficheros escribibles por todos;
  - SUID y SGID, indicando si son de root;
  - permisos de los 4 ficheros de cuentas frente a lo recomendado (644, 644, 400 o 000,
    400 o 000);
  - estado `timeout` con un recuento parcial si se agota el tiempo.
- [ ] (c) Vista, equivalente a `aridi.badfiles` pero dentro del informe. **No se escribe
  ningún fichero.**
- [ ] (d) Pruebas:
  - el SUID y el directorio de prueba del escenario aparecen;
  - en Debian 12 el recuento de SUID coincide con
    `find / -xdev -perm -4000 -type f | wc -l` de `facts.txt`;
  - un `timeout` forzado (límite de 0 s) da `status="timeout"`;
  - busybox (Alpine).
- [ ] (e) Regresión: las entradas SUID de `legacy/` en Debian 12 (9, incluida una de otro
  montaje) quedan en 8 por `-xdev`. Documentar la diferencia en la prueba.

### Específica

#### 3.6 Identidad y banners

- [ ] (a) Secciones `hostname`, `/proc/sys/kernel/hostname`,
  `/proc/sys/kernel/domainname`, `dnsdomainname` (si existe), `hostid` (si existe),
  `/etc/issue`, `/etc/issue.net`, `/etc/motd` y `/etc/motd.d/*`, con límite de tamaño.
- [ ] (b) `parsers/identity.py`: hostname, dominio (**el dominio, no el hostname**:
  fallo de `legacy/gathering2.py:35`), hostid y banners como texto no fiable (sin
  interpretarlo).
- [ ] (c) Vista: los banners con caracteres de control neutralizados.
- [ ] (d) Pruebas: un banner con secuencias ANSI y `<script>` sale neutralizado en la
  vista de texto; dominio vacío frente a configurado.
- [ ] (e) Regresión: el hostname coincide con el de `legacy/`.

#### 3.7 Usuarios y grupos

- [ ] (a) Secciones `/etc/passwd` y `/etc/group`, y **`/etc/shadow` filtrado en origen**:
  solo `usuario:prefijo` (`$y$`, `$6$`… hasta el segundo `$`, o `!`, `*` o vacío) y los
  campos de caducidad, con `awk` o `sed`. **El hash nunca sale de la máquina.** Lo mismo
  para `/etc/gshadow`.
- [ ] (b) `parsers/users.py`:
  - usuarios con uid, gid, gecos, home, shell, grupos y el algoritmo de la contraseña;
  - algoritmos: MD5 `$1$`, bcrypt `$2a$`/`$2b$`/`$2y$`, SHA-256 `$5$`, SHA-512 `$6$`,
    **yescrypt `$y$`**, gost-yescrypt `$gy$`, scrypt `$7$`;
  - **bloqueada** (`!` o `*`, incluido `!$6$…`), **sin contraseña** (vacío) y
    **desconocido**;
  - sin `shadow` legible, `denied`;
  - un miembro de grupo sin usuario **no falla**: se registra como «miembro sin cuenta
    local»;
  - el recuento por algoritmo es correcto (el contador MD5 de 2019 siempre valía 0).
- [ ] (c) Vista: resumen sin perder nombres (fallo de corte de línea de
  `legacy/gathering2.py:121-149`).
- [ ] (d) Pruebas:
  - `alice` con `$y$` en Debian 12, Ubuntu 24.04 y Fedora 44 **no** sale como «sin
    contraseña» (n.º 12);
  - Alpine con `kvm` como miembro sin usuario no falla (n.º 12);
  - cuenta bloqueada;
  - **ningún paquete del corpus contiene una cadena con forma de hash completo**: prueba
    con la expresión `\$[0-9a-z]+\$[^:]{20,}` sobre todos los `bundle.aridi`;
  - sin root, `denied`.
- [ ] (e) Regresión: el número de usuarios y grupos coincide con el de `legacy/` (18 y 38
  en Debian 12).

#### 3.8 Servicios

- [ ] (a) Secciones:
  - `systemctl list-units --all --plain --no-legend --no-pager --full`,
    `systemctl list-unit-files --no-legend --no-pager`, **solo si
    `/run/systemd/system` existe** (si no, `na`);
  - `runlevel`, `chkconfig --list` y `/etc/rc.d/rc*.d`;
  - OpenRC: `rc-status -a` o `/etc/runlevels`;
  - runit: `sv status /var/service/*` o `/etc/service`.
- [ ] (b) `parsers/services.py`: lista homogénea de servicios con gestor, nombre, estado
  activo y subestado (en marcha, fallido, otros), habilitado, y el *runlevel* o *target*.
- [ ] (c) Vista: los fallidos primero, después el recuento de los que están en marcha y
  el detalle por estado.
- [ ] (d) Pruebas:
  - VMs con systemd: el servicio que falla a propósito aparece como fallido;
  - CentOS 7 en contenedor (`systemctl` presente, sin systemd) da `na` para systemd y
    **no** un error (n.º 19), y usa `chkconfig`/`rc.d`;
  - Alpine con OpenRC;
  - CentOS 6 con SysV.
- [ ] (e) Regresión: no hay base útil en `legacy/`, porque en los contenedores fallaba.
  Comparar con `systemctl` en la VM.

#### 3.9 Red: interfaces, rutas, DNS y puertos en escucha

- [ ] (a) Secciones:
  - `ip -o link`, `ip -o addr` e `ip -o -6 route`, si existe `ip`;
  - **siempre** `/sys/class/net/*/` (`address`, `operstate`, `mtu`, `type`),
    `/proc/net/if_inet6`, `/proc/net/route`, `/proc/net/ipv6_route`, `/etc/hosts` y
    `/etc/resolv.conf`;
  - `/run/systemd/resolve/resolv.conf` si existe;
  - `/proc/net/tcp`, `tcp6`, `udp`, `udp6` y `raw`;
  - el mapa inodo → PID de `/proc/[0-9]*/fd/*` con `ls -l` o `readlink`.
- [ ] (b) `parsers/network.py`:
  - interfaces con MAC y todas sus direcciones v4 y v6, **con nombres `eth0@if5`
    normalizados** (n.º 15);
  - rutas v4 y v6;
  - DNS, incluido el *stub* de systemd-resolved con sus servidores reales;
  - `/etc/hosts` con IPv6;
  - **puertos en escucha TCP y UDP, v4 y v6**, con el proceso. UDP en escucha es estado
    `07` sin destino, no `LISTEN` (n.º 16).
  - Un uid o PID sin nombre no falla.
  - Relaciones: `local`, `dns_server` y `peer` desde `/etc/hosts`.
- [ ] (c) Vista de red y puertos.
- [ ] (d) Pruebas:
  - la muestra en red *bridge* con `eth0@ifN` **da** interfaces (n.º 15);
  - `[::]:8080` aparece como TCP en escucha (n.º 16);
  - `0.0.0.0:5353` aparece como UDP en escucha (n.º 16);
  - el proceso con uid 4242 no tumba el apartado (n.º 16);
  - un DNS IPv6 en `resolv.conf` no genera una IP nula (`ESTUDIO.md` §8);
  - coincide con `ss -lntup` de `facts.txt` donde exista.
- [ ] (e) Regresión: la vista `-oi` de `legacy/` en Debian 12 sin red (`127.0.0.1`, DNS
  `192.168.65.7`) aparece igual en las relaciones nuevas.

#### 3.10 Cortafuegos

- [ ] (a) Secciones `nft -j list ruleset` (o `nft list ruleset`), `iptables-save` e
  `ip6tables-save` (incluidas las variantes `-legacy` y `-nft` si existen),
  `firewall-cmd --list-all-zones` y `ufw status verbose`. Todas exigen root; sin root,
  `denied`.
- [ ] (b) `parsers/firewall.py`:
  - motor o motores detectados, y políticas por defecto;
  - reglas de aceptación **INPUT, OUTPUT y FORWARD**, v4 y v6, con origen, destino,
    puerto y protocolo;
  - zonas de firewalld y reglas de ufw;
  - relaciones `fw_allowed_in` y `fw_allowed_out` para IPs `/32` y `/128`.
- [ ] (c) Vista de cortafuegos.
- [ ] (d) Pruebas: nftables en las VMs (reglas del escenario, FORWARD incluido); firewalld
  en Rocky 9; contenedor sin `CAP_NET_ADMIN` da `denied` o `error` con motivo, no un
  apartado vacío.
- [ ] (e) Regresión: no hay base útil en `legacy/`, porque en los contenedores fallaba.

#### 3.11 Sincronización de hora (recuperada de `legacy/gathering2.py:260`)

- [ ] (a) Secciones `/etc/chrony.conf`, `/etc/chrony/chrony.conf`, `chronyc -n sources`,
  `/etc/ntp.conf`, `ntpq -pn`, `/etc/systemd/timesyncd.conf` y `timedatectl
  show-timesync --all`.
- [ ] (b) `parsers/timesync.py`: servicio de hora, servidores configurados y en uso, y la
  relación `ntp_server` (sin resolver nombres; los nombres se guardan como texto).
- [ ] (c) Vista.
- [ ] (d) Pruebas: chrony en Rocky 9 y timesyncd en Debian 12 (VMs); un contenedor sin
  servicio de hora da `na`.

### Volátil

#### 3.12 Procesos

- [ ] (a) Sección: para cada `/proc/[0-9]*`, `stat`, `status` (Uid y VmRSS) y `cmdline`
  (con `\0` convertido a espacio), con límite de procesos y bytes. Además `/proc/uptime`
  y `getconf CLK_TCK`.
- [ ] (b) `parsers/processes.py`, con la sección marcada `volatile`:
  - estado, usuario (tolerante a un uid sin nombre), RSS, *nice*, %CPU desde el arranque
    (fórmula de `legacy/gathering3.py:66-75`), zombis;
  - **top N con cualquier número de procesos**.
- [ ] (c) Vista: totales por estado, top 5 en el resumen y top 10 en el detalle.
- [ ] (d) Pruebas: un contenedor con 2 procesos **no** falla (n.º 17); el proceso con uid
  4242 aparece con el uid como nombre; zombi sintético en
  `tests/test_parsers/data/proc/`.
- [ ] (e) Regresión: no hay base útil en `legacy/` (fallaba en todas). Comparar con
  `ps` en la VM.

#### 3.13 Uso de CPU, memoria y disco

- [ ] (a) Secciones `/proc/meminfo`, `/proc/loadavg`, `/proc/stat` y `/proc/diskstats`,
  **dos muestras separadas por `sleep 1`**, además de `/proc/sys/fs/file-nr` y
  `/proc/sys/fs/inode-nr`.
- [ ] (b) `parsers/load.py` (`volatile`):
  - memoria usada, en búferes y libre, y swap;
  - carga a 1, 5 y 15 minutos;
  - CPU desde el arranque y en el último segundo;
  - **carga de disco en % correcta** (ms ocupados / 10 por segundo; el fallo n.º 13 de
    2019 dividía entre 1000);
  - lecturas y escrituras por segundo;
  - descriptores e inodos.
- [ ] (c) Vista.
- [ ] (d) Pruebas: % de disco con datos sintéticos conocidos; memoria igual a la de
  `legacy/` en Debian 12 (7934 MB en el mismo anfitrión).
- [ ] (e) Regresión: el uso de CPU y memoria cuadra con lo que daba `legacy/` en la misma
  muestra, con ±5 puntos por ser volátil.

#### 3.14 Sesiones e inicios de sesión

- [ ] (a) Secciones:
  - `utmpdump` de `/run/utmp`, `/var/log/wtmp` y `/var/log/btmp` (si existen);
  - `wtmpdb last` y `lastlog2` (sistemas sin `wtmp`);
  - `who`;
  - `last -F -w` y `lastb -F -w` como respaldo;
  - `journalctl _COMM=sshd -o short-iso --since -30d --no-pager`, con límite de líneas.
- [ ] (b) `parsers/sessions.py` (`volatile` para lo activo):
  - sesiones activas;
  - últimos accesos con recuentos de día, semana y mes;
  - accesos fallidos con IPs de origen v4 y v6;
  - relaciones `login_source` y `failed_login_source`.

  Las fechas se tratan en UTC, sin depender de la configuración regional (en 2019 se
  usaba `setlocale`). Un PID que ya no existe no falla.
- [ ] (c) Vista.
- [ ] (d) Pruebas: VMs con inicios reales y fallidos; un sistema con `wtmpdb`, si alguna
  imagen del corpus lo usa (Debian 13 u openSUSE; anotar cuál); fechas en otro idioma en
  datos sintéticos.
- [ ] (e) Regresión: no hay base útil en `legacy/`.

#### 3.15 Conexiones establecidas

- [ ] (a) Reutiliza las secciones de `/proc/net/*` y el mapa inodo → PID de 3.9.
- [ ] (b) `parsers/connections.py` (`volatile`): conexiones TCP y UDP v4 y v6 no en
  escucha, con proceso y estado, y relaciones `peer_in` y `peer_out` con el puerto y su
  nombre.
- [ ] Copiar `legacy/services.csv` a `src/aridi/data/services.csv` sin cambios y crear
  `src/aridi/ports.py`, que lo carga (formato `nombre|puerto|descripción`) para dar
  nombre a los puertos en 3.9 y 3.15. Así no se pierde al borrar `legacy/` (4.2); se
  regenerará en 7.1. **Pruebas:** carga del fichero y puerto desconocido sin error.
- [ ] (c) Vista.
- [ ] (d) Pruebas: una conexión sintética v6 y v4; un uid sin nombre.

### Carving y vecinos

#### 3.16 IPs y nombres en `/etc`, `/var/log` y journald

- [ ] (a) Secciones:
  - `grep -rIEoHn` de IPv4 e IPv6 sobre `/etc` y `/var/log`, **solo ficheros de texto**
    (`-I`), con límite de tamaño por fichero y de líneas totales, emitiendo
    `fichero:línea:coincidencia`;
  - `journalctl --since -7d -o cat --no-pager`, con límite de líneas y filtrado por IP
    en origen.
- [ ] (b) `parsers/carving.py`:
  - trasladar los filtros de `legacy/gathering4.py:36-55` (169.254, multicast, 0.x,
    `.0`, versiones, prefijos de red);
  - añadir IPv6;
  - relación `named_in_file` con fichero y línea truncada;
  - FQDN encontrados en `/etc`, **guardados sin resolver** (la resolución DNS queda
    aparcada, `docs/CAMBIO.md`).
- [ ] (c) Vista.
- [ ] (d) Pruebas: `/etc` sintético con IPs válidas, versiones y redes; un fichero
  binario se ignora; respeta el límite; contrastar con `legacy/` («2 ips found in /etc»
  en Debian 12).
- [ ] (e) Regresión: las mismas 2 IPs que `legacy/` en Debian 12.

#### 3.17 Vecinos (descubrimiento pasivo)

- [ ] (a) Secciones `/proc/net/arp` e `ip -6 neigh` / `ip neigh`.
- [ ] (b) `parsers/neighbours.py`: IP v4 y v6, MAC, interfaz y estado; relación
  `neighbour`. **No genera ningún tráfico.**
- [ ] (c) Vista.
- [ ] (d) Pruebas: VM con vecinos; contenedor sin `ip` (solo `/proc/net/arp`).

### Transversal de la fase 3

#### 3.18 Mapa de relaciones, límites y huecos

- [ ] `src/aridi/relations.py`: consolida las relaciones de todas las áreas por IP, con
  sus papeles enumerados, y genera la vista «infraestructura» (`Local machine` /
  `Remote`), equivalente a `legacy/ -oi`.
- [ ] Pruebas: cada papel de `docs/FORMATO.md` sale de al menos una muestra o dato
  sintético; v4 y v6 se ordenan sin error (en 2019 mezclarlas, o tener una clave nula,
  rompía `-oi`).
- [ ] **Regresión global:** ejecutar `tests/run.sh all` y comprobar que **no hay ninguna
  muestra del corpus con un área en `error`**. Cualquier `error` es un fallo que
  corregir o un `na`, `missing` o `denied` mal clasificado.
- [ ] Medir y anotar en `tests/corpus/README.md` la duración del script por muestra. Si
  alguna supera los 60 s, abrir una tarea para revisar los límites de esa área.

**Criterio de aceptación de la fase 3:**

- las 17 áreas producen datos que coinciden con `facts.txt` en todo el corpus;
- todos los fallos n.º 11 a 21 de `docs/MVP.md` tienen una prueba que pasa;
- ningún paquete contiene hashes;
- ninguna muestra deja rastro;
- `aridi report` en modo local funciona de principio a fin en las 10 imágenes y las 3
  VMs;
- `tests/run.sh all` pasa, incluida la línea base de `legacy/`.

---

## Fase 4: paridad y retirada de `legacy/`

**Depende de:** fase 3 completa.

### 4.1 Comprobación de paridad

- [ ] Crear `tests/parity.md`: una tabla con **cada funcionalidad numerada de
  `docs/MVP.md`** (1-10 entregadas, 11-21 a medias, las «implementadas, sin verificar» y
  las «abandonadas») y, para cada una, el área del colector nuevo que la cubre, la prueba
  que lo demuestra o la indicación de que se abandona según `docs/CAMBIO.md` (grafo,
  barrido ARP activo, escaneo desde la máquina, resolución DNS de FQDN, vista
  `view_vulns`).
- [ ] Verificar uno por uno los puntos de `tests/parity.md` ejecutando las pruebas
  indicadas. **No se marca nada por lectura de código.**
- [ ] **Regresión final:** ejecutar `legacy/` y el colector nuevo sobre las mismas
  muestras (Debian 12 y CentOS 7, red *bridge* y sin red) y comprobar que todo lo que
  `legacy/` daba bien lo da también el nuevo, con los mismos valores.

### 4.2 Recuperar lo que `legacy/` aporta y retirarlo

- [ ] Comprobar que `src/aridi/data/services.csv` (copiado en 3.15) es idéntico a
  `legacy/services.csv` (`cmp`) antes de borrar `legacy/`.
- [ ] Comprobar con `grep -r legacy src tests collector` que nada fuera de `legacy/`
  depende de él, salvo `tests/legacy/`.
- [ ] `git rm -r legacy/ tests/legacy/` y quitar el subcomando `legacy` de
  `tests/run.sh`.
- [ ] Ejecutar `tests/run.sh all`.

### 4.3 Documentación (lo que deja de ser cierto al retirar `legacy/`)

- [ ] `docs/MVP.md`: reescribirlo para el colector nuevo con las mismas categorías
  (entregada, entregada con limitaciones, a medias, implementada sin verificar,
  abandonada). *Cómo se ha medido* pasa a ser las pruebas automáticas sobre el corpus
  (`tests/run.sh`). Sección «Fuera de lo entregado» actualizada: el central todavía no
  existe.
- [ ] `docs/ARCHITECTURE.md`:
  - la parte del colector pasa a describir el script, el núcleo, el formato
    (`docs/FORMATO.md`), las pruebas y el corpus;
  - lo de 2019 queda en una sección histórica breve;
  - registro de decisiones ampliado con las de `docs/CAMBIO.md` y las de planificación
    de este `TODO.md`.
- [ ] `docs/IDEA.md`:
  - *Funcionalidad principal* 1 (recogida en bruto más interpretación), 3 (pasivo en la
    máquina y escaneo desde el central) y 5 (modo local en dos pasos, con Python 3.12 en
    algún equipo);
  - *Principios*: «cero dependencias» acotado al colector;
  - recorrido D en dos pasos;
  - *Glosario*: paquete en bruto, intérprete, núcleo, hueco con sus estados, red
    autorizada.
- [ ] `docs/FUTURE.md`:
  - renumerar según las fases de este `TODO.md`;
  - 1.2-1.5 y 1.10 hechas;
  - 1.6 precisada (RHEL 6 y contenedores sin Python, con el script);
  - 4.1 reescrita (pasivo y escaneo desde el central);
  - añadir a las ideas aparcadas «guardar el paquete en bruto para reinterpretarlo» (si
    5.0 no lo adopta) y «resolución DNS de FQDN».
- [ ] `README.md` (en inglés):
  - instalación y uso del modo local en dos pasos (`sh aridi-collect.sh > host.aridi`;
    `pip install .` y `aridi report host.aridi`);
  - requisitos (POSIX `sh` en la máquina; Python 3.12 donde se interpreta);
  - pruebas (`tests/run.sh all`);
  - qué se ha perdido respecto a 2019 (`docs/CAMBIO.md`, *Qué se pierde*);
  - quitar las referencias a `legacy/`;
  - conservar el título y la frase original del autor.
- [ ] `CLAUDE.md`:
  - quitar todo lo de `legacy/` y la regla de Python 3.6;
  - reglas nuevas: el script es POSIX `sh` (sin *bashisms*), nunca escribe en disco y
    filtra lo sensible en origen;
  - el núcleo nunca importa Django ni nada ajeno (prueba de 0.4);
  - el formato es un contrato versionado (`docs/FORMATO.md`);
  - los papeles de relación son códigos, no frases;
  - una área nueva se hace con el patrón (a)-(e) de la fase 3;
  - el corpus es la única forma de verificar.

**Criterio de aceptación de la fase 4:**

- `tests/parity.md` está completo y verificado;
- `legacy/` no existe;
- `tests/run.sh all` pasa;
- `MVP.md`, `ARCHITECTURE.md`, `IDEA.md`, `FUTURE.md`, `README.md` y `CLAUDE.md`
  describen el colector nuevo, y ninguno menciona como presente algo de 2019.

---

## Fase 5: componente central, inventario

**Depende de:** fase 4 (colector con paridad), por la regla de `docs/CAMBIO.md`: el formato
se fija antes de guardar las primeras fotografías.

### 5.0 Decisiones previas (bloqueantes)

- [ ] **[decisión]** Escalada de privilegios. Las opciones son:
  1. `sudoers` con `aridi ALL=(root) NOPASSWD: /bin/sh -s`, que equivale a root completo
     para la cuenta `aridi` y lo documenta;
  2. script instalado con una ruta fija (`/usr/local/libexec/aridi-collect.sh`, de root
     y en solo lectura) con una regla de `sudoers` limitada a esa ruta, lo que deja
     rastro y requiere actualizarlo;
  3. sin `sudo`, recogida como usuario normal con huecos `denied`.

  Anotar la decisión en `docs/CAMBIO.md` (*Seguridad de destino* y *Riesgos*).
- [ ] **[decisión]** ¿Se guarda el paquete en bruto en el central? Permitiría
  reinterpretarlo, a cambio de más datos sensibles. Anotarlo en `docs/CAMBIO.md` (modelo
  de datos).

### 5.1 Proyecto Django

- [ ] Crear `src/aridi_central/` con `manage.py`, `settings.py`, `urls.py`, `wsgi.py` y
  las aplicaciones `inventory`, `collection`, `changes`, `discovery` y `web`
  (`changes` y `discovery` vacías por ahora).
- [ ] `settings.py`:
  - `SECRET_KEY`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS` y `ARIDI_DB_PATH` desde
    variables de entorno, con error si falta `SECRET_KEY` en producción;
  - SQLite en `ARIDI_DB_PATH`, con `PRAGMA journal_mode=WAL`, `busy_timeout` y
    `foreign_keys=ON` mediante la señal `connection_created`;
  - `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_PROXY_SSL_HEADER` (detrás del
    proxy con TLS);
  - logging a stdout con el módulo `logging`.
- [ ] Ampliar `tests/test_core_isolation.py` para comprobar que **`src/aridi` no importa
  `aridi_central` ni `django`**.
- [ ] `tests/run.sh central`: construye una imagen de pruebas a partir de
  `python:3.12-slim` con `requirements/central.txt` y ejecuta
  `python src/aridi_central/manage.py check --deploy` y `manage.py test`.
- [ ] Pruebas: arranque con variables mínimas; WAL activo (consultar `PRAGMA
  journal_mode`); `check --deploy` sin errores con la configuración de producción.

### 5.2 Modelo de inventario

- [ ] `inventory/models.py`:
  - `Group` (nombre, programación por defecto);
  - `Machine` (nombre, `ssh_target`, `ssh_port`, `proxy_jump`, grupos, programación
    propia, activa; **sin credenciales**);
  - `Snapshot` (máquina, `collected_at`, `origin` = ssh/import/on_demand,
    `schema_version`, `data` JSON, `result` = complete/gaps/failed, `failure_reason`);
  - `Gap` (fotografía, área, estado, motivo).

  Migración inicial.
- [ ] Modelos de índice: `SnapshotPackage(name, version, arch, manager)`,
  `SnapshotUser(name, uid, shell, password_algo, groups)`,
  `SnapshotPort(proto, family, address, port, process)`,
  `SnapshotService(manager, name, state, enabled)` y `Relation(ip, role, detail)`, con
  índices de base de datos sobre los campos de búsqueda. **Solo se indexan las áreas no
  volátiles.** Migración.
- [ ] `inventory/indexing.py`: de `Snapshot.data` a las filas de índice y de `Gap`.
  **Pruebas** con las fotografías de 3 muestras del corpus: recuentos iguales a los de
  la fotografía; los volátiles no se indexan.
- [ ] Pruebas de migración: `manage.py makemigrations --check` no genera nada nuevo.

### 5.3 Importación de recogidas locales

- [ ] `inventory/importing.py`: recibe un paquete en bruto, lo valida e interpreta con el
  núcleo (`aridi.interpret`), asocia la fotografía a una máquina por `machine_id` (y, si
  no lo hay, por hostname, con confirmación) y la guarda e indexa.
- [ ] Comando `manage.py aridi_import <fichero> [--machine NOMBRE]`.
- [ ] Vista web de subida (solo el rol de administración), con límite de tamaño.
- [ ] Pruebas: importar cada paquete del corpus; rechazar una versión desconocida o un
  paquete truncado; importar dos veces la misma recogida no la duplica.

### 5.4 Recogida por SSH

- [ ] `collection/ssh.py`: lanza
  `ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=… [-J proxy] -p
  puerto destino '<comando según 5.0>'`, con `collector/aridi-collect.sh` por stdin,
  límite de bytes y de tiempo, y captura de stderr para el motivo de fallo. **Nunca con
  `shell=True`**, y con argumentos validados (`ssh_target` sin espacios ni opciones que
  empiecen por `-`).
- [ ] Una recogida fallida (sin conexión, clave de *host* desconocida, `sudo` denegado,
  tiempo agotado) se guarda como `Snapshot(result="failed", failure_reason=…)`.
- [ ] Pruebas unitarias con un `ssh` falso (un script en `PATH` de prueba): argumentos
  correctos, inyección rechazada, *timeout* y salida truncada.
- [ ] Prueba de integración en `tests/run.sh central`: un contenedor `debian:12` con
  `openssh-server`, clave de prueba y regla de `sudo` según 5.0. El central recoge de
  él por SSH, y la fotografía tiene `result="complete"` o `gaps`.

### 5.5 Cola, trabajador y programación

- [ ] `collection/models.py`: `Job` (tipo `collect` o `scan`, máquina o grupo, estado
  `queued`/`running`/`done`/`failed`, intentos, fechas, motivo) y `Schedule` (por
  máquina o grupo: cada N horas o diario a una hora UTC; activa).
- [ ] Comando `manage.py aridi_worker`:
  - bucle que toma trabajos con bloqueo optimista (`UPDATE … WHERE state='queued'`);
  - concurrencia limitada por `ARIDI_MAX_SSH` (hilos con semáforo);
  - reintentos con espera;
  - genera los trabajos programados al llegar su hora;
  - parada limpia con SIGTERM;
  - solo librería estándar y Django, **sin Celery ni Redis**.
- [ ] Recogida a demanda desde la web: encola un `Job` para una máquina, varias o un
  grupo.
- [ ] Pruebas:
  - dos trabajadores simultáneos no toman el mismo trabajo;
  - la programación genera exactamente un trabajo por periodo;
  - SIGTERM con trabajos en curso los deja `failed` o reintentables y no `running` para
    siempre;
  - el límite de concurrencia se respeta.

### 5.6 Interfaz web e inventario

- [ ] Autenticación con `django.contrib.auth`: inicio y cierre de sesión. Grupos
  **administración** y **consulta** creados por migración de datos, con sus permisos.
- [ ] Vistas en `web/` (plantillas en el servidor, sin JavaScript de terceros):
  - lista de máquinas (última fotografía, resultado, número de huecos, fecha);
  - detalle de máquina (áreas en resumen y detalle, a partir de la fotografía; los
    banners y las líneas de registro escapados);
  - histórico de fotografías;
  - huecos de la máquina con «desde cuándo»;
  - gestión de máquinas, grupos y programación (solo administración).
- [ ] Pruebas por vista y por rol:
  - consulta no puede crear, editar ni lanzar recogidas (403);
  - anónimo redirige al inicio de sesión;
  - CSRF exigido en los POST;
  - un banner con `<script>` sale escapado.

### 5.7 Búsqueda en el parque

- [ ] Vista y formulario de búsqueda por paquete (nombre y versión opcional), puerto
  (protocolo y número), usuario, servicio e IP de relación, sobre la **última
  fotografía** de cada máquina. Cada resultado muestra la fecha de esa fotografía.
- [ ] Pruebas con fotografías del corpus importadas: «¿qué máquinas tienen
  `openssh-server`?», «¿dónde escucha el 8080?», «¿dónde existe `alice`?».

### 5.8 Contenedor y despliegue

- [ ] `Dockerfile`:
  - `python:3.12-slim` fijado por *digest*;
  - `apt-get install --no-install-recommends openssh-client sqlite3`;
  - usuario sin privilegios `aridi`;
  - `pip install --require-hashes -r requirements/central.txt` y `pip install --no-deps .`;
  - `collector/aridi-collect.sh` copiado a una ruta conocida;
  - sin claves ni secretos en la imagen.
- [ ] `compose.yaml`:
  - servicios `web` (`gunicorn aridi_central.wsgi`, escuchando en `127.0.0.1:8000` o en
    la red del proxy) y `worker` (`manage.py aridi_worker`);
  - volumen `/data` para SQLite;
  - montaje del socket del `ssh-agent` (`SSH_AUTH_SOCK`) y de `known_hosts` y
    `ssh_config` en solo lectura;
  - variables de entorno;
  - `healthcheck`;
  - `restart: unless-stopped`.
- [ ] Prueba de humo en `tests/run.sh central`: `docker compose up`, crear un
  superusuario, inicio de sesión, recogida de la máquina SSH de prueba de 5.4,
  `docker compose down`.
- [ ] Documentar las copias de seguridad (`sqlite3 /data/aridi.db ".backup …"`) y la
  restauración, y probarlas una vez en la prueba de humo.

### 5.9 Documentación de la fase

- [ ] `README.md` (en inglés):
  - instalación del central con `docker compose`;
  - preparación de una máquina: usuario, clave en el agente, `known_hosts` y regla de
    `sudo` según 5.0;
  - copias de seguridad;
  - que el TLS lo pone el proxy.
- [ ] `docs/ARCHITECTURE.md`: secciones del central (visión, stack con versiones reales
  de `requirements/central.txt`, modelo de datos, interfaces, trabajador, seguridad,
  despliegue).
- [ ] `docs/MVP.md`: añadir las funcionalidades del inventario central con sus pruebas.
- [ ] `CLAUDE.md`:
  - reglas del central: sin credenciales en la base de datos, `ssh` siempre con lista de
    argumentos y `BatchMode`, plantillas sin `|safe` sobre datos de máquinas;
  - nuevas dependencias solo con decisión del usuario y con hash.
- [ ] `docs/FUTURE.md`: marcar la etapa de inventario como hecha.

**Criterio de aceptación de la fase 5:**

- con `docker compose up`, un administrador da de alta la VM `debian12-arm64` de Lima,
  la recoge a demanda y por programación, ve su ficha con los huecos e importa un paquete
  hecho en local;
- la búsqueda encuentra paquetes, puertos y usuarios;
- el rol de consulta no puede modificar nada;
- `tests/run.sh all` pasa.

---

## Fase 6: cambios y alertas

**Depende de:** fase 5.

### 6.1 Comparación de fotografías

- [ ] `changes/diff.py`: compara dos fotografías área por área (elementos añadidos,
  quitados y cambiados) con clave estable por área (paquete por nombre y arquitectura,
  puerto por protocolo, dirección y puerto, usuario por nombre…). **Un área que pasa de
  `ok` a otro estado se informa como «dejó de poder verse», no como «todo desapareció».**
  Los volátiles se comparan solo si se pide.
- [ ] Vista web de comparación entre dos fotografías cualesquiera de una máquina.
- [ ] Pruebas con pares de fotografías sintéticas por área, más el caso «de `ok` a
  `denied`».

### 6.2 Reglas de serie y ajustes

- [ ] `changes/rules.py` con las reglas de serie de `docs/IDEA.md`, cada una con una
  gravedad por defecto:
  - usuario nuevo con shell de acceso, uid 0 o miembro de `sudo`/`wheel`/`admin`;
  - puerto nuevo en escucha;
  - servicio que pasa a fallido;
  - binario SUID o SGID nuevo;
  - cambio de kernel;
  - disco por encima del umbral (90 % por defecto);
  - permisos de `passwd` o `shadow` peor que lo recomendado (de 3.5);
  - **máquina que no responde** (N recogidas fallidas seguidas o sin fotografía en dos
    periodos).

  La lista exacta está pendiente según `IDEA.md`: **[decisión]** confirmarla con el
  usuario antes de implementar.
- [ ] `RuleOverride` por máquina o grupo: silenciar, cambiar la gravedad o cambiar el
  umbral. El ajuste más específico gana.
- [ ] Pruebas: cada regla, con un par de fotografías que la dispara y otro que no; la
  precedencia de los ajustes; los volátiles no disparan nada salvo el disco, que es
  estable.

### 6.3 Alertas

- [ ] `changes/models.py`: `Alert` (máquina, regla, gravedad, detalle, fotografías
  implicadas, estado nueva/vista/resuelta). La evaluación se hace al guardar cada
  fotografía (en el trabajador y en la importación).
- [ ] Vistas: lista de alertas filtrable y detalle con la comparación; marcar como vista o
  resuelta (administración).
- [ ] Pruebas: una recogida con cambios crea las alertas esperadas; la misma alerta no se
  duplica en recogidas sucesivas sin cambio nuevo.

### 6.4 Canales de aviso

- [ ] **[decisión]** Confirmar con el usuario qué canales se implementan (`IDEA.md` los
  deja pendientes). Propuesta: correo y webhook genérico JSON; el chat con un webhook
  entrante compatible con Slack o Mattermost.
- [ ] `changes/channels.py`:
  - correo con `django.core.mail` (SMTP por variables de entorno);
  - webhook con `urllib.request` (POST JSON, *timeout*, reintentos);
  - filtro por gravedad mínima y por grupo.
- [ ] Pruebas: correo con el backend `locmem`; webhook contra un `http.server` local en
  la prueba (recibe el JSON esperado); fallo del destino con reintento sin bloquear el
  trabajador.

### 6.5 Mapa de relaciones en la web

- [ ] Vista por máquina con las relaciones de la última fotografía (IP, papeles, detalle),
  agrupadas como la vista de infraestructura. Diagrama SVG generado en el servidor con
  plantillas, sin librerías de terceros: máquina, subredes, pasarela, IPs. Sustituye al
  `--graph` de 2019.
- [ ] Pruebas: la vista renderiza con v4 y v6 y con más de 200 IPs (con límite y
  paginación).

### 6.6 Documentación de la fase

- [ ] `docs/MVP.md`, `docs/ARCHITECTURE.md` (app `changes`, reglas y canales),
  `README.md` (configuración de avisos) y `docs/FUTURE.md` (etapa de alertas hecha).

**Criterio de aceptación de la fase 6:**

- sobre la VM de Lima, añadir un usuario con shell y abrir un puerto produce, en la
  siguiente recogida, dos alertas visibles en la web y entregadas al webhook de prueba;
- silenciar la regla para esa máquina las evita;
- apagar la VM genera la alerta de «no responde»;
- `tests/run.sh all` pasa.

---

## Fase 7: exploración de red desde el central

**Depende de:** fase 5. Puede hacerse antes que la fase 6 si interesa.

### 7.1 `services.csv` regenerado

- [ ] `tools/build_services.py` (solo librería estándar): descarga el registro de puertos
  de IANA (`service-names-port-numbers.csv`) y genera
  `src/aridi/data/services.csv` con `nombre|puerto|protocolo|descripción`, más una
  cabecera con la fuente y la fecha. Sustituye al fichero heredado de 4.2.
- [ ] Pruebas: el cargador del núcleo lee el formato nuevo; los nombres de 3.15 siguen
  resolviéndose.

### 7.2 Redes autorizadas

- [ ] `discovery/models.py`: `AuthorizedNetwork` (CIDR v4/v6, descripción, quién la
  autorizó y cuándo, activa) y `ScanResult` (IP, protocolo, puerto, estado, fecha,
  trabajo).
- [ ] Gestión en la web (solo administración), con validación del CIDR y un tamaño máximo
  configurable (por ejemplo, /16 en v4 y /112 en v6).
- [ ] Pruebas: un CIDR inválido o demasiado grande se rechaza; consulta no puede
  gestionar redes.

### 7.3 Escáner

- [ ] `discovery/scanner.py`:
  - TCP *connect* v4 y v6 con `socket`;
  - grupo de hilos con límite;
  - *timeout* por conexión y límite de conexiones por segundo;
  - lista de puertos configurable: la lista de los más comunes por defecto y la completa
    a petición.

  **Comprueba antes de cada conexión que la IP está dentro de una `AuthorizedNetwork`
  activa**, y nunca escanea IPs que vengan solo de relaciones (registros, carving) fuera
  del perímetro.
- [ ] Trabajo `scan` en `aridi_worker` y en `Schedule`, **desactivado por defecto**.
- [ ] Integración de los resultados: los puertos abiertos pasan a `Relation` con el papel
  `scan_open_port` y a la vista de la máquina, si la IP corresponde a una máquina
  inventariada.
- [ ] Pruebas:
  - un servidor local en la red autorizada se detecta;
  - **una IP fuera de toda red autorizada no recibe ninguna conexión** (se comprueba con
    un `socket` falso que registra los intentos);
  - se respeta el límite de velocidad;
  - el escaneo no corre si no está activado.

### 7.4 Documentación y cierre del cambio

- [ ] **[decisión]** Antes de publicar (en GitHub o en cualquier sitio) la versión nueva,
  confirmar la autoría y los derechos (`docs/ESTUDIO.md` §10, `docs/CAMBIO.md`,
  *Riesgos*).
- [ ] `docs/IDEA.md`, `docs/MVP.md`, `docs/ARCHITECTURE.md` (app `discovery`) y
  `README.md`:
  - el escaneo se hace desde el central;
  - el contenedor necesita alcanzar las redes autorizadas;
  - aviso legal: escanear solo redes autorizadas.
- [ ] `docs/FUTURE.md`: todas las etapas de `docs/CAMBIO.md` hechas; las ideas aparcadas
  quedan como futuro real.
- [ ] `docs/CAMBIO.md`: añadir al principio una nota «Cambio completado el <fecha>» que
  enlace a este `TODO.md`.

**Criterio de aceptación de la fase 7:**

- con una red autorizada que contiene la máquina SSH de prueba, un escaneo programado
  encuentra su puerto 22 y lo muestra en su ficha;
- una IP de los registros fuera del perímetro nunca se toca (prueba);
- `tests/run.sh all` pasa;
- toda la documentación describe el sistema completo.

---

## De `docs/CAMBIO.md` a las fases

| Punto de `docs/CAMBIO.md` | Fase que lo entrega |
|---|---|
| **Reparto:** `aridi.py` → abandonar al llegar a la paridad | 0.2 (a `legacy/`), 4.2 (se borra) |
| **Reparto:** `gathering0.py` → reescribir (detección de capacidades, huecos) | 2.2 (estados por sección), 2.3 (`interpret.py`) |
| **Reparto:** `gathering1.py` → reescribir | 3.1, 3.2, 3.3, 3.4, 3.5 |
| **Reparto:** `gathering2.py` → reescribir | 3.6, 3.7, 3.8, 3.9, 3.10, 3.11 |
| **Reparto:** `gathering3.py` → reescribir | 3.12, 3.13, 3.14, 3.15 |
| **Reparto:** `gathering4.py` → reescribir (con journald y límites) | 3.16 |
| **Reparto:** `scan.py` → reescribir | 3.17 (pasivo), 7.2-7.3 (activo desde el central) |
| **Reparto:** `graph.py` → abandonar; mapa en la web | 4.2 (se borra), 6.5 (mapa web) |
| **Reparto:** `reporting.py` → modelo más vistas | 2.3 (`model.py`, `views/text.py`), 3.18 (relaciones) |
| **Reparto:** `utils.py` → abandonar | 4.2 (se borra); IPs v4 y v6 en 3.9 |
| **Reparto:** `services.csv` → adaptar | 3.15 (se conserva en `src/aridi/data/`), 4.2 (se comprueba antes de borrar), 7.1 (se regenera) |
| **Reparto:** `__init__.py` → abandonar | 0.3 (`pyproject.toml`), 4.2 (se borra) |
| **Reparto:** `LICENSE` → conservar; confirmar la autoría | 0.3 (licencia en `pyproject.toml`), 7.4 ([decisión] de autoría) |
| **Reparto:** `README.md`, `CLAUDE.md` → adaptar | 0.6, 4.3, 5.9, 6.6, 7.4 |
| **Reparto:** historia de git → conservar | 0.2 (`git mv`), 4.2 (`git rm`) |
| **Reparto:** componente central → nuevo | Fases 5, 6 y 7 |
| **Destino:** script POSIX `sh`, sin escrituras, filtrado en origen, límites | 2.2, 3.x (a), 3.7 (filtrado de `shadow`) |
| **Destino:** núcleo en Python 3.12 solo con la librería estándar; nunca importa Django | 0.3, 0.4 (prueba de aislamiento), 5.1 (ampliada) |
| **Destino:** Django 5.2 LTS, `--require-hashes`, gunicorn 23 | 0.3 (`requirements/central.txt`), 5.1, 5.8 |
| **Destino:** SQLite en modo WAL; migraciones Django; copias con `.backup` | 5.1, 5.2, 5.8 |
| **Destino:** SSH con OpenSSH y `ssh-agent`, sin claves guardadas | 5.4, 5.8 |
| **Destino:** imagen `python:3.12-slim` y `docker compose` (`web` y `worker`) | 5.8 |
| **Destino:** estructura (`collector/`, `src/aridi/…`, `src/aridi_central/…`, `tests/corpus/`) | 0.4, 2.3, 3.x, 5.1 |
| **Destino:** paquete en bruto v1 versionado | 2.1, 2.2, 2.3 (`bundle.py`) |
| **Destino:** fotografía JSON v1 versionada | 2.1, 2.3 (`model.py`) |
| **Destino:** CLI `aridi report`/`interpret`/`validate` y códigos de salida | 0.4, 2.3 |
| **Destino:** entidades `Machine`, `Group`, `Snapshot`, índices, `Gap` | 5.2 |
| **Destino:** `Job` y `aridi_worker`, sin Celery | 5.5 |
| **Destino:** `Rule`, `RuleOverride`, `Alert`, `Channel` | 6.2, 6.3, 6.4 |
| **Destino:** `AuthorizedNetwork`, `ScanResult` | 7.2, 7.3 |
| **Destino:** usuarios y roles (administración y consulta) | 5.6 |
| **Destino:** decisión menor, no guardar el paquete en bruto (revisable) | 5.0 ([decisión]) |
| **Destino:** configuración por variables de entorno | 5.1, 5.8 |
| **Destino:** errores siempre declarados (`Gap`), códigos de salida | 2.3, 3.18, 5.2 |
| **Destino:** logging con el módulo `logging` | 2.3, 5.1 |
| **Destino:** concurrencia limitada en el trabajador | 5.5 |
| **Destino:** pruebas con `unittest` sobre el corpus y `manage.py test` | 0.5, fase 1, 3.x (d), 5.1 |
| **Seguridad:** credenciales fuera de la base de datos y `known_hosts` estricto | 5.4, 5.8 |
| **Seguridad:** escalada con `sudo` (decisión abierta) | 5.0 ([decisión]) |
| **Seguridad:** datos sensibles (filtrado, roles, volumen) | 3.7, 5.6, 5.8 |
| **Seguridad:** datos no fiables escapados | 3.6, 5.6 |
| **Seguridad:** escaneo solo hacia redes autorizadas | 7.2, 7.3 |
| **Qué se pierde:** contarlo en la documentación de usuario | 4.3 (`README.md`) |
| **Migración:** `legacy/` hasta la paridad, sin datos ni usuarios | 0.2, 4.1, 4.2 |
| **Ruta:** etapa 0 (base y corpus) | Fases 0 y 1 |
| **Ruta:** etapa 1 (colector nuevo, paridad, borrar `legacy/`) | Fases 2, 3 y 4 |
| **Ruta:** etapa 2 (inventario central) | Fase 5 |
| **Ruta:** etapa 3 (cambios y alertas) | Fase 6 |
| **Ruta:** etapa 4 (exploración de red) | 3.17 (pasivo, adelantado) y fase 7 |
| **Riesgo:** punto de no retorno, formato versionado antes de guardar fotografías | 2.1 (política de versiones), dependencia de la fase 5 respecto de la 4 |
| **Riesgo:** portabilidad de `sh` | 1.1 (10 imágenes), 2.2 (pruebas en `dash`, `bash`, busybox y CentOS 6) |
| **Riesgo:** escalada con `sudo` | 5.0 |
| **Riesgo:** datos sensibles en el central | 3.7, 5.6, 5.8 |
| **Riesgo:** alcance de red del contenedor | 5.9, 7.4 (documentación) |
| **Riesgo:** estimaciones (la etapa 1 puede crecer) | 3.18 (medición de tiempos); criterio de aceptación por subfase |
| **Riesgo:** autoría y licencia | 7.4 ([decisión]) |
| **Documentos:** `docs/IDEA.md` | 4.3, 7.4 |
| **Documentos:** `docs/MVP.md` | 0.2 (se remite desde `legacy/README.md`), 4.3, 5.9, 6.6, 7.4 |
| **Documentos:** `docs/FUTURE.md` | 4.3, 5.9, 6.6, 7.4 |
| **Documentos:** `docs/ARCHITECTURE.md` | 4.3, 5.9, 6.6, 7.4 |
| **Documentos:** `README.md` y `CLAUDE.md` | 0.6, 4.3, 5.9, 6.6, 7.4 |
| **Falta en el repositorio:** `.gitignore`, `pyproject.toml` | 0.3 |
| **Falta en el repositorio:** `Dockerfile`, `compose.yaml` | 5.8 |
| **Falta en el repositorio:** CI | 0.5 (decidido: `tests/run.sh` en local) |
