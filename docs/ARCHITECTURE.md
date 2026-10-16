# aridi: arquitectura actual

> Este documento describe la arquitectura **que existe** en la rama `rewrite` al cerrar la
> fase 4 de [`TODO.md`](../TODO.md) (2026-10-16): el colector nuevo, que ya funciona en
> modo local. La arquitectura de destino, con el componente central, está decidida en
> [`CAMBIO.md`](CAMBIO.md) y **todavía no existe**. El contrato de datos está en
> [`FORMATO.md`](FORMATO.md). Los hechos vienen de leer el código y de ejecutar
> `tests/run.sh`; las referencias van en la forma `archivo:línea` o con el nombre de la
> función. Lo que no se puede probar va marcado como **suposición**.

---

## Visión general

aridi es hoy **un colector en dos pasos que se usa en modo local**:

1. **Recoger:** un script POSIX `sh` (`collector/aridi-collect.sh`) se ejecuta en la
   máquina inventariada, lee lo que puede y escribe un **paquete en bruto** por la salida
   estándar. No escribe nada en disco.
2. **Interpretar:** el **núcleo** en Python 3.12 (`src/aridi/`), sin dependencias
   ajenas, lee ese paquete en cualquier equipo y produce una **fotografía** (JSON) o un
   informe de texto.

```
 Máquina inventariada                         Cualquier equipo con Python 3.12
 ┌──────────────────────────────┐             ┌─────────────────────────────────────┐
 │ sh aridi-collect.sh          │  paquete    │ aridi validate|interpret|report     │
 │  17 grupos collect_*         │  en bruto   │  bundle.read()   → Bundle           │
 │  → 134 secciones con estado, │ ──────────► │  interpret()     → Snapshot         │
 │    rc y nota                 │  (fichero   │    parsers/<área>.py (17)           │
 │  filtra lo sensible en origen│   o stdout) │    relations.consolidate()          │
 │  nada en disco               │             │  views/text.render() | to_json()    │
 └──────────────────────────────┘             └─────────────────────────────────────┘
```

**Cómo se comunican las piezas:**

- **Script → núcleo:** solo a través del paquete en bruto (`FORMATO.md`). El script no
  sabe nada de Python y el núcleo no ejecuta nada en la máquina inventariada.
- **Dentro del núcleo:** llamadas a funciones. Los analizadores se registran con el
  decorador `register` y `interpret()` los invoca uno por área.
- **Con el sistema inventariado:** solo lectura de ficheros y ejecución de herramientas
  del propio sistema, desde el script.
- **Red:** ninguna. El script no abre conexiones; el núcleo tampoco.

**Lo que no existe todavía** (regla 15 de `CLAUDE.md`): la ejecución por SSH, el
componente central (inventario, histórico, comparación, alertas, web) y la exploración de
red desde el central. Están previstos en las fases 5 a 7 de `TODO.md` y descritos en
`CAMBIO.md`, *La arquitectura de destino*.

---

## Stack tecnológico

| Pieza | Versión | Para qué | Fuente |
|---|---|---|---|
| POSIX `sh` | Probado con `dash`, `bash` (incluido el 4.1 de CentOS 6) y busybox `ash` | El script de recogida | `tests/collector/test_script.sh` |
| Herramientas del sistema | Las de cada distribución; ninguna obligatoria | `awk`, `find`, `stat`, `grep`, `head` y, si existen, `ip`, `ss`, `lsblk`, `rpm`, `dpkg-query`, `nft`, `journalctl`… Si falta una, la sección queda en `missing`. | `collector/aridi-collect.sh` |
| Python | ≥ 3.12 (`requires-python`) | El núcleo | `pyproject.toml` |
| Librería estándar | La del intérprete | Todo el núcleo. `tests/test_core_isolation.py` falla si `src/aridi` importa otra cosa. | `src/aridi/` |
| `setuptools` | ≥ 77, solo para construir | Empaquetado (`pip install .`), con `services.csv` como `package-data` | `pyproject.toml` |
| Django, gunicorn | Django ~5.2, gunicorn ~23, fijados con hashes | **Previsto** para el central; ningún código lo usa todavía | `requirements/central.in`, `requirements/central.txt` |
| Docker | El del anfitrión | Ejecutar todas las pruebas y capturar el corpus | `tests/run.sh` |
| Lima | 2.x | VMs desechables para el corpus (systemd, sesiones, x86_64) | `tests/lima/` |

---

## Estructura del proyecto

| Ruta | Qué es |
|---|---|
| `collector/aridi-collect.sh` | El script de recogida (unas 840 líneas) |
| `src/aridi/` | El núcleo (librería estándar), con la CLI `aridi` |
| `src/aridi/data/services.csv` | Nombres de puertos (`nombre\|puerto\|descripción`), copia sin cambios del de 2019 |
| `tests/` | Pruebas, corpus y referencias de 2019 (ver *Estrategia de pruebas*) |
| `requirements/` | Dependencias del central, fijadas con hashes |
| `docs/` | Documentación del proyecto, en español |
| `pyproject.toml` | Distribución `aridi`: núcleo sin dependencias y extra `central` |

### El script: `collector/aridi-collect.sh`

**Flujo.** `main()` llama a `bundle_begin` (cabecera `ARIDI-BUNDLE 1 <versión>` y
frontera aleatoria), después a 17 grupos de recogida en el orden del aridi de 2019, y
cierra con `close sections=N`:

`collect_meta`, `collect_system`, `collect_hardware`, `collect_packages`,
`collect_storage`, `collect_permissions`, `collect_identity`, `collect_users`,
`collect_services`, `collect_network`, `collect_firewall`, `collect_timesync`,
`collect_processes`, `collect_load`, `collect_sessions`, `collect_carving` y
`collect_neighbours`.

En las muestras de `tests/parity/` el paquete tiene 134 secciones (observado). Con
`ARIDI_COLLECT_LIB=1` el script solo define las funciones; lo usan las pruebas.

**Primitivas de sección.** Cada sección lleva nombre, estado, código de salida y, como
mucho, una nota:

| Función | Qué hace |
|---|---|
| `section NOMBRE HERRAMIENTA …` | Salida de un comando. Si la herramienta no existe, sección `missing` sin ejecutar nada. |
| `section_rc NOMBRE CÓDIGOS HERRAMIENTA …` | Como `section`, pero los códigos de `CÓDIGOS` son un resultado normal (por ejemplo, `ldd --version` sale con 1 en musl). Se conserva el `rc` real. |
| `section_file NOMBRE RUTA` | Contenido de un fichero: `na` si no existe, `denied` si no se puede leer. |
| `section_text NOMBRE TEXTO` | Un valor calculado por el propio script (`meta.env`). |
| `_empty NOMBRE CAMPOS ESTADO NOTA` | Una sección que no se ejecutó, con su motivo. |
| `_password_file NOMBRE RUTA` | `passwd`, `shadow`, `group` y `gshadow` con el campo de contraseña reducido a su forma (`_PASSWORD_PREFIX_AWK`). |

`_run` ejecuta el comando con `</dev/null`, envía como mucho `límite + 1` bytes de
contenido por el descriptor 3, captura el código de salida y la primera línea de stderr,
y `_status_of` traduce el código a estado (`ok`, `denied`, `missing`, `timeout`, `error`).

**Garantías de ejecución** (observadas en `tests/run.sh collector`):

- **No escribe en disco:** sin ficheros temporales, `umask 077`. La prueba lo comprueba
  con `find / -xdev -newer` en cada imagen.
- **Cada comando lee de `/dev/null`:** el script puede llegar por stdin (`sh -s`), y un
  comando que leyera stdin se comería el resto.
- **`PATH` fijo**, con los directorios del sistema primero
  (`/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin`), y `LC_ALL=C`.
- **Límites por sección:** 4 MiB (`ARIDI_SECTION_LIMIT`) y 60 s (`ARIDI_SECTION_TIMEOUT`).
  El tiempo lo impone el `timeout` de coreutils si existe; si no, un vigilante propio en
  `sh` (`_watch`). El `timeout` de busybox no se usa (ver *Registro de decisiones*).
- **Sin privilegios** termina igual, con 0, y marca `denied` lo que no puede leer.

**Filtrado en origen** (detalle en `FORMATO.md`, *Qué no sale nunca de la máquina*):

- **Contraseñas:** solo sale la forma del campo (`$y$`, `!`, `*`, `des`…), nunca el hash.
- **Líneas de órdenes de los procesos:** cortadas a 512 bytes, con los valores de
  opciones con aspecto de secreto sustituidos por `***` (`_SECRET_AWK`). No cubre todas
  las formas (por ejemplo, `mysql -pSECRETO`).
- ***Carving*:** de `/etc` y `/var/log` solo salen la ruta, el número de línea, la
  dirección, su prefijo y marcas de contexto (`_IP_AWK`), nunca el texto de la línea. En
  `/etc` solo se abren ficheros legibles por cualquier usuario (`-perm -0004`). Del
  journal, solo recuentos por dirección.
- **Variables de entorno de los procesos:** no se leen.

**Herramientas que podrían modificar el sistema:**

- `rpm -qa` como root se ejecuta como uid 65534 mediante `chroot --userspec`, porque como
  root escribe en `/var/lib/rpm` (`collect_packages`).
- `nft` e `iptables` solo se consultan si el motor ya está en el kernel
  (`/sys/module/nf_tables`, `nft_do_chain` en `/proc/kallsyms`,
  `/proc/net/ip_tables_names`); firewalld, solo si `firewall-cmd --state` responde
  (`collect_firewall`).

### El núcleo: `src/aridi/`

| Módulo | Responsabilidad |
|---|---|
| `__init__.py` | `__version__` (`2.0.0.dev0`) y `BUNDLE_FORMAT_VERSION` (1) |
| `bundle.py` | Lector del paquete en bruto: `parse()` y `read()` devuelven un `Bundle` con sus `RawSection` (nombre, estado, `rc`, nota, contenido, truncado). Errores propios: `BundleError`, `UnsupportedVersion`, `TruncatedBundle`. |
| `model.py` | La fotografía v1 (`SCHEMA_VERSION = 1`): `Snapshot`, `Machine`, `Section`, `Gap`, `Relation`, y los enumerados `Status`, `Role` y `Outcome`. Serialización a JSON y lectura con validación. |
| `interpret.py` | `AREAS` (las 17 áreas, con grupo y marca de volátil), `register(área, uses=(), needs_own=True)` y `interpret(bundle)`. |
| `parsers/` | Un analizador por área (`system.py`… `neighbours.py`) y utilidades comunes (`_common.py`: `text`, `first_line`, `gap`, `user_names`). |
| `relations.py` | `consolidate()`: une las relaciones de todas las áreas por IP, ordena IPv4 e IPv6 juntas y pone primero la máquina local. |
| `ports.py` | Nombre de un puerto a partir de `data/services.csv`, leído con `importlib.resources`. |
| `views/text.py` | Informe de texto: una vista por área (`@renderer`), la de infraestructura y «What could not be seen». `clean()` neutraliza los caracteres de control de todo texto que viene de la máquina. |
| `cli.py` | `aridi validate|interpret|report`, con `-v` para el log por stderr. |

**Cómo se interpreta un paquete** (`interpret.py`):

- **Todas las áreas aparecen siempre** en la fotografía. Si no hay analizador, el área
  queda en `no_parser`; si el paquete no trae secciones suyas, en `not_collected`; si el
  analizador lanza una excepción, en `error` con el motivo, y las demás siguen.
- **Cada analizador recibe solo sus secciones** (`<área>.*`), más las de los prefijos que
  declara en `uses`. Hoy: `processes` usa `users`; `sessions` usa `meta`; `connections`
  usa `network` y `users`, y no tiene secciones propias (`needs_own=False`).
- **El analizador devuelve un `AreaResult`:** datos, relaciones, estado, motivo y
  **huecos parciales** (`Gap(item, status, reason)`), es decir, lo que no se pudo ver
  dentro de un área que por lo demás sí se vio. `na` no cuenta como hueco.
- **El resultado global** (`Outcome`) es `complete` o `gaps`, y de él sale el código de
  salida de la CLI: 0 completa, 1 con huecos, 2 si el paquete no es válido o no se puede
  escribir la salida.

**Áreas** (en el orden de 2019):

| Grupo | Áreas |
|---|---|
| General | `system`, `hardware`, `packages`, `storage`, `permissions` |
| Específica | `identity`, `users`, `services`, `network`, `firewall`, `timesync` |
| Volátil | `processes`, `load`, `sessions`, `connections` |
| *Carving* y vecinos | `carving`, `neighbours` |

Son volátiles `processes`, `load`, `connections` y `neighbours`. `sessions` no lo es como
área (ver *Registro de decisiones*).

---

## Modelo de datos

**No hay almacenamiento persistente.** El núcleo trabaja en memoria; lo único que se
escribe es lo que pide el usuario (`aridi interpret -o FICHERO`, en modo 0600, sin
sobrescribir ni seguir enlaces simbólicos).

**Hay dos formatos versionados**, especificados en `FORMATO.md`:

- **Paquete en bruto v1:** texto con cabecera, frontera aleatoria por ejecución y
  secciones `begin` / contenido / `end status= rc=` / `note`, cerradas con
  `close sections=N`. Lo escribe el script y lo lee `bundle.py`.
- **Fotografía v1:** el JSON de `Snapshot.to_json()`, con `schema_version`, la identidad
  de la máquina (`machine_id`, `hostname`), `collected_at`, la versión del colector, una
  entrada por área (`status`, `reason`, `data`, `volatile`, `gaps`) y la lista de
  relaciones.

**Relaciones.** La clave transversal sigue siendo la IP, como en 2019, pero ahora es un
objeto `ipaddress` (IPv4 o IPv6) y su papel es un código del enumerado `Role` (`local`,
`dns_server`, `ntp_server`, `login_source`, `failed_login_source`, `fw_allowed_in`,
`fw_allowed_out`, `peer_in`, `peer_out`, `named_in_file`, `neighbour`, `scan_open_port`),
nunca una frase. `scan_open_port` está reservado para el escáner del central (fase 7) y
solo se prueba con datos sintéticos.

**El modelo de datos del central** (máquinas, grupos, fotografías, alertas en SQLite)
está previsto en `CAMBIO.md`, *Modelo de datos*, y **no existe todavía**.

---

## Interfaces y contratos

**Script:**

```
sh aridi-collect.sh > maquina.aridi
ssh host sh -s < aridi-collect.sh > maquina.aridi     (forma prevista para el central)
```

- Sin argumentos ni preguntas. Variables opcionales: `ARIDI_SECTION_LIMIT` y
  `ARIDI_SECTION_TIMEOUT`.
- Termina con 0 aunque haya secciones en `denied`, `missing` o `error`: el estado va en
  cada sección.

**Núcleo (CLI `aridi`, `src/aridi/cli.py`):**

```
aridi [-v|-vv] validate  PAQUETE
aridi [-v|-vv] interpret PAQUETE [-o FICHERO]
aridi [-v|-vv] report    PAQUETE [--detail]
```

- Códigos de salida: 0 completa, 1 con huecos, 2 paquete inválido o error de salida.
- El log va por stderr con el módulo `logging`.

**Fronteras** (vigiladas por pruebas):

- El núcleo solo importa la librería estándar (`tests/test_core_isolation.py`).
- El núcleo nunca importa Django ni `aridi_central` (regla 16 de `CLAUDE.md`).
- Los papeles de relación son códigos enumerados; un papel desconocido es un error de
  validación (`tests/test_core/test_model.py`).

---

## Aspectos transversales

**Configuración.** No hay ficheros de configuración. El script solo admite las dos
variables de límites; el núcleo, los argumentos de la CLI.

**Gestión de errores.**

- **Nada se omite en silencio.** Lo que no se puede recoger queda como sección con su
  estado (`denied`, `missing`, `na`, `timeout`, `error`) y su nota; lo que no se puede
  interpretar, como área con estado o como hueco parcial con motivo.
- **Un analizador que falla no tumba a los demás** (`_area_section` en `interpret.py`);
  el error se registra con `log.exception`.
- **Un dato dudoso se declara desconocido**, no se encaja en otra categoría (por ejemplo,
  algoritmos de contraseña que no se reconocen).

**Logging.** Módulo `logging` hacia stderr, con `-v` (INFO) y `-vv` (DEBUG). El script no
tiene log: su diagnóstico son el estado y la nota de cada sección, y `meta.env` (shell,
tipo de límite de tiempo, origen de la frontera, `PATH`).

**Concurrencia.** Ninguna en el núcleo. En el script, solo el vigilante de tiempo
(`_watch`) corre en segundo plano junto a cada comando cuando no hay `timeout` de
coreutils.

**Texto que no es de fiar.** Todo lo que viene de la máquina (banners, nombres de
proceso, rutas) se trata como no confiable: `views/text.py` escapa los caracteres de
control antes de mostrarlo.

---

## Seguridad

Descripción del estado actual; la auditoría es un paso aparte.

- **Solo lectura.** El script no escribe en disco y evita las herramientas que escriben
  al leer (`rpm` como root) o que cargan módulos (`nft`, `iptables`). Las pruebas lo
  comprueban en cada imagen del corpus.
- **Secretos.** El filtrado en origen descrito arriba. `tests/test_corpus_hygiene.py`
  comprueba que ninguna muestra del corpus ni de `tests/parity/` lleva hashes de
  contraseñas ni rutas del anfitrión que la capturó.
- **Cadena de suministro.** El script y el núcleo no tienen dependencias ajenas. Las del
  central previsto están fijadas con hashes en `requirements/central.txt`.
- **Entradas.** El núcleo trata el paquete como no confiable: valida su estructura
  (`bundle.py`) y declara como hueco lo que no puede interpretar.
- **Ficheros de salida.** `aridi interpret -o` crea el fichero con `O_EXCL | O_NOFOLLOW`
  y modo 0600.
- **Lo que queda abierto:**
  - la redacción de las líneas de órdenes no cubre todas las formas de pasar un secreto;
  - la escalada de privilegios para la recogida remota está sin decidir
    (`TODO.md` 5.0).

---

## Estrategia de pruebas

**Punto de entrada único:** `tests/run.sh`. Todo corre en Docker; el Python del
anfitrión no se usa.

| Parte | Qué hace |
|---|---|
| `unit` | `python -m unittest discover -s tests -t .` en `python:3.12-slim`, con el repositorio en solo lectura y sin red |
| `collector` | `tests/collector/test_script.sh`: el script en las 10 imágenes, con cada shell disponible, como root y como uid 65534; comprueba código 0, que no deja rastro, que los datos tras el script en stdin no se ejecutan y los estados esperados; valida los paquetes con `tests/collector/check_bundles.py` |
| `golden` | Regenera el informe de referencia de `tests/test_core/test_text.py` (revisando el diff) |
| `central` | Sin pruebas todavía (fase 5) |

**Pruebas de `unittest`:**

- `tests/test_parsers/`: una por área (o por grupo de áreas), contrastadas con
  `facts.txt` de cada muestra, con los casos de `docs/MVP.md` y con entradas sintéticas
  (`tests/helpers.py`: `make_bundle`).
- `tests/test_core/`: lector, modelo, `interpret`, mapa de relaciones, vista de texto y
  CLI.
- `tests/test_core_isolation.py`: solo librería estándar en el núcleo.
- `tests/test_corpus_hygiene.py`: sin rastros del anfitrión ni hashes en los datos de
  prueba.
- `tests/test_parity.py` y `tests/test_parity_doc.py`: la regresión final contra 2019
  (ver abajo).

**El corpus** (`tests/corpus/`, detalle en su `README.md`):

- `capture.sh` captura una muestra en un contenedor desechable: aplica `scenario.sh`
  (usuarios, grupos, ficheros, banners, *listeners*, un proceso con un uid sin cuenta),
  ejecuta el script por `sh -s` como root y después `facts.sh`, que obtiene la «verdad de
  referencia» con las herramientas del propio sistema.
- **10 imágenes** fijadas por *digest* (`images.txt`): Debian 12 y 13, Ubuntu 24.04,
  Rocky 9, Fedora 44, Alpine 3.20, openSUSE Leap 15.6, Arch, CentOS 7 y CentOS 6 (Arch y
  CentOS 6 en amd64 emulado). Cada una en tres variantes: `minimal` (la imagen tal cual,
  sin red), `server` (con herramientas de red y de sistema, sin red) y `bridge` (la
  anterior en una red *bridge* interna, con interfaces `eth0@ifN`).
- **3 VMs de Lima** (`tests/lima/`: Debian 12 arm64 y amd64, Rocky 9 arm64) para lo que no
  dan los contenedores: systemd, sesiones SSH reales, cortafuegos con reglas y x86_64.
  `capture-vm.sh` las arranca con `--mount-none` y aborta si ve un montaje del anfitrión.

**Regresión final contra 2019** (`tests/parity/`, `tests/parity.md`):

- `tests/parity/<distro>-<variante>/` guarda el informe del aridi de 2019, su
  `aridi.badfiles` y el paquete del script nuevo, tomados uno detrás de otro en el mismo
  contenedor: Debian 12 y CentOS 7, en las variantes `plain`, `none` y `bridge`. Los generó
  `tests/legacy/reference.sh`.
- `tests/test_parity.py` comprueba que todo valor que 2019 daba bien sale igual en el
  nuevo, y que donde 2019 se equivocaba el nuevo da el valor correcto.
- `tests/parity.md` relaciona cada funcionalidad de `docs/MVP.md` con las pruebas que la
  cubren o con el motivo por el que se abandona; `tests/test_parity_doc.py` comprueba que
  la tabla está completa y que las pruebas que nombra existen.

---

## Compilación, CI y despliegue

- **Compilación:** no hay. `pip install .` instala el núcleo y la orden `aridi`.
- **CI:** no hay CI remota (decisión de planificación de `TODO.md`): todo se verifica en
  local con `tests/run.sh`.
- **Distribución:** ninguna publicada. La versión es `2.0.0.dev0`.
- **Despliegue:** sin despliegue. El modo de uso es el local en dos pasos. El contenedor
  del central (`docker compose`) está previsto en la fase 5.

---

## Objetivos de rendimiento

**No hay objetivos declarados**, salvo el límite de 60 s por sección del script. Medido
en el corpus (`collector_seconds` de cada `meta.txt`; `tests/corpus/README.md`):

- de 1 a 2 s en las imágenes arm64 nativas y en las VMs arm64;
- de 1 a 7 s en Alpine;
- de 13 a 21 s en las imágenes amd64 emuladas (CentOS 6 y Arch);
- 14 s en la VM x86_64.

**Sin medir:** máquinas reales con muchos registros, muchos procesos o sistemas de
ficheros grandes. El *carving* y el recorrido de permisos están acotados (`-xdev`,
ficheros de menos de 1 MiB, como mucho 20.000 líneas por sección), pero su duración en
una máquina grande es una **suposición**.

---

## Historia: el aridi de 2019

- **Qué era:** un único proceso de consola en Python 3, interactivo (7 preguntas
  `input()`), que se ejecutaba como root en la propia máquina y producía un informe de
  texto. Fases `gathering0` (precheck) a `gathering4` (*carving*), más `scan.py` (barrido
  ARP y escaneo TCP) y `graph.py` (grafo con `graphviz`). Estado compartido en un objeto
  `Reporting`, papeles de relación como frases en inglés y análisis de la salida de los
  binarios por columnas.
- **Su estado medido** está en `docs/MVP.md` y su estudio en `docs/ESTUDIO.md`.
- **Dónde está el código:** en la historia de git. En la raíz del repositorio hasta el
  commit `4ab279e` (2019-04-12); en `legacy/`, sin modificar, de `6f749d6` a `037284e`.
  Se retira del árbol en la fase 4.2 de `TODO.md`, una vez comprobada la paridad
  (`tests/parity.md`).
- **Lo que se conserva de él:** `services.csv` (copiado sin cambios), su conocimiento de
  cada área como especificación, y sus resultados en `tests/parity/` como referencia
  congelada.

---

## Registro de decisiones

Fuentes: **documentado** (`CAMBIO.md`, `TODO.md`, `FORMATO.md`, un commit), **usuario**
(decidido por el usuario), **deducido** (del código o de la historia).

### Del aridi de 2019 (se mantienen)

| Decisión | Motivo | Cómo se sabe |
|---|---|---|
| Sin dependencias ajenas en lo que llega a la máquina | Evitar ataques de cadena de suministro | **Usuario** (`IDEA.md`). En 2019, solo la librería estándar; hoy, `sh` y el núcleo sin dependencias. |
| Aislar cada parte y seguir aunque otra falle | Sacar todo lo posible | **Deducido** del código de 2019. Hoy se mantiene, pero declarando el fallo en lugar de omitirlo. |
| Licencia GPL v3 | No documentado | **Documentado:** `LICENSE` |

### De `CAMBIO.md` (2026-10-15)

| Decisión | Motivo | Alternativas descartadas |
|---|---|---|
| Reescribir el colector, usando el de 2019 como especificación | Adaptarlo costaba lo mismo o más y dejaba la mezcla de datos y texto | Adaptarlo por pasos; mixto |
| Script POSIX `sh` más intérprete en Python 3.12 | Cubrir RHEL/CentOS 6 y contenedores sin Python | Colector entero en Python ≥ 3.6; binario en Go |
| Recoger en bruto e interpretar fuera | Que la máquina solo lea y que los datos puedan reinterpretarse con un núcleo mejor | — |
| Huecos declarados con estado y motivo | Que el informe no mienta por omisión | — |
| Fotografía JSON versionada desde el primer día | Es el contrato con los datos que guarde el central | — |
| Central en Django 5.2 LTS con SQLite (WAL), cola en la base de datos, credenciales en el `ssh-agent`, contenedor con `docker compose` | Pocas dependencias fijadas por hash; un único servicio que operar; el central no guarda claves | `http.server` a mano; FastAPI + React; PostgreSQL; Celery + Redis; claves en la base de datos; wheel + systemd (**el usuario eligió el contenedor**) |
| Volátiles guardados, sin alertas | Conservar lo que se ve hoy sin generar ruido | Eliminarlos; alertas por umbral |
| Descubrimiento pasivo en la máquina y escaneo activo desde el central, acotado a redes autorizadas | No generar tráfico desde máquinas que solo deben leerse; no escanear a terceros | Escaneo desde la máquina con `nmap`/`arping`; abandonar el escaneo activo |
| Código de 2019 en `legacy/` hasta la paridad | No dejar un hueco sin herramienta | Dejarlo en la raíz; borrarlo al empezar |

### De planificación (`TODO.md`)

| Decisión | Motivo |
|---|---|
| Sin CI remota: todo con `tests/run.sh` en Docker | macOS solo tiene Python 3.9; las pruebas usan `python:3.12-slim` |
| Las áreas se construyen en el orden de 2019 | Seguir la especificación tal como está |
| Muestras de VM con Lima 2.x | systemd, sesiones reales y x86_64 no se obtienen en contenedores |
| Una tarea que cambia comportamiento incluye sus pruebas | No dar nada por hecho sin verlo pasar |

### De la fase 2 (`FORMATO.md`, *Decisiones tomadas en la fase 2*)

| Decisión | Motivo |
|---|---|
| El tamaño de cada sección lo calcula el lector, no el script | Contar bytes en `sh` sin ficheros temporales no es fiable; el truncado se detecta con el byte de más |
| Las secciones `meta.*` son la identidad de la ejecución, no un área | Separar la cabecera de la fotografía de los datos |
| `neighbours` es volátil | La tabla ARP cambia continuamente |
| `sessions` no es volátil como área | El historial de accesos debe poder alertar |
| `denied` se deduce del texto de stderr en `LC_ALL=C` | Es lo único que distingue un fallo de permisos con el mismo código de salida |

### De la fase 3

| Decisión | Motivo | Cómo se vio |
|---|---|---|
| Huecos parciales (`Gap`) dentro de cada área | Un área con parte de los datos no debe marcarse entera como fallida ni callar lo que falta | Al empezar la fase 3 |
| Papeles de relación como códigos enumerados (`Role`) | En 2019 eran frases que luego se clasificaban por prefijo de texto | `CLAUDE.md`, regla 7 |
| `rpm` como uid 65534 (`chroot --userspec`) | Como root, `rpm -qa` crea o actualiza ficheros en `/var/lib/rpm` | Prueba `find -newer` en CentOS 6 y 7 y Rocky 9 |
| `nft` e `iptables` solo si el motor ya está en el kernel; firewalld solo si responde | Consultarlos puede cargar módulos del kernel | Lectura de su comportamiento; principio de solo lectura |
| JSON de `nft` solo si `nft --help` lo ofrece; si no, `missing` | El `nft` 0.8 de CentOS 7 no admite `-j` | Corpus de CentOS 7 |
| *Carving* sin el texto de las líneas, y en `/etc` solo ficheros legibles por todos | Las líneas pueden contener secretos; un primer diseño podía leer `/etc/shadow` | Detectado en pruebas locales antes de llegar a ninguna muestra |
| Vigilante de tiempo propio en lugar del `timeout` de busybox | El de busybox mantenía la tubería abierta hasta un segundo por sección | Alpine pasó de 93 s a 7 s |
| VMs de Lima con `--mount-none` y comprobación de montajes | Lima 2 añade los montajes de la plantilla base (el directorio personal del anfitrión) aunque el YAML diga `mounts: []` | Un montaje del anfitrión apareció en las muestras de VM |

### De la fase 4

| Decisión | Motivo |
|---|---|
| Regresión final con referencias congeladas en `tests/parity/` (2019 y el script nuevo en el mismo contenedor) | Comparar valor a valor, y conservar la referencia cuando `legacy/` ya no exista |
| En las referencias con escenario se quita el `nameserver` IPv6 antes de ejecutar los dos programas | Con él, el aridi de 2019 no escribe ningún informe (clave `None` en su mapa) |
| Una IPv4 seguida de `-` se trata como número de versión (`anaconda 21.48.22.159-1`) | Es el criterio de 2019; el script clasifica ahora el guion como carácter vecino propio |

---

## Deuda y riesgos

- **El componente central no existe.** Sin él no hay ejecución remota, histórico ni
  alertas, que son el objetivo del cambio (`IDEA.md`).
- **La redacción de secretos en las líneas de órdenes es incompleta** (`mysql -pSECRETO`).
  La alternativa segura, no enviar la línea de órdenes, está documentada en `FORMATO.md`.
- **La deducción de `denied` depende del texto de stderr.** Un comando que falle por
  permisos con otro mensaje queda en `error` hasta que su analizador lo corrija.
- **El corpus depende del colector:** cada cambio del script obliga a recapturar las 30
  muestras de contenedor y las 3 VMs, y la VM amd64 es lenta (emulación QEMU).
- **Artefacto de la emulación amd64:** en Arch y CentOS 6, leer `/proc/PID/cmdline` crea y
  borra un fichero en `/tmp`. Lo provoca la emulación, no el script; la prueba del
  colector lo acepta solo cuando lo demuestra (`tests/collector/test_script.sh`).
- **`services.csv`** sigue sin origen, fecha ni columna de protocolo. Su regeneración está
  prevista en `TODO.md` 7.1.
- **Sin medir en máquinas reales grandes** (ver *Objetivos de rendimiento*).
- **x86_64 nativo:** solo se ha probado con emulación (la VM amd64 y las imágenes de Arch
  y CentOS 6).
