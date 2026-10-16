# aridi: arquitectura actual

> Este documento describe la arquitectura **que existe** en la rama `rewrite` durante la
> fase 5 de [`TODO.md`](../TODO.md) (2026-10-16): el colector nuevo, que funciona en modo
> local, y el **componente central** (inventario, recogida por SSH, cola y programación,
> web y búsqueda). Lo que sigue sin existir de la arquitectura de destino de
> [`CAMBIO.md`](CAMBIO.md) son los cambios y alertas (fase 6) y el descubrimiento de red
> y el escaneo desde el central (fase 7). El contrato de datos está en
> [`FORMATO.md`](FORMATO.md). Los hechos vienen de leer el código y de ejecutar
> `tests/run.sh`; las referencias van en la forma `archivo:línea` o con el nombre de la
> función. Lo que no se puede probar va marcado como **suposición**.

---

## Visión general

aridi es hoy **un colector en dos pasos**, que se usa en modo local o desde el
**componente central**:

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

**El componente central** (`src/aridi_central/`, Django) lanza el mismo script por SSH,
guarda cada fotografía en SQLite y la muestra en una web:

```
 docker compose
 ┌──────────────────────────────────────────────────────────────────┐
 │ web: gunicorn + Django                worker: aridi_worker       │
 │  inventario, fichas, histórico,        toma trabajos de la cola, │
 │  huecos, búsqueda, importación,        programa los periódicos,  │
 │  recogida a demanda (encola)           lanza ssh (lista de args) │
 │            │                                   │                 │
 │            └────── SQLite (WAL) en /data ──────┤                 │
 └────────────────────────────────────────────────┼─────────────────┘
                                                  │ ssh -T -o BatchMode=yes …
                                                  ▼   (clave en el ssh-agent)
 Máquina inventariada: sudo -n /usr/local/libexec/aridi-collect.sh  → paquete en bruto
```

**Cómo se comunican las piezas:**

- **Script → núcleo:** solo a través del paquete en bruto (`FORMATO.md`). El script no
  sabe nada de Python y el núcleo no ejecuta nada en la máquina inventariada.
- **Dentro del núcleo:** llamadas a funciones. Los analizadores se registran con el
  decorador `register` y `interpret()` los invoca uno por área.
- **Central → núcleo:** el central importa el núcleo como librería (`aridi.bundle`,
  `aridi.interpret`, `aridi.model`, `aridi.views.text`, `aridi.relations`); el núcleo
  nunca importa el central.
- **Central → máquina:** un proceso `ssh` por recogida, sin shell local, con un comando
  remoto fijo (ver *Recogida por SSH*).
- **Web ↔ trabajador:** solo a través de la base de datos (tabla `Job`).
- **Con el sistema inventariado:** solo lectura de ficheros y ejecución de herramientas
  del propio sistema, desde el script.

**Lo que no existe todavía** (regla 15 de `CLAUDE.md`): la comparación entre
fotografías y las alertas (fase 6 de `TODO.md`; las aplicaciones `changes` y `discovery`
están creadas pero vacías) y el descubrimiento de red y el escaneo desde el central
(fase 7).

---

## Stack tecnológico

| Pieza | Versión | Para qué | Fuente |
|---|---|---|---|
| POSIX `sh` | Probado con `dash`, `bash` (incluido el 4.1 de CentOS 6) y busybox `ash` | El script de recogida | `tests/collector/test_script.sh` |
| Herramientas del sistema | Las de cada distribución; ninguna obligatoria | `awk`, `find`, `stat`, `grep`, `head` y, si existen, `ip`, `ss`, `lsblk`, `rpm`, `dpkg-query`, `nft`, `journalctl`… Si falta una, la sección queda en `missing`. | `collector/aridi-collect.sh` |
| Python | ≥ 3.12 (`requires-python`) | El núcleo | `pyproject.toml` |
| Librería estándar | La del intérprete | Todo el núcleo. `tests/test_core_isolation.py` falla si `src/aridi` importa otra cosa. | `src/aridi/` |
| `setuptools` | ≥ 77, solo para construir | Empaquetado (`pip install .`), con `services.csv` como `package-data` | `pyproject.toml` |
| Django | 5.2.18 (LTS), con asgiref 3.12.1 y sqlparse 0.6.0 | El central: modelos, migraciones, web, autenticación | `requirements/central.txt` (fijado con hashes) |
| gunicorn | 23.0.0 (con packaging 26.3) | Servidor WSGI del central | `requirements/central.txt` |
| SQLite | La de la imagen | Base de datos del central, con WAL | `src/aridi_central/settings.py` |
| OpenSSH (cliente) y `sqlite3` | Los de Debian en la imagen | Recogida por SSH; copias de seguridad | `Dockerfile` |
| Imagen base | `python:3.12-slim`, fijada por *digest* (`sha256:a6e34c59…`) | Contenedor del central | `Dockerfile` |
| Docker | El del anfitrión | Ejecutar todas las pruebas y capturar el corpus | `tests/run.sh` |
| Lima | 2.x | VMs desechables para el corpus (systemd, sesiones, x86_64) | `tests/lima/` |

---

## Estructura del proyecto

| Ruta | Qué es |
|---|---|
| `collector/aridi-collect.sh` | El script de recogida (unas 840 líneas) |
| `src/aridi/` | El núcleo (librería estándar), con la CLI `aridi` |
| `src/aridi/data/services.csv` | Nombres de puertos (`nombre\|puerto\|descripción`), copia sin cambios del de 2019 |
| `src/aridi_central/` | El componente central (Django): ver *El componente central* |
| `Dockerfile`, `.dockerignore`, `compose.yaml` | Imagen y despliegue del central |
| `tests/` | Pruebas, corpus y referencias de 2019 (ver *Estrategia de pruebas*) |
| `requirements/` | Dependencias del central, fijadas con hashes |
| `docs/` | Documentación del proyecto, en español |
| `pyproject.toml` | Distribución `aridi`: núcleo sin dependencias y extra `central` |

### El componente central: `src/aridi_central/`

| Ruta | Responsabilidad |
|---|---|
| `manage.py`, `settings.py`, `urls.py`, `wsgi.py` | Proyecto Django. `manage.py` añade `src/` a la ruta, así que funciona desde el repositorio (`python src/aridi_central/manage.py`) y en la imagen (`python -m aridi_central.manage`). |
| `inventory/` | Modelos del inventario, `validators.py` (campos SSH), `indexing.py` (de la fotografía a los índices), `importing.py` (validar, interpretar, guardar), comando `aridi_import`. Su `apps.py` fija los `PRAGMA` de SQLite en cada conexión. |
| `collection/` | Modelos `Job` y `Schedule`, `ssh.py` (recogida), `worker.py` (cola, programación, ciclo de vida), comando `aridi_worker`. |
| `web/` | Vistas, formularios, plantillas (`templates/web/`), `roles.py`, el *middleware* de CSP y la migración de datos de los roles. |
| `changes/`, `discovery/` | Vacías: fases 6 y 7. |
| `testing.py` | Rutas del corpus para las pruebas del central. |
| `*/tests/` | Pruebas de Django (ver *Estrategia de pruebas*). |

**Configuración** (`settings.py`), toda por variables de entorno:

- **Producción por defecto:** sin `ARIDI_SECRET_KEY` el arranque falla
  (`ImproperlyConfigured`), salvo con `ARIDI_DEBUG=1`.
- **Web:** `ARIDI_ALLOWED_HOSTS` y `ARIDI_CSRF_TRUSTED_ORIGINS`.
- **Base de datos:** `ARIDI_DB_PATH` (por defecto `/data/aridi.db`).
- **Recogida:** `ARIDI_SSH_CONFIG`, `ARIDI_KNOWN_HOSTS`, `ARIDI_SSH_CONNECT_TIMEOUT` (15 s),
  `ARIDI_SSH_TIMEOUT` (900 s), `ARIDI_MAX_SSH` (4), `ARIDI_JOB_ATTEMPTS` (3),
  `ARIDI_MAX_BUNDLE_BYTES` (64 MiB), `ARIDI_RAW_RETENTION` (10),
  `ARIDI_COLLECTOR_SCRIPT` y `ARIDI_WORKER_HEARTBEAT`.
- **Seguridad:** `ARIDI_SSL_REDIRECT` y `ARIDI_HSTS_SECONDS` (un año por defecto).
- **Log:** `ARIDI_LOG_LEVEL`.

**SQLite:** en cada conexión, `PRAGMA journal_mode=WAL`, `busy_timeout=20000` y
`foreign_keys=ON` (señal `connection_created`), y transacciones `IMMEDIATE`, para que la
web y el trabajador no choquen al pasar de lectura a escritura.

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

**El núcleo no tiene almacenamiento persistente:** trabaja en memoria, y lo único que
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

**El modelo de datos del central** (SQLite; `inventory/models.py`,
`collection/models.py`; migraciones `0001` de cada aplicación):

| Modelo | Campos clave | Notas |
|---|---|---|
| `Group` | nombre, descripción | Su programación por defecto es un `Schedule` del grupo |
| `Machine` | nombre, `ssh_target`, `ssh_port`, `proxy_jump`, `privilege` (`sudo` o `user`), grupos, `machine_id`, activa | **Sin credenciales.** `ssh_target` vacío: máquina solo de importación. `machine_id` se toma de la primera fotografía y asocia las importaciones. |
| `Snapshot` | máquina, `collected_at`, `received_at`, `origin` (`ssh`, `on_demand`, `import`), `schema_version`, `collector_version`, `data` (JSON), `result` (`complete`, `gaps`, `failed`), `failure_reason`, `raw_bundle`, `bundle_sha256`, `installed_collector_sha256`, `collector_outdated` | El JSON se guarda entero. El paquete en bruto va comprimido con gzip y solo en las `ARIDI_RAW_RETENTION` fotografías más recientes de cada máquina (`prune_raw_bundles`). Restricción única: el mismo paquete (`bundle_sha256`) no se guarda dos veces para una máquina. Una recogida fallida es una fotografía `failed` sin datos. |
| `Gap` | fotografía, área, *item*, estado, motivo | Todos los huecos de `Snapshot.gaps()` del núcleo |
| `SnapshotPackage`, `SnapshotUser`, `SnapshotPort`, `SnapshotService`, `Relation` | nombre, versión…; usuario, uid, algoritmo…; protocolo, familia, dirección, puerto, proceso; gestor, nombre, estado…; IP, papel, origen, detalle | Índices de búsqueda, derivados de la fotografía al guardarla (`indexing.py`). **Solo de las áreas no volátiles:** las relaciones de `processes`, `load`, `connections` y `neighbours` se quedan en el JSON pero no se indexan. |
| `Job` | tipo (`collect`; `scan` reservado para la fase 7), máquina, origen, estado (`queued`, `running`, `done`, `failed`), intentos, `not_before`, fechas, trabajador, motivo, fotografía, solicitante | La cola del trabajador |
| `Schedule` | máquina **o** grupo (restricción `CHECK`), tipo (`interval` cada N horas o `daily` a una hora UTC), activa, `next_run_at` | Una máquina con programación propia queda fuera de la de sus grupos |

Usuarios y roles: `django.contrib.auth`, con los grupos **`administration`** y
**`read-only`** (ver *Seguridad*).

---

## Interfaces y contratos

**Script:**

```
sh aridi-collect.sh > maquina.aridi
ssh host sh -s < aridi-collect.sh > maquina.aridi     (modo "user" del central)
sudo -n /usr/local/libexec/aridi-collect.sh            (modo "sudo" del central)
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

**Central:**

| Interfaz | Qué es |
|---|---|
| `GET /healthz` | Sin autenticación; responde `ok` si la base de datos contesta. Exento de la redirección a HTTPS. |
| `/login/`, `/logout/` (POST) | `django.contrib.auth` |
| `/`, `/machines/<id>/`, `…/history/`, `…/gaps/`, `/snapshots/<id>/` | Lista de máquinas, ficha (áreas en resumen o `?detail=1`, huecos, infraestructura), histórico y huecos con «desde cuándo» |
| `/machines/new/`, `/machines/<id>/edit/`, `/groups/…`, `/schedules/…` | Gestión (rol de administración) |
| `POST /collect/` | Encola recogidas de máquinas (`machine=`) o de un grupo (`group=`) |
| `/jobs/` | Trabajos recientes |
| `/import/` | Subida de un paquete hecho en local (rol de administración) |
| `/search/` | Búsqueda por paquete (`nombre` o `nombre=versión`), puerto (`22` o `tcp/22`), usuario, servicio o IP, **sobre la última fotografía con datos de cada máquina** |
| `manage.py aridi_import FICHERO [--machine NOMBRE \| --create]` | Importación por consola |
| `manage.py aridi_worker [--poll S] [--max-ssh N]` | El trabajador; para con SIGTERM o SIGINT |

La vista de cada área reutiliza el texto del núcleo (`aridi.views.text.area_lines`).

**Fronteras** (vigiladas por pruebas):

- El núcleo solo importa la librería estándar (`tests/test_core_isolation.py`).
- El núcleo nunca importa Django ni `aridi_central` (regla 16 de `CLAUDE.md`).
- Los papeles de relación son códigos enumerados; un papel desconocido es un error de
  validación (`tests/test_core/test_model.py`).

---

## Aspectos transversales

**Configuración.** No hay ficheros de configuración. El script solo admite las dos
variables de límites; el núcleo, los argumentos de la CLI; el central, las variables de
entorno de `settings.py` (ver *El componente central*).

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
tipo de límite de tiempo, origen de la frontera, `PATH`). El central registra en stdout
(`LOGGING` de `settings.py`), incluido el comando `ssh` completo de cada recogida.

**Concurrencia.** Ninguna en el núcleo. En el script, solo el vigilante de tiempo
(`_watch`) corre en segundo plano junto a cada comando cuando no hay `timeout` de
coreutils. En el central, el trabajador usa hilos (ver *El trabajador*).

### El trabajador (`collection/worker.py`)

- **Cola en la base de datos,** sin Celery ni Redis. `claim()` toma un trabajo con un
  `UPDATE … WHERE state='queued'` condicional: solo lo pasa a `running` quien lo
  actualiza. Si otro trabajador se adelanta, busca otros candidatos.
- **Concurrencia limitada** por `ARIDI_MAX_SSH` con un semáforo; un hilo por recogida.
- **`enqueue()`** crea un trabajo por máquina activa con destino SSH que no tenga ya uno
  pendiente.
- **Reintentos:** si la recogida falla y quedan intentos, el trabajo vuelve a la cola con
  `not_before` (1, 2, 4… minutos, como mucho 60). Al agotarlos se guarda una fotografía
  `failed` con el motivo. Un paquete inválido cuenta como fallo.
- **Programación:** `due_schedules()` mueve `next_run_at` con un `UPDATE` condicional y
  solo encola quien lo mueve: **un trabajo por periodo**, aunque se hayan perdido varios.
  Una programación nueva espera a su primer periodo.
- **Parada limpia:** con SIGTERM deja `shutdown_grace` (30 s) a las recogidas en curso; lo
  que sigue en marcha vuelve a la cola sin gastar un intento.
- **Recuperación:** al arrancar, los trabajos `running` con más del doble de
  `ARIDI_SSH_TIMEOUT` vuelven a la cola.
- **Latido:** con `ARIDI_WORKER_HEARTBEAT`, toca un fichero en cada vuelta; lo usa el
  *healthcheck* del contenedor.

### Recogida por SSH (`collection/ssh.py`)

- **Comando:** `ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=…
  -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR [-F config]
  [-o UserKnownHostsFile=…] -p PUERTO [-J SALTOS] -- DESTINO COMANDO`, como lista de
  argumentos (`subprocess.Popen`, nunca `shell=True`). `--` impide que el destino se lea
  como opción, y `ssh_target` y `proxy_jump` se validan dos veces: en el modelo
  (`validators.py`) y al construir el comando.
- **Comando remoto fijo,** sin nada de la máquina dentro:
  - **`sudo`** (decisión de `TODO.md` 5.0): `sha256sum` del script instalado por stderr y
    `exec sudo -n /usr/local/libexec/aridi-collect.sh`. El central compara ese SHA-256 con
    el de su copia y marca `collector_outdated` si difieren.
  - **`user`:** `exec sh -s`, con la copia del central por stdin; se ejecuta como el
    usuario SSH, con huecos `denied` donde haga falta root.
- **Límites:** `ARIDI_SSH_TIMEOUT` (mata `ssh`), `ARIDI_MAX_BUNDLE_BYTES` (mata `ssh` en
  cuanto se pasa) y 64 KiB de stderr.
- **Motivo de fallo:** se clasifica el stderr (clave de *host* desconocida o cambiada,
  autenticación rechazada, nombre no resuelto, conexión rechazada o agotada, `sudo`
  denegado, script no instalado) y se añaden sus últimas líneas.

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
  central (Django, asgiref, sqlparse, gunicorn, packaging) están fijadas con hashes en
  `requirements/central.txt` y se instalan con `--require-hashes`. La imagen no construye
  el proyecto con `pip`, porque eso descargaría `setuptools` sin hash: copia `src/`.
- **Entradas.** El núcleo trata el paquete como no confiable: valida su estructura
  (`bundle.py`) y declara como hueco lo que no puede interpretar.
- **Ficheros de salida.** `aridi interpret -o` crea el fichero con `O_EXCL | O_NOFOLLOW`
  y modo 0600.
- **Central: autenticación y roles.** Todas las páginas salvo `/healthz` exigen sesión.
  Hay dos grupos de Django, creados por la migración `web/0001_roles.py` con sus permisos
  (`web/roles.py`): `read-only`, solo permisos `view_*`, y `administration`, que además
  puede crear y cambiar máquinas, grupos y programaciones, importar (`add_snapshot`) y
  lanzar recogidas (`add_job`). Sin permiso, la vista responde 403; sin sesión, redirige
  al inicio de sesión. Contraseñas de 12 caracteres como mínimo.
- **Central: web.** CSRF en todos los POST; redirecciones solo a la propia web
  (`url_has_allowed_host_and_scheme`); `Content-Security-Policy` sin scripts
  (`default-src 'none'`, `frame-ancestors 'none'`); `X-Frame-Options: DENY`; cookies
  `Secure` y `HttpOnly`; HSTS de un año; redirección a HTTPS detrás del proxy
  (`X-Forwarded-Proto`). Los datos de las máquinas solo salen por el *autoescape* de las
  plantillas, nunca con `|safe`.
- **Central: credenciales.** Ni la base de datos ni la imagen guardan claves: `ssh` usa el
  `ssh-agent` montado (`SSH_AUTH_SOCK`) y un `known_hosts` en solo lectura con
  verificación estricta. **Observado:** `ssh-agent` solo atiende a clientes con su mismo
  uid («uid mismatch: peer euid 10001 != uid 0»), así que el agente debe ejecutarse con el
  uid 10001 del contenedor. En Docker Desktop, el socket `/run/host-services/ssh-auth.sock`
  es un *proxy* del anfitrión (**suposición**: no comprobado en esta fase).
- **Central: escalada.** Regla de `sudoers` limitada al script instalado, sin argumentos
  (`TODO.md` 5.0); un permiso mal puesto en la ruta o en sus directorios padre la
  convertiría en root completo.
- **Central: datos sensibles.** El JSON de cada fotografía y, en las 10 más recientes por
  máquina, el paquete en bruto comprimido. Están filtrados en origen, pero describen el
  parque entero: el volumen `/data` y sus copias hay que protegerlos.
- **Lo que queda abierto:**
  - la redacción de las líneas de órdenes no cubre todas las formas de pasar un secreto;
  - el script instalado en cada máquina hay que actualizarlo a mano cuando cambia (el
    central solo lo detecta).

---

## Estrategia de pruebas

**Punto de entrada único:** `tests/run.sh`. Todo corre en Docker; el Python del
anfitrión no se usa.

| Parte | Qué hace |
|---|---|
| `unit` | `python -m unittest discover -s tests -t .` en `python:3.12-slim`, con el repositorio en solo lectura y sin red |
| `collector` | `tests/collector/test_script.sh`: el script en las 10 imágenes, con cada shell disponible, como root y como uid 65534; comprueba código 0, que no deja rastro, que los datos tras el script en stdin no se ejecutan y los estados esperados; valida los paquetes con `tests/collector/check_bundles.py` |
| `golden` | Regenera el informe de referencia de `tests/test_core/test_text.py` (revisando el diff) |
| `central` | `tests/central/run.sh` (ver abajo) |

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

**Pruebas del central** (`tests/central/run.sh`):

- **Imagen de pruebas** `aridi-central-test` (`tests/central/Dockerfile`): `python:3.12-slim`
  con `requirements/central.txt` instalado con `--require-hashes`, más `openssh-client` y
  `sqlite3`. El repositorio se monta en solo lectura.
- **Sin red:** `manage.py check --deploy --fail-level WARNING` con la configuración de
  producción, y `manage.py test aridi_central` con la base de datos de pruebas en un
  fichero (`ARIDI_TEST_DB_PATH`). Cubren la configuración (WAL, `check --deploy`,
  migraciones al día), el inventario y la importación (todo el corpus), los índices, la
  recogida con un `ssh` falso (argumentos, inyección, *timeout*, salida excesiva), el
  trabajador (dos trabajadores a la vez, un trabajo por periodo, límite de concurrencia,
  parada con SIGTERM) y la web por vista y por rol.
- **Integración SSH:** `tests/central/ssh-target.sh` arranca un `debian:12` con
  `openssh-server` en una red Docker interna, preparado como dice la documentación
  (cuenta `aridi` con la regla de `sudo`, cuenta `nosudo` sin ella, script instalado); las
  pruebas de `collection/tests/test_integration.py` recogen de él de verdad.
- **Humo del despliegue:** `tests/central/smoke.sh`: `docker compose up` con
  `tests/central/compose.smoke.yaml` (un `ssh-agent` como contenedor auxiliar con uid
  10001), superusuario, inicio de sesión, alta y recogida de la máquina de prueba desde
  la web, copia con `sqlite3 .backup`, comprobación de la copia restaurada y
  `docker compose down`.
- **Aceptación de la fase 5** (fuera de `tests/run.sh`, porque crea una VM):
  `tests/lima/central-acceptance.sh` hace lo mismo contra una VM de Lima `debian12-arm64`
  real, más la recogida por programación, la importación de un paquete local, la
  búsqueda y las negativas del rol de consulta. Observado el 2026-10-16: pasa entera.

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

- **Compilación:** no hay. `pip install .` instala el núcleo y la orden `aridi` (y
  descarga `setuptools` para construir).
- **CI:** no hay CI remota (decisión de planificación de `TODO.md`): todo se verifica en
  local con `tests/run.sh`.
- **Distribución:** ninguna publicada. La versión es `2.0.0.dev0`.
- **Despliegue del central** (`Dockerfile`, `compose.yaml`):
  - **Imagen:** `python:3.12-slim` por *digest*, `openssh-client` y `sqlite3`, usuario sin
    privilegios `aridi` (uid y gid 10001), dependencias por hash, `src/aridi` y
    `src/aridi_central` copiados (no instalados), el script en
    `/opt/aridi/aridi-collect.sh`, volumen `/data`. Sin claves ni secretos.
    `.dockerignore` deja fuera todo menos eso (pruebas, corpus, documentos).
  - **Servicios:** `web` (migra al arrancar y lanza gunicorn con 3 *workers*; publicado
    solo en `127.0.0.1:8000`; *healthcheck* a `/healthz` con el primer nombre de
    `ARIDI_ALLOWED_HOSTS`) y `worker` (`aridi_worker`; *healthcheck* por la edad del
    latido; espera a que `web` esté sano; 60 s de gracia al parar). Ambos con
    `restart: unless-stopped`, el volumen `aridi-data`, el socket del agente, y
    `known_hosts` y `ssh_config` en solo lectura.
  - **TLS:** lo pone un proxy inverso delante de `web`.
  - **Copias:** `sqlite3 /data/aridi.db ".backup …"` dentro del contenedor. Para
    restaurar se para el servicio, se sustituye el fichero y se borran `aridi.db-wal` y
    `aridi.db-shm` de la base anterior (`README.md`). La prueba de humo hace las dos cosas
    y comprueba que vuelve la fotografía y desaparece un cambio posterior a la copia.

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

### De la fase 5

| Decisión | Motivo | Cómo se sabe |
|---|---|---|
| Script instalado en `/usr/local/libexec/aridi-collect.sh` con una regla de `sudoers` limitada a él, y comparación de su SHA-256 en cada recogida | Con `sudo sh -s`, quien tenga la clave de aridi o el central tiene root en todo el parque | **Usuario**, 2026-10-16 (`TODO.md` 5.0, `CAMBIO.md`) |
| El paquete en bruto se guarda comprimido, solo en las últimas recogidas de cada máquina (10 por defecto) | Poder reinterpretar con un núcleo mejor, a cambio de más datos sensibles | **Usuario**, 2026-10-16 |
| Modo `user` (script por stdin, sin `sudo`) como alternativa por máquina | Máquinas sin la regla de `sudo`: datos con huecos `denied` mejor que ningún dato | **Deducido** de la opción 3 de `TODO.md` 5.0 |
| La imagen copia `src/` en lugar de `pip install --no-deps .` | Construir el proyecto con `pip` descarga `setuptools` sin hash | **Observado:** falla sin red en `python:3.12-slim` |
| La base de datos de pruebas es un fichero (`ARIDI_TEST_DB_PATH`) | La base en memoria compartida no reproduce el bloqueo real de SQLite entre hilos | **Observado:** con ella, la prueba de concurrencia del trabajador fallaba |
| El agente SSH se ejecuta con el uid 10001 del contenedor | `ssh-agent` rechaza a los clientes con otro uid | **Observado** en la prueba de humo |
| Una importación del mismo fichero devuelve la fotografía ya guardada, antes de buscar la máquina | Las muestras sin `machine_id` no se podían reconocer por máquina | **Observado** en las pruebas de importación |
| Un nombre de *host* que coincide nunca basta para asociar una importación: hay que confirmar la máquina | Dos máquinas pueden llamarse igual; un dato mal asociado es peor que uno que falta | **Deducido** de la regla 12 de `CLAUDE.md` |

---

## Deuda y riesgos

- **Sin comparación ni alertas** (fase 6): el central guarda el histórico, pero todavía
  no avisa de cambios, que es el objetivo del cambio (`IDEA.md`).
- **El script instalado en cada máquina se actualiza a mano.** El central detecta la
  diferencia (`collector_outdated`), pero no la corrige.
- **SQLite y un solo trabajador** son una **suposición** de escala suficiente: no se ha
  medido con muchas máquinas.
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
