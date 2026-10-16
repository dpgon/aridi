# aridi: cambio de rumbo

> Decidido con el usuario el 2026-10-15. Parte de [`ESTUDIO.md`](ESTUDIO.md),
> [`IDEA.md`](IDEA.md), [`MVP.md`](MVP.md), [`FUTURE.md`](FUTURE.md) y
> [`ARCHITECTURE.md`](ARCHITECTURE.md), que describen el proyecto **tal como es hoy**.
> Este documento decide; no implementa nada. Las duraciones son estimaciones
> (**suposición**: una persona a tiempo completo con ayuda de un agente).

## El cambio, en un párrafo

aridi pasa de ser **un script interactivo** que se ejecuta a mano en una máquina y
devuelve un informe de texto, sin guardar nada, a ser **un sistema de dos piezas**:

- **Un colector sin dependencias ajenas:** un script POSIX `sh` que recoge en bruto, más
  un intérprete en Python 3.12 que solo usa la librería estándar. Llega a cada máquina
  por SSH, no pregunta nada, no deja rastro y devuelve un resultado estructurado que
  declara lo que no ha podido ver.
- **Un componente central** en Django 5.2 LTS, distribuido como contenedor. Programa las
  recogidas, guarda el inventario y su histórico en SQLite, permite buscar en todo el
  parque, compara fotografías y avisa de los cambios significativos.

El colector de 2019 **se reescribe por completo** tomándolo como especificación, y el
componente central se construye desde cero.

## Por qué

**Con las palabras del usuario:**

> «Lo quiero para darle una vuelta completa, actualizarlo a versiones actuales y
> evolucionarlo a un servicio remoto, que tenga el aplicativo, lo pueda enviar a una
> máquina vía ssh, ejecutarlo allí y recibir por la misma via la información, que un
> segundo componente debe poder centralizar para tener el control de las máquinas, y ver
> sus evoluciones, alertando de cambios significativos entre ejecuciones.»
>
> «Me preocupa que […] esté muy desactualizado, sea incompatible contra distribuciones
> modernas o tenga problemas serios de seguridad.»

**Lo que lo justifica técnicamente:**

- **La preocupación se confirmó en ejecución.** En contenedores con Debian 12, Ubuntu
  24.04, Rocky 9, Fedora 44, Alpine 3.20 y CentOS 7, ocurre lo siguiente (`MVP.md`):
  - 11 funcionalidades se pierden o dan datos erróneos;
  - los hashes yescrypt se clasifican como si no hubiera contraseña;
  - no se ve IPv6;
  - el apartado de discos se rompe con el `lsblk` actual;
  - una interfaz `eth0@ifN` hace perder toda la red;
  - en Fedora y Alpine no se obtienen paquetes;
  - sin terminal se pierden apartados.
- **Lo que pide la evolución no cabe en el diseño actual.** Cada función `_get*()` extrae
  los datos y escribe el texto final a la vez. El estado se comparte mediante objetos
  mutables y variables globales, y hay funciones privadas que se usan entre módulos
  (`ARCHITECTURE.md`, *Deuda*). Producir un resultado estructurado y declarar lo que
  falta obliga a abrir todas las funciones.
- **Comparación de costes del colector.** Adaptarlo costaría unas 5–6 semanas y
  cambiaría cerca del 80 % de las líneas, conservando además la deuda. Reescribirlo con
  el actual como especificación costaría unas 4–5 semanas y permite tener pruebas desde
  el primer día.
- **Los requisitos de `IDEA.md` chocan con un colector en Python.** Hay que llegar a
  contenedores sin Python y a RHEL/CentOS 6 (Python 2.6, kernel 2.6.32) **sin instalar
  nada**. Solo un script `sh` lo cumple.

---

## El reparto

Cada parte del proyecto tiene un destino: **conservar**, **adaptar**, **reescribir** o
**abandonar**. **Ninguna línea de código de 2019 llega al producto final.** Lo que se
aprovecha es el conocimiento, los datos y la licencia.

| Parte | Destino | Motivo | De qué depende / qué depende de ella |
|---|---|---|---|
| `aridi.py` | **Abandonar** (al llegar a la paridad) | La CLI interactiva y la orquestación se sustituyen por la CLI del intérprete y por el central | Punto de entrada; nada lo importa |
| `gathering0.py` | **Reescribir** | La idea se conserva: detectar permisos, ficheros y herramientas pasa a alimentar los huecos declarados. `interesting_files` queda como especificación. | Lo usan todas las fases; `scan.py` usa `portnames` |
| `gathering1.py` | **Reescribir** | El análisis de `/proc/meminfo` y de los gestores de paquetes sirve de especificación; el de CPU (falla en ARM) y el de `lsblk` (falla hoy), de contraejemplo | `gathering3.py` importa `_getdisks` |
| `gathering2.py` | **Reescribir** | Concentra la mayoría de los fallos (`MVP.md` n.º 12, 15, 18, 19) | `gathering3.py` y `scan.py` importan `_getusers` y `_getnetinfo` |
| `gathering3.py` | **Reescribir** | Las fórmulas de `/proc/stat` y `/proc/<pid>/stat` son especificación útil | Nada lo importa |
| `gathering4.py` | **Reescribir** | El carving alimenta el mapa de relaciones; hay que añadir journald y límites de tamaño | Nada lo importa |
| `scan.py` | **Reescribir** (etapa 4) | Barrido ARP y escaneo pasan a ser descubrimiento pasivo en la máquina más escaneo activo desde el central | Depende de `portnames` y de `_getnetinfo` |
| `graph.py` | **Abandonar** | Decidido: sale del colector y el mapa pasa a la web | Lee `report.routes` e `infrastructure_data` |
| `reporting.py` | **Reescribir** | Pasa a ser el modelo de datos más sus vistas de texto. **Se conservan** el concepto de mapa de infraestructura y los dos niveles de lectura. | Todos los módulos escriben en él |
| `utils.py` | **Abandonar** | Las cabeceras pasan a las vistas; la conversión de IPs se reescribe con IPv6 | Todas las fases |
| `services.csv` | **Adaptar** | Se regenera desde el registro de IANA con fecha y columna de protocolo. Pasa a ser un dato del central. | `loadports`: nombres de puertos y lista de escaneo |
| `__init__.py` | **Abandonar** | Lo sustituye un empaquetado real (`pyproject.toml`) | Nada |
| `LICENSE` (GPL v3) | **Conservar** | Sin cambio de licencia. Antes de publicar, confirmar la autoría (`ESTUDIO.md` §10). | Todo el repositorio |
| `README.md` | **Adaptar** | Se describe el sistema nuevo. Se conservan la frase original del autor y el inglés. | — |
| `CLAUDE.md` | **Adaptar** | Reglas nuevas (dos paquetes, corpus, contrato de formato); `legacy/` en lugar de la raíz | — |
| `docs/*.md` | **Adaptar** | Ver *Qué documentos hay que reescribir* | — |
| Historia de git | **Conservar** | El cambio se hace en el mismo repositorio | — |
| Componente central | **Nuevo** | No existe nada | — |

---

## La arquitectura de destino

### Visión general

```
 Máquina inventariada (cualquier Linux del alcance)
 ┌───────────────────────────────────────────────┐
 │  ssh … "sudo -n sh -s" < aridi-collect.sh     │  nada se escribe en disco
 │  → lee /proc, /sys, /etc, journal y binarios   │  presentes; filtra en origen
 │  → paquete en bruto por stdout                 │  lo sensible
 └───────────────────────┬───────────────────────┘
                         │ SSH (OpenSSH del sistema, ssh-agent)
 Central (docker compose)▼
 ┌──────────────────────────────────────────────────────────────┐
 │ worker: manage.py aridi_worker                               │
 │   cola en BD → lanza ssh → paquete en bruto                  │
 │   → aridi.interpret (núcleo) → fotografía JSON               │
 │   → guarda + indexa → compara con la anterior → alertas      │
 │   → escaneo activo de redes autorizadas (etapa 4)            │
 │ web: gunicorn + Django (plantillas en servidor)              │
 │   inventario, histórico, búsqueda, diff, alertas, mapa, admin│
 │ volumen: SQLite (WAL) │ socket del ssh-agent del anfitrión   │
 └──────────────────────────────────────────────────────────────┘
          ▲ HTTPS a través del proxy inverso del administrador (TLS)

 Modo local: sh aridi-collect.sh > maquina.aridi   (en la máquina)
             aridi report maquina.aridi            (en cualquier equipo con Python 3.12)
             importación del paquete en el central
```

### Stack

| Pieza | Versión | Para qué | Dependencias ajenas |
|---|---|---|---|
| Script de recogida | POSIX `sh` (dash, bash, busybox ash) | Recoger en bruto en la máquina inventariada | **Ninguna.** Usa las herramientas que existan; si falta alguna, lo declara. |
| Núcleo `aridi` | Python 3.12 | Interpretar el paquete en bruto, modelo de datos, JSON, informe de texto y CLI | **Ninguna** (solo la librería estándar) |
| Central `aridi_central` | Django 5.2 LTS sobre Python 3.12 | Web, autenticación y roles, ORM y migraciones, trabajador | `Django`, `asgiref`, `sqlparse` (fijados con `--require-hashes`) |
| Servidor WSGI | gunicorn 23 | Servir Django dentro del contenedor | `gunicorn`, `packaging` |
| Base de datos | SQLite 3 (el del módulo `sqlite3`), modo WAL | Inventario, histórico, cola de trabajos, alertas | — |
| SSH | OpenSSH cliente (`openssh-client` de la imagen) | Llegar a las máquinas | Paquete de Debian de la imagen |
| Imagen | `python:3.12-slim` | Distribución del central | Paquetes de Debian de la imagen base |
| Orquestación | `docker compose` | Servicios `web` y `worker`, volumen y socket del agente | — |

### Estructura del repositorio

```
legacy/                    código de 2019 tal cual (se borra al llegar a la paridad)
collector/
  aridi-collect.sh         script POSIX de recogida; versión en cabecera
src/aridi/                 núcleo: solo librería estándar; NUNCA importa Django
  bundle.py                lectura del paquete en bruto (secciones, estado, versión)
  model.py                 modelo de la fotografía (dataclasses) y esquema JSON versionado
  parsers/                 un módulo por área: system, hardware, packages, storage,
                           users, services, network, firewall, processes, sessions,
                           permissions, carving, neighbours
  views/                   informe de texto: resumen y detalle
  cli.py                   `aridi report|interpret|validate <paquete>`
src/aridi_central/         proyecto Django: importa `aridi`, nunca al revés
  settings.py, urls.py
  inventory/               máquinas, grupos, fotografías, índices, búsqueda, importación
  collection/              destinos SSH, programación, cola, comando aridi_worker
  changes/                 comparación, reglas, ajustes por máquina o grupo, alertas, avisos
  discovery/               redes autorizadas, escaneo activo, services.csv
  web/                     plantillas, vistas, mapa de relaciones
tests/
  corpus/                  paquetes en bruto reales por distribución y entorno
  test_parsers/            pruebas del núcleo con el corpus (unittest de la librería estándar)
  test_central/            pruebas de Django
pyproject.toml             dos distribuciones: `aridi` (sin dependencias) y `aridi-central`
Dockerfile, compose.yaml
```

### Formatos y contratos

**El paquete en bruto** es la salida del script.

- Es texto que el script escribe por la salida estándar.
- Empieza con una cabecera `ARIDI-BUNDLE <versión_formato> <versión_script>`.
- Se divide en secciones, cada una delimitada por una frontera aleatoria por ejecución.
- Cada sección lleva:
  - un nombre;
  - un estado: `ok`, `denied`, `missing` (herramienta ausente), `na` (no aplica),
    `timeout` o `error`;
  - el código de salida;
  - el contenido.
- El script **filtra en origen** lo sensible. De `/etc/shadow` solo sale el usuario y el
  prefijo del algoritmo, nunca el hash.
- El script tiene límites: tiempo máximo por sección, tamaño máximo de las lecturas, y el
  recorrido de permisos se hace con `find -xdev` (solo sistemas de ficheros locales).

**La fotografía** es el JSON que produce el núcleo.

- Contiene `schema_version`, la identidad de la máquina (`/etc/machine-id`, hostname),
  `collected_at`, la versión del colector y `sections`.
- Para cada sección: `status`, `reason` y `data`. Los volátiles van en secciones marcadas
  como `volatile`.
- **El esquema está versionado desde el primer día.** Es el contrato con los datos
  guardados (ver *Riesgos*).

**La CLI del núcleo:**

- `aridi report <paquete>` genera el informe legible (resumen o detalle).
- `aridi interpret <paquete>` genera la fotografía JSON.
- `aridi validate <paquete>` comprueba el formato.

**Las fronteras entre partes:**

- El script no sabe nada de Python.
- El núcleo no sabe nada de Django.
- El central llama al núcleo como librería.

### Modelo de datos (central, SQLite)

| Entidad | Campos clave | Notas |
|---|---|---|
| `Machine` | nombre, destino SSH (`usuario@host`), puerto, `ProxyJump`, grupos, programación, activa | **No guarda credenciales** |
| `Group` | nombre, programación por defecto | — |
| `Snapshot` | máquina, `collected_at`, origen (SSH, importado o a demanda), `schema_version`, JSON completo, resultado (completa / con huecos / fallida), paquete en bruto comprimido (opcional) | El JSON se guarda entero; el paquete en bruto, solo en las últimas recogidas |
| Índices de búsqueda | `SnapshotPackage(nombre, versión)`, `SnapshotUser`, `SnapshotPort(proto, ip, puerto, proceso)`, `SnapshotService`, `Relation(ip, papel)` | Se derivan del JSON al guardarlo; solo de lo no volátil |
| `Gap` | fotografía, sección, estado, motivo | Responde a «qué no se pudo ver y desde cuándo» |
| `Job` | tipo (recogida, escaneo), objetivo, estado, intentos, fechas | Es la cola del `aridi_worker` |
| `Rule`, `RuleOverride` | regla de serie, gravedad; ajuste o silencio por máquina o grupo | — |
| `Alert`, `Channel` | cambio, gravedad, estado; canal (correo, webhook…) | Los canales concretos están pendientes (`IDEA.md`) |
| `AuthorizedNetwork`, `ScanResult` | CIDR autorizado; resultados del escaneo activo | Etapa 4 |
| Usuarios y roles | `auth` de Django con dos grupos: **administración** y **consulta** | Una instalación por equipo |

**Migraciones:** las de Django (`manage.py migrate`). **Copias de seguridad:**
`sqlite3 aridi.db ".backup …"` sobre el volumen.

**Paquete en bruto (decidido por el usuario el 2026-10-16, TODO.md 5.0):** el central
**guarda el paquete en bruto comprimido (gzip), solo de las últimas recogidas de cada
máquina** (por defecto 10, configurable con `ARIDI_RAW_RETENTION`), además de la
fotografía JSON, que se guarda siempre. Así puede reinterpretar las recogidas recientes
cuando mejoren los analizadores. El precio: más datos sensibles en el central, aunque ya
filtrados en origen. Sustituye a la decisión menor anterior de no guardarlo.

### Aspectos transversales

- **Configuración del central:** variables de entorno en `compose.yaml` (`SECRET_KEY`,
  hosts permitidos, ruta de la base de datos). Las máquinas, la programación, las reglas y
  las redes se configuran en la web.
- **Errores:** nunca se omiten. Toda sección fallida produce un `Gap` con su motivo, y el
  código de salida de la CLI distingue entre completa, con huecos y fallida.
- **Logging:** el módulo `logging` de la librería estándar, hacia stdout del contenedor.
- **Concurrencia:** el `aridi_worker` lanza las recogidas con un límite configurable de
  conexiones SSH simultáneas; la cola es la tabla `Job`. Sin Celery ni Redis.
- **Pruebas:** `python -m unittest` para el núcleo, contra el corpus; `manage.py test`
  para el central. Están en CI desde la etapa 0. La plataforma de CI está pendiente.
  - **Nota (2026-10-15, planificación de `TODO.md`):** se decidió **no tener CI
    remota**. Todo se verifica en local con `tests/run.sh`, que ejecuta las pruebas en
    contenedores Docker.

### Seguridad de destino

- **Credenciales:** el central no guarda claves privadas. Usa el `ssh-agent` del
  anfitrión (socket montado) y `known_hosts` con verificación estricta.
- **Escalada de privilegios (decidido por el usuario el 2026-10-16, TODO.md 5.0):
  script instalado.** El script se instala en la máquina en una ruta fija,
  `/usr/local/libexec/aridi-collect.sh`, de root y en solo lectura (con directorios
  padre también de root), y la regla de `sudoers` solo permite esa ruta, sin argumentos:
  `aridi ALL=(root) NOPASSWD: /usr/local/libexec/aridi-collect.sh ""`. El central lanza
  `sudo -n` sobre esa ruta.
  - **Por qué:** con `sudo sh -s`, quien robe la clave de la cuenta de aridi o controle
    el central tiene root en todo el parque. Con la ruta fija solo puede lanzar el
    colector, que es de solo lectura.
  - **El precio:** queda un fichero en cada máquina («ningún rastro» pasa a ser «ningún
    rastro salvo el script instalado»), y hay que actualizarlo cuando cambie el script.
    En cada recogida, el central compara el SHA-256 del script instalado con el de su
    copia; si no coincide, lo marca como desactualizado.
  - **Sin `sudo`** (cuenta sin la regla), la recogida sigue siendo posible como usuario
    normal, con huecos `denied`.
- **Datos sensibles:** el filtrado se hace en origen (hashes), la web exige autenticación
  y hay dos roles. La base de datos queda en un volumen que hay que proteger.
- **Datos no fiables:** todo lo que viene de las máquinas (banners, líneas de registro,
  nombres de proceso) se escapa en la web. Las plantillas de Django lo hacen por defecto.
- **Escaneo:** solo desde el central y solo hacia `AuthorizedNetwork`.

---

## Qué se pierde

- **Todo el código de 2019, unas 3.460 líneas.** Se borra al llegar a la paridad y solo
  queda en la historia de git.
- **La CLI actual y sus opciones** (`-g -s -v -c -a --scan --graph -os -od -of -oi`).
  Cualquier costumbre o script basado en ella deja de funcionar.
- **El formato exacto del informe de texto actual.** Habrá un informe legible nuevo,
  distinto.
- **El grafo local `--graph`** y `network.dot`. El mapa existe solo en la web del central.
- **El barrido ARP activo desde la máquina.** Los equipos de su red local que nunca le
  hayan hablado ya no se descubren.
- **El escaneo de puertos visto desde la propia máquina.** El central ve la red desde su
  posición, y los cortafuegos pueden hacer que vea algo distinto.
- **El escaneo de IPs de terceros encontradas en los registros.** Se pierde a propósito.
- **La resolución DNS de los FQDN encontrados en `/etc` y `/var/log`.** Queda aparcada
  (`FUTURE.md`).
- **El modo local de una sola pieza.** Pasa a ser recoger con `sh` en la máquina e
  interpretar con Python 3.12 en cualquier equipo. **En una máquina sin Python 3.12 el
  informe no se puede leer allí mismo.**
- **«Cero dependencias» en todo el producto.** El central añade 5 paquetes de PyPI y la
  imagen base `python:3.12-slim`. El colector sigue sin dependencias.
- **La interpretación local en Python 3.6.** Hoy el script funciona con el Python de
  CentOS 7. El intérprete nuevo exige 3.12, aunque el script de recogida sí funciona en
  CentOS 7.
- **Usuarios afectados:** ninguno, porque no hay despliegues (`ARCHITECTURE.md`).
- **Datos que no migran:** ninguno, porque aridi nunca ha guardado nada.
- **Trabajo que se tira:** las funciones `_get*()` como código. Su conocimiento pasa a
  las pruebas y a los analizadores.

## Migración

**No hay datos ni usuarios que migrar.** aridi no tiene almacenamiento persistente y no
está desplegado en ningún sitio (decisión confirmada el 2026-10-15). La transición es solo
de código:

- en el primer commit del cambio, el código de 2019 se mueve tal cual a `legacy/`, sigue
  ejecutable y se documenta como obsoleto;
- se borra cuando el colector nuevo cubra todos sus apartados, comprobado contra la lista
  de `MVP.md`.

## Alternativas consideradas y descartadas

| Decisión | Alternativa descartada | Por qué se descartó |
|---|---|---|
| Reescribir el colector | **Adaptarlo por pasos**, manteniendo `gathering0` a `gathering4` | Cuesta lo mismo o más (5–6 semanas frente a 4–5), cambia cerca del 80 % de las líneas y deja dentro la mezcla de datos y texto que impide el resultado estructurado y los huecos declarados |
| | **Mixto**: núcleo nuevo con los análisis antiguos trasladados casi literales | Los análisis que funcionan son pocos y pequeños. Trasladarlos ahorra poco y arrastra su estilo sin pruebas. Se reutilizan como especificación. |
| Script `sh` más intérprete en Python | **Colector entero en Python ≥ 3.6** enviado por SSH | Deja fuera RHEL/CentOS 6 y los contenedores sin Python, que están en el alcance decidido en `IDEA.md`, o los obliga a una recogida mínima |
| | **Binario estático en Go 1.25** | Deja de ser Python, añade otra cadena de herramientas y Go 1.25 no admite el kernel 2.6.32 de RHEL 6 |
| Django 5.2 LTS en el central | **Solo librería estándar** (`http.server`, sesiones y CSRF escritos a mano) | Escribir a mano la autenticación y la protección web es un riesgo de seguridad mayor que 3 dependencias LTS fijadas por hash |
| | **FastAPI más SQLAlchemy 2 más React 19** | Decenas de dependencias en Python y cientos en npm, en contra del principio de reducir la cadena de suministro |
| SQLite (WAL) | **PostgreSQL 17** con `psycopg` 3 | Otro servicio que operar y otra dependencia con código C, sin necesidad para cientos de máquinas. Django permite migrar más adelante. |
| | **Ficheros JSON en disco con un índice aparte** | Dos fuentes de verdad que mantener coherentes |
| Cola en la base de datos con `aridi_worker` | **Celery con Redis** | Más dependencias y otro servicio para un volumen pequeño |
| Credenciales en el `ssh-agent` | **Claves cifradas en la base de datos** con clave maestra | Convierte el central en un almacén de claves de todo el parque |
| | **Claves y contraseñas por máquina** introducidas en la web | Lo mismo, y además contraseñas |
| Contenedor con `docker compose` | **Wheel más systemd** con gunicorn | Era la recomendación por su integración directa con el `ssh-agent`. **El usuario eligió el contenedor**; el coste es montar el socket del agente y `known_hosts`. |
| | **Ambos** | Doble superficie de distribución que mantener |
| Código de 2019 en `legacy/` hasta la paridad | **Dejarlo en la raíz** | Mezcla lo viejo y lo nuevo en el mismo nivel |
| | **Borrarlo al empezar** | Deja un hueco sin herramienta hasta la paridad |
| Volátiles guardados, sin alertas | **Eliminarlos** | Se pierde lo que el usuario ve hoy en el informe |
| | **Alertas por umbral sobre volátiles** | Ruido en cada fotografía. Eso es trabajo de un sistema de monitorización (no objetivo en `IDEA.md`). |
| Descubrimiento pasivo y escaneo desde el central | **Escaneo desde la máquina si tiene `nmap` o `arping`** | Resultados desiguales entre máquinas y tráfico generado desde máquinas que deberían solo leerse |
| | **Abandonar el escaneo activo** | El usuario decidió conservarlo de forma opcional y acotada (`IDEA.md`) |

## Ruta por etapas

`legacy/` sigue funcionando durante las etapas 0 y 1, así que **en ningún momento hay un
hueco sin herramienta**.

| Etapa | Contenido | Qué queda en pie al final | Duración aproximada |
|---|---|---|---|
| **0. Base** | Mover el código a `legacy/`. Crear la estructura, `pyproject.toml`, las pruebas y la CI. **Corpus de paquetes en bruto** de Debian, Ubuntu, Rocky, Fedora, Alpine, CentOS 7, openSUSE y Arch en contenedores, más una VM con systemd y sesiones reales (x86_64 y arm64). | `legacy/` funciona igual que hoy. El esqueleto nuevo compila y pasa pruebas vacías. | 1 semana |
| **1. Colector nuevo** | `aridi-collect.sh`, analizadores área por área, fotografía JSON versionada, informe legible, huecos declarados, filtrado en origen y límites. **Criterio de paridad:** todas las funcionalidades de `MVP.md` (entregadas, a medias y sin verificar que se conserven) funcionan con datos correctos en el corpus. | Cada área cerrada funciona en el colector nuevo, en modo local. **Al llegar a la paridad se borra `legacy/`.** | 4–5 semanas |
| **2. Inventario central** | Proyecto Django, máquinas y grupos, SSH con agente, `aridi_worker` y programación, recogida a demanda, importación, histórico, búsqueda, huecos por máquina, roles, `Dockerfile` y `compose.yaml` | Inventario utilizable de todo el parque | 4–6 semanas |
| **3. Cambios y alertas** | Comparación de fotografías, reglas de serie ajustables por máquina o grupo, alertas en la web y por canales externos, alerta por máquinas que no responden, mapa de relaciones en la web | Todo `IDEA.md` salvo la exploración de red | 2–3 semanas |
| **4. Exploración de red** | Descubrimiento pasivo (vecinos ARP e IPv6), que puede adelantarse a la etapa 1, y escaneo activo desde el central sobre `AuthorizedNetwork` | Todo `IDEA.md` | 1–2 semanas |

## Riesgos

- **Punto de no retorno: las primeras fotografías reales guardadas en el central**
  (etapa 2). Desde entonces, el formato del paquete y el esquema JSON son un contrato
  con datos que habrá que migrar. Mitigación: los dos llevan versión desde la etapa 1, y
  la paridad se verifica antes de la etapa 2. Borrar `legacy/` **no** es un punto de no
  retorno, porque se recupera de git.
- **Portabilidad del script `sh`.** dash, bash, busybox ash y el `sh` de CentOS 6 se
  comportan distinto, y algunas herramientas faltan o cambian sus opciones. Mitigación:
  el corpus por distribución y las pruebas del script en cada imagen dentro de la CI.
- **Escalada con `sudo`.** **Decidido (2026-10-16):** script instalado en una ruta fija
  con una regla de `sudoers` limitada a ella (ver *Seguridad de destino*). Riesgos que
  quedan:
  - un script desactualizado en alguna máquina, mitigado con la comparación del SHA-256
    en cada recogida;
  - un permiso mal puesto en la ruta o en sus directorios padre convertiría la regla en
    root completo. La documentación de instalación da los comandos exactos.
- **Datos sensibles en el central.** La base de datos describe usuarios, servicios
  expuestos y debilidades de todo el parque. Mitigación: filtrado en origen, roles, y un
  volumen y unas copias protegidos.
- **Alcance de red del contenedor.** El escaneo activo y el SSH dependen de que el
  contenedor llegue a las redes y de que el socket del agente esté montado. Hay que
  documentarlo en la instalación.
- **Estimaciones.** Son suposiciones. La etapa 1 es la que más puede crecer, porque cada
  distribución nueva del corpus descubre casos nuevos.
- **Autoría y licencia.** Antes de publicar el sistema nuevo, confirmar quién tiene los
  derechos (`ESTUDIO.md` §10).

## Qué documentos hay que reescribir

**No se reescriben ahora:** es trabajo del cambio y va en la lista de tareas.

### `docs/IDEA.md`

- **Funcionalidad principal, punto 1 (Recogida):** deja de ser cierto que la recogida
  completa la hace el programa en la máquina. Pasa a ser recogida en bruto en la máquina
  más interpretación aparte.
- **Funcionalidad principal, punto 3 (Descubrimiento y escaneo):** pasa a ser
  descubrimiento pasivo en la máquina más escaneo activo desde el central, con las
  pérdidas de *Qué se pierde*.
- **Funcionalidad principal, punto 5 (Modo local):** pasa a ser de dos pasos, y el
  informe legible exige Python 3.12 en algún equipo.
- **Principios:** «cero dependencias ajenas» se acota al colector; el central tiene
  dependencias fijadas por hash.
- **Recorrido D (auditoría):** se reescribe con los dos pasos.
- **Glosario:** añadir *paquete en bruto*, *intérprete*, *núcleo* y *red autorizada* (con
  su lugar en el central).

### `docs/MVP.md`

- **Todo el documento** describe el código de 2019. Pasa a describir `legacy/` mientras
  exista y, al llegar a la paridad, el colector nuevo.
- **Cómo se ha medido** se sustituye por las pruebas automáticas sobre el corpus.
- **Las categorías** se mantienen.

### `docs/FUTURE.md`

- **Etapas 1 a 4:** se renumeran y se ajustan a la ruta de este documento (añadir la
  etapa 0).
- **1.2 a 1.5:** se cumplen con el script `sh` más el intérprete.
- **1.6:** se precisa que RHEL 6 y los contenedores sin Python se cubren con el script.
- **1.10:** ya resuelta.
- **2.x:** se concreta con Django, SQLite y `docker compose`.
- **4.1:** se reescribe como descubrimiento pasivo más escaneo desde el central.
- **Ideas aparcadas:** añadir guardar el paquete en bruto para reinterpretarlo.

### `docs/ARCHITECTURE.md`

- **Todo el documento** describe la arquitectura de 2019.
- Pasa a describir la arquitectura de destino de este documento, a medida que se
  construya:
  - visión general, stack, estructura, modelo de datos, interfaces, transversales,
    seguridad, pruebas, compilación y despliegue;
  - el registro de decisiones se amplía con las de este cambio.
- Lo actual se conserva como sección histórica sobre `legacy/` hasta que se borre.

### Otros

- **`README.md`:**
  - instalación del central con `docker compose`;
  - uso del modo local en dos pasos;
  - pruebas;
  - índice de `docs/` con `CAMBIO.md`.
- **`CLAUDE.md`:**
  - estructura nueva;
  - regla de que `aridi` (núcleo) no importa Django;
  - mínimo de Python 3.12 en el núcleo y el central, y `sh` POSIX en el script;
  - contrato de versión del formato;
  - el corpus como única forma de verificar;
  - `legacy/` en lugar de la raíz;
  - la regla de Python 3.6 deja de aplicarse fuera de `legacy/`.
- **Falta en el repositorio (para la lista de tareas):**
  - `.gitignore`;
  - `pyproject.toml`;
  - `Dockerfile`;
  - `compose.yaml`;
  - configuración de CI.
