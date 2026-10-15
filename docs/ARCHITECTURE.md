# aridi: arquitectura actual

> Este documento describe la arquitectura **que existe** en el commit `4ab279e` (2019-04-12),
> no la que debería existir. La futura está pendiente y parte de [`IDEA.md`](IDEA.md) y
> [`FUTURE.md`](FUTURE.md). Los hechos vienen de leer el código ([`ESTUDIO.md`](ESTUDIO.md)),
> de ejecutarlo en contenedores ([`MVP.md`](MVP.md)) y de la historia de git. Las
> referencias van en la forma `archivo:línea`; lo que no se puede probar va marcado como
> **suposición**.

---

## Visión general

aridi es **un solo proceso de consola, de corta vida, que se ejecuta en la propia máquina
que analiza**. No tiene servidor, base de datos, red propia ni estado entre ejecuciones.
Contado como un diagrama:

```
            usuario (terminal)
                 │  argumentos CLI + respuestas a 7 preguntas input()
                 ▼
   aridi.py ── main() ──────────────────────────────────────────────┐
     │ crea                                                          │
     ▼                                                               │
  Reporting  ◄──── objeto compartido: informe + log + estado ────┐   │
     ▲                                                           │   │
     │ escriben (summarized / detailed / infrastructure / attrs) │   │
     │                                                           │   │
  Precheck (gathering0) ── uid, ficheros legibles, binarios, DNS, services.csv
     │ se pasa a todas las fases                                 │   │
     ▼                                                           │   │
  gathering1 → gathering2 → gathering3 → gathering4 → scan → graph   │
     │            ▲   ▲          │ (llama a _getusers/_getnetinfo)   │
     │            └───┴──────────┘                                   │
     ▼                                                               │
  Fuentes: /proc, /sys, /etc, /var/log  +  ~15 binarios (subprocess) │
           + sockets crudos AF_PACKET (ARP) + TCP connect (scan)     │
                                                                     ▼
  Salidas en el directorio actual: stdout | FILE, aridi.log, aridi.badfiles, network.dot
```

**Cómo se comunican las piezas:**

- **Llamadas directas a funciones.** `main()` invoca una función de entrada por fase
  (`aridi.py:129-191`).
- **Estado compartido** en dos objetos que se pasan a todas las funciones: `report`
  (`reporting.Reporting`) y `precheck` (`gathering0.Precheck`).
- **Globales de módulo:** `process` y `uptime` (`gathering3.py:16-17`); `waiting`,
  `ipmac` y `ports` (`scan.py:12-14`); y `Precheck.portnames`, que es un atributo de clase
  (`gathering0.py:10`).
- **Con el sistema operativo:** lectura de ficheros y ejecución de binarios con
  `subprocess.check_output`.
- **Con la red:** solo en la fase de escaneo y en la resolución DNS.

---

## Stack tecnológico

**No hay manifiesto.** No existe `requirements.txt`, `pyproject.toml`, `setup.py` ni
`Pipfile`. Las versiones que aparecen aquí vienen de leer el código o de observarlo en
ejecución, no de un manifiesto.

| Pieza | Versión | Para qué | Fuente |
|---|---|---|---|
| Python 3 (CPython) | **No declarada.** Mínimo deducido: 3.3 (`subprocess.DEVNULL`, `ipaddress`). Observada funcionando entre 3.6.8 y 3.14.8. | Todo el programa | `#!/usr/bin/env python3` (`aridi.py:1`); `MVP.md` *Cómo se ha medido* |
| Librería estándar | La del intérprete | `argparse` (CLI), `subprocess` (binarios), `os`, `re`, `socket`, `struct` y `binascii` (ARP), `threading` (escaneo), `ipaddress`, `platform` (libc), `resource` (límite de descriptores), `locale`, `datetime`, `traceback` | imports de cada módulo |
| `graphviz` (PyPI) | **No declarada**, sin fijar | Generar `network.dot` y renderizarlo (`--graph`). Se importa de forma perezosa y es opcional. | `graph.py:5-10` |
| Graphviz, binario `neato` | No declarada | Motor de dibujo que usa la librería anterior | `graph.py:23` |
| Binarios del sistema | Los de cada distribución | `lsusb`, `lsblk`, `findmnt`, `df`, `yum`, `dpkg-query`, `zypper`, `apt`, `pacman`, `hostname`, `dnsdomainname`, `hostid`, `ip`, `iptables`, `runlevel`, `systemctl`, `chkconfig`, `utmpdump`, `nslookup`/`dig` | `ESTUDIO.md` §3, con líneas |
| `services.csv` | Sin versión ni origen documentado | Nombres de puertos y lista de puertos a escanear (5.877 líneas `nombre\|puerto\|descripción`) | `gathering0.py:82-98` |

---

## Estructura del proyecto

Todo está en la raíz, sin subdirectorios de código. El repositorio contiene 14 ficheros
versionados y `docs/`.

| Fichero | Líneas | Responsabilidad | Depende de |
|---|---|---|---|
| `aridi.py` | 244 | **Arranque y orquestación:** CLI (`argparse`), precheck, invocación de fases dentro de su propio `try`, elección de la vista y escritura de salidas | todos los demás |
| `gathering0.py` | 208 | **Contexto:** clase `Precheck` (uid y grupos, legibilidad de ~60 ficheros, `checkcommand`, `nslookup`, `loadports`) | — |
| `gathering1.py` | 616 | Fase **general** (`getgeneralinfo`): hardware, sistema operativo, libc, paquetes, discos y recorrido de permisos | `utils` |
| `gathering2.py` | 570 | Fase **específica** (`getspecificinfo`): identidad, usuarios, servicios, red e iptables | `utils` |
| `gathering3.py` | 861 | Fase **volátil** (`getvolatileinfo`): procesos, RAM, CPU, disco, sesiones y sockets | `utils`, **funciones privadas** de `gathering1` y `gathering2` |
| `gathering4.py` | 282 | Fase **carving** (`getotherinfo`): IPs y FQDN en `/etc` y `/var/log` | `utils` |
| `scan.py` | 278 | **Escaneo:** barrido ARP con sockets crudos y escaneo TCP *connect* con hilos | `utils`, función privada `gathering2._getnetinfo` |
| `graph.py` | 76 | **Grafo** con `graphviz` | `graphviz` (opcional) |
| `reporting.py` | 273 | Clase `Reporting`: almacenes del informe, mapa de infraestructura, log y vistas | `utils` |
| `utils.py` | 49 | Cabeceras de texto, conversión de IPs hexadecimales y barra de progreso | — |
| `__init__.py` | 5 | Solo metadatos. **No hace que el directorio funcione como paquete:** los imports son de primer nivel (`import reporting`). | — |
| `services.csv` | 5.877 | Datos de puertos | — |
| `LICENSE`, `README.md` | — | GPL v3; una línea de descripción | — |

**Convenciones internas:**

- Cada fase expone una función pública `get*info(report, precheck)` y funciones privadas
  `_get*()` que devuelven un par `(summ, detail)` de cadenas.
- El orden de los parámetros no es uniforme. Algunas reciben `(report, precheck)`, como
  `_gethostnames` y `_getusers`; otras `(precheck, report)`, como `_getrunningservices`,
  `_getdisk` y `_getuserdata`.
- **Suposición:** es una incoherencia accidental, sin motivo.

---

## Modelo de datos

**No hay almacenamiento persistente, ni motor, ni esquema, ni migraciones.** Todo vive en
memoria durante una ejecución y se pierde al terminar, salvo el texto que se escribe en
ficheros.

**Entidades en memoria** (todas son listas y diccionarios sin tipos declarados):

| Entidad | Dónde | Forma real |
|---|---|---|
| Secciones del informe | `Reporting.summarized_data`, `Reporting.detailed_data` (`reporting.py:12-13`) | Dos listas de 6 listas de cadenas, indexadas por un entero "kind": 0 = ejecución, 1 = general, 2 = específica, 3 = volátil, 4 = otra (carving), 5 = escaneo (`reporting.py:68-94`) |
| Mapa de infraestructura | `Reporting.infrastructure_data` (`reporting.py:14,99-112`) | `dict[IPv4Address \| None, list[str]]`. Cada cadena es un papel en texto libre ("Local machine", "DNS Server", "Port TCP 22 (ssh) with service sshd"…), truncada a 120 caracteres. La clasificación posterior se hace por prefijo de texto (`scan.py:155-169`). |
| Usuarios | `Reporting.users` (`reporting.py:51`, rellenado en `gathering2.py:76`) | `dict[nombre, [tipo_hash, uid(str), gid(str), gecos, home, shell, [grupos]]]` |
| UID → nombre | `Reporting.pidusers` (`gathering2.py:77`) | `dict[int, str]`. El nombre sugiere PID, pero las claves son **UID**. |
| Grupos | `Reporting.groups` | `dict[nombre, ["?", gid, [miembros]]]` |
| Interfaces | `Reporting.ifaces` (`gathering2.py:178-194`) | `dict[iface, [mac] \| [mac, "ip/prefijo"]]`. Solo guarda la última dirección IPv4. |
| Rutas | `Reporting.routes` | `list[[destino, prefijo, gateway, iface]]` |
| Discos | `Reporting.disks`, `mounted`, `unmounted` | Listas posicionales; `mounted` = `[nombre, tamaño, punto, fstype, opciones, usado]` |
| Procesos | global `gathering3.process` | `dict[pid, [comm, estado, euid, usuario, rss_kB, nice, %cpu, cmdline]]` |
| Paquetes | `precheck.packages` (`gathering1.py:478-490`) | `list[[nombre, versión]]`. **Se guardan en `Precheck`, no en `Reporting`:** `Reporting.packages` existe (`reporting.py:40`) y queda vacío. |
| Puertos conocidos | `Precheck.portnames` (atributo de clase) | `dict[int, [nombre, descripción]]` |
| ARP | global `scan.ipmac` | `dict[IPv4Address, "MAC"]` |
| Log | `Reporting.log_data` | `list[[fecha, nivel, texto]]` |

**Relaciones:** la única clave transversal es la **IP** del mapa de infraestructura, que
vincula interfaces, DNS, conexiones, accesos, reglas de cortafuegos, IPs halladas en
ficheros y puertos abiertos. Ningún objeto tiene identificador de máquina o de ejecución.

**Atributos creados sobre la marcha:** fuera de `__init__` se añaden atributos como
`report.total` (`gathering1.py:429`) y `precheck.packages`. Si ninguna rama los crea, el
acceso falla: en Alpine se observó `'Precheck' object has no attribute 'packages'`
(`MVP.md` n.º 14).

---

## Interfaces y contratos

**Línea de comandos** (`aridi.py:43-71`). Es la única interfaz externa:

```
python3 aridi.py [-a] [-g] [-s] [-v] [-c] [--scan] [--graph] [-V NIVEL]
                 [-of | -os | -od | -oi] [FILE]
```

- **Fases:**
  - `-a` activa todas;
  - `-s` implica `-g`;
  - sin `-v` ni `-c` se fuerza `-g` (`aridi.py:80-89`).
- **Vistas:** `-of`, `-os` (por defecto), `-od` y `-oi` son mutuamente excluyentes.
- **`FILE`:** escribe ahí el informe en lugar de en stdout.
- **Códigos de salida:**
  - `0` al terminar, aunque se hayan perdido apartados;
  - `1` si se aborta, porque `sys.exit(<mensaje>)` lo devuelve así (`aridi.py:26,39,92,126,232`);
  - `0` también si el usuario sin root responde «no» (`aridi.py:120`).
- **Entrada interactiva:** 7 llamadas a `input()` que leen una línea de stdin
  (`ESTUDIO.md` §5). Sin terminal provocan `EOFError`.

**Contrato entre `main()` y las fases:**

- Cada `get*info(report, precheck)` no devuelve nada y escribe en `report`.
- `main()` envuelve cada fase en `try/except Exception` y registra el error.
- Las fases envuelven cada subapartado de la misma manera.

**Contrato de los subapartados:** devuelven `(summ, detail)`, que la fase añade con
`report.summarized(kind, …)` y `report.detailed(kind, …)`. Hay excepciones que rompen el
contrato:

- `_gethardware` devuelve 4 valores (`gathering1.py:143`).
- `_getusb` devuelve 3 (`gathering1.py:46`).
- `_getdisks` devuelve listas, no texto (`gathering1.py:284`).
- `_getram` devuelve `None` si no puede leer `/proc/meminfo` (`gathering3.py:541-615`).

**Fronteras rotas entre módulos:**

- `gathering3` importa funciones privadas de otras fases:
  - `_getdisks` (`gathering3.py:5`);
  - `_getusers` y `_getnetinfo` (`gathering3.py:6`).
- `scan` importa `_getnetinfo` (`scan.py:9`).
- Esas funciones se reinvocan si faltan datos, y escriben en `report` como efecto
  secundario.

**Contrato con el sistema operativo:**

- **Salida de los binarios:** se decodifica como UTF-8 y se analiza **por posición de
  columnas** separadas por espacios (por ejemplo, `lsblk -l` en `gathering1.py:243-247` y
  `systemctl list-units` en `gathering2.py:433-442`). No se usan formatos estables como
  `--json`, `-o`, `--output=` o `--plain`. El cambio de formato de `lsblk` ya rompe el
  apartado de discos (`MVP.md` n.º 13).
- **`/proc/net/tcp` y `udp`:** se leen en hexadecimal *little-endian*, solo IPv4
  (`utils.py:31-46`).

**Formatos de salida:**

- Texto en árbol ASCII de 80 columnas (`utils.py:4-28`).
- `aridi.log`: líneas `fecha - NIVEL - texto` (`reporting.py:263-271`).
- `aridi.badfiles`: una frase por fichero (`gathering1.py:589-605`).
- `network.dot`: formato DOT de Graphviz.
- **No hay ningún formato estructurado** (JSON, CSV…).

**Red:**

- **DNS:** a través de `nslookup` o `dig` (`gathering0.py:132-171`).
- **ARP:**
  - tramas Ethernet construidas a mano y enviadas por `AF_PACKET`/`SOCK_RAW` en cada
    interfaz con prefijo mayor que /22 (`scan.py:47-71,245-249`);
  - las respuestas se leen con otro socket crudo (`scan.py:17-44`).
- **TCP connect** con un timeout de 1 s a cada puerto de `services.csv` (`scan.py:108-117`).
- **No escucha ningún puerto.**

---

## Aspectos transversales

**Configuración.** No hay fichero de configuración ni variables de entorno propias. Solo
existen:

- los argumentos de la CLI;
- `$PATH`, que se lee como `os.environ["PATH"]` sin valor por defecto
  (`gathering0.py:107`);
- el directorio actual, del que dependen `./services.csv` (`aridi.py:101`) y todas las
  salidas;
- `-V` (de -1 a 3; 2 por defecto), que solo regula qué llega a `aridi.log`.

**Gestión de errores.**

- **Patrón uniforme:** cada fase y cada subapartado van en su propio
  `try/except Exception`, que registra `ERROR` y la traza en `DEBUG`, y continúa.
- **Efecto:** el programa casi nunca se cae, pero un error borra el apartado entero del
  informe sin dejar rastro en él (`MVP.md` n.º 21 y *Fuera de lo entregado*).
- **Además:**
  - hay `except:` desnudos que se tragan cualquier error: `gathering0.py:97`,
    `gathering2.py:36`, `gathering3.py:122,664,672,674`, `gathering4.py:68,97,189,222`,
    `scan.py:116`, entre otros;
  - un error al crear `aridi.badfiles` provoca a su vez un `UnboundLocalError` en el
    `finally` (`gathering1.py:610-611`).

**Logging y observabilidad.**

- **Logger propio en memoria:** `Reporting.log`, `reporting.py:114-130`. No usa el módulo
  `logging`.
- **Solo se escribe al final,** desde `finish()` (`aridi.py:23-26`). Si el proceso muere
  antes (Ctrl-C, una excepción fuera de los `try`, `kill`), **no queda log**.
- **`ERROR` también se imprime por stdout,** mezclado con el informe (`reporting.py:122-123`).
- **No hay** métricas, trazas ni tiempos por fase.

**Concurrencia y trabajos en segundo plano.** Solo existen en `scan.py`:

- **ARP:** un hilo por cada IP de la subred, cada uno con su propio socket crudo que no se
  cierra (`scan.py:84-91,51`), y un hilo receptor. La coordinación es una espera activa
  sobre `threading.active_count()` y una variable global `waiting` (`scan.py:94-105`).
- **Escaneo TCP:** un hilo por puerto (5.877 por IP), limitado por
  `RLIMIT_NOFILE - 100` mediante espera activa (`scan.py:129-136`), y resultados en una
  lista global `ports`.
- **Fuera del escaneo** no hay trabajos en segundo plano. Las esperas de medición son
  `sleep(1)` (`gathering3.py:400,509`).

**Internacionalización.**

- **No hay.** Los mensajes están en inglés, con alguna palabra en español: "vía" en las
  rutas (`gathering2.py:226,230`). Los mensajes llaman al programa "aridy.py".
- **`setlocale(LC_TIME, '')`** (`gathering3.py:784`) adopta la configuración regional del
  sistema para interpretar fechas con `%b`, que depende del idioma.
- **Toda la salida de los binarios se decodifica como UTF-8**, sin tratamiento de errores.

---

## Seguridad

Esto es una descripción del estado actual; la auditoría es un paso aparte.

- **Autenticación y autorización.** No hay usuarios ni control de acceso. El único
  criterio es el uid del proceso: se recomienda ejecutar como root
  (`aridi.py:110-120`), y `iptables` y el barrido ARP solo se intentan como root
  (`gathering2.py:290`, `scan.py:219`).
- **Secretos.** aridi no maneja credenciales propias, pero **lee secretos del sistema**:
  `/etc/shadow`, del que solo extrae el tipo de hash (`gathering2.py:87-107`), y las líneas
  completas de todos los ficheros de `/etc` y `/var/log`, que copia en el informe cuando
  contienen una IP o un FQDN (`gathering4.py:64-66,185-187`).
- **Validación de entradas.**
  - Los ficheros del sistema y la salida de los binarios se tratan como confiables:
    cualquier formato inesperado provoca una excepción y se pierde el apartado.
  - El contenido controlable por usuarios locales (banners, líneas de registro, nombres
    de proceso) se copia literalmente en el informe.
- **Riesgos concretos de hoy** (detalle en `ESTUDIO.md` §8 y `MVP.md`):
  - **Ficheros de salida con nombre fijo en el directorio actual:**
    - `aridi.log` (`aridi.py:24`), `aridi.badfiles` (`gathering1.py:588`) y
      `network.dot` (`graph.py:23`) se abren siguiendo enlaces simbólicos;
    - ejecutado como root en un directorio compartido, eso permite sobrescribir ficheros
      arbitrarios;
    - se crean `-rw-r--r--` (observado).
  - **Escaneo sin perímetro:** puede dirigir 5.877 conexiones por IP a direcciones de
    terceros que solo aparecen en los registros (`scan.py:155-209`).
  - **Resolución de binarios ambigua:**
    - `checkcommand` mira primero el directorio actual (`gathering0.py:103-104`), pero la
      ejecución usa el nombre a secas a través de `$PATH`;
    - lo comprobado y lo ejecutado pueden ser ficheros distintos, y la ejecución hereda
      el `$PATH` del llamante.
  - **Lectura completa de ficheros** de `/etc` y `/var/log` en memoria con `readlines()`
    (`gathering4.py:30-31,83-84,149-151,204-205`), sin límite de tamaño.
  - **Cadena de suministro.** Como única dependencia de terceros está `graphviz`, opcional
    y sin versión fijada (`graph.py:6`). El resto de lo que se ejecuta son binarios de la
    distribución.

---

## Estrategia de pruebas

**No hay ninguna.** No hay directorio de pruebas, `unittest`, `pytest`, fixtures, datos de
ejemplo ni CI.

- **Comando de pruebas del proyecto:** no existe.
- **Cobertura:** 0 %.
- **Lo único reproducible** es la medición manual de `MVP.md`: el programa sin modificar,
  en contenedores Docker desechables, con respuestas inyectadas por stdin
  (`printf 'y\nn\nn\nn\nm\n' | python3 aridi.py -a --scan -V 3 -of report.txt`). Los
  scripts de esa medición no forman parte del repositorio.
- **Sin cubrir por ningún medio:** barrido ARP, systemd en marcha, sesiones reales,
  `iptables` con reglas, zypper, pacman, x86_64, RHEL/CentOS 6 y el grafo con `graphviz`
  (`MVP.md` *Implementadas, sin verificar*).

---

## Compilación, CI y despliegue

- **Compilación:** no hay. Son fuentes Python interpretadas, y Python solo genera
  `__pycache__` en tiempo de ejecución.
- **Distribución:** no hay paquete, binario, imagen ni versión publicada. La única copia
  es el repositorio `git@github.com:dpgon/aridi.git` (rama `master`, sin etiquetas).
- **Despliegue:** **sin despliegue.** No está en uso en ningún sitio (decisión confirmada
  por el usuario el 2026-10-15). El modo de uso previsto es copiar el directorio a la
  máquina y ejecutar `sudo python3 aridi.py …` desde dentro de él.
- **CI:** no hay.
- **Actualización:** no hay mecanismo; habría que volver a copiar el directorio.

---

## Objetivos de rendimiento

**El proyecto no declara ninguno.** Sí hay medidas:

- **Duración observada** de una ejecución completa (`-a --scan`, escaneo solo de la
  propia máquina, sin red), en contenedores (`MVP.md`):
  - entre 3 y 4 s en Debian 12, Ubuntu 24.04, Rocky 9, Fedora 44 y CentOS 7;
  - 9 s en Alpine 3.20.
- **Escaneo de una IP local** (5.877 puertos): 1 s.
- **Esperas fijas:** al menos 2 s por ejecución con `-v`, por los `sleep(1)` de CPU y
  disco (`gathering3.py:400,509`), y 5 s por cada interfaz en el barrido ARP
  (`scan.py:98`).
- **Sin medir, y con riesgo de crecer mucho en máquinas reales:**
  - el recorrido completo de `/` (`gathering1.py:299`), que atraviesa todos los montajes;
  - el carving, que lee todo `/var/log` en memoria;
  - el cruce de sockets con descriptores, `O(procesos × fds × conexiones)`
    (`gathering3.py:654-675`);
  - el escaneo remoto, que con timeout de 1 s puede tardar segundos o minutos por IP.

---

## Registro de decisiones

Fuentes, de mayor a menor peso: **documentado** (un texto del autor: commit, README o
comentario), **deducido** (del código o de la historia), **usuario** (contado por el
usuario en esta revisión).

| Decisión | Motivo | Cómo se sabe |
|---|---|---|
| Solo librería estándar de Python | Evitar ataques de cadena de suministro | **Usuario** (`IDEA.md`). El código es coherente con ello. |
| Descartar scapy y construir ARP con sockets crudos | Motivo no documentado; coherente con la decisión anterior | **Deducido:** `checkscapy()` en el primer commit (`dfe9502`, 2019-03-21), retirado en `765ee3d` "First alpha release" (2019-04-07) con `scan.py` ya escrito con sockets crudos |
| Usar binarios del sistema en vez de leer siempre `/proc` y `/sys` | Motivo no documentado | **Deducido.** Mezcla incoherente: CPU, memoria, rutas y sockets por `/proc`; discos, interfaces, USB y servicios por binario. |
| Analizar la salida de los binarios como texto por columnas | Motivo no documentado | **Deducido** (`gathering1.py:243-247`, `gathering2.py:433-442`). Los ajustes "Little modification for RH 6" (2019-03-23) son de este tipo. |
| Adaptarse a cada distribución detectando ficheros de release y binarios | Funcionar en distribuciones distintas | **Usuario** y **deducido** (`gathering1.py:155-222,477-491`); commits "pacman support" (`00d0012`) y "zypper support" (`ce28b2b`, `2d26797`) |
| Prioridad de gestores: yum > dpkg-query > zypper > apt > pacman | Motivo no documentado | **Deducido** (`gathering1.py:477-491`) |
| Aislar cada fase y subapartado en `try/except` y seguir | Sacar todo lo posible aunque algo falle | **Deducido** (patrón en todos los módulos); **usuario** («obtiene toda la información que puede») |
| Un único objeto `Reporting` como informe, log y estado | Motivo no documentado | **Deducido** (`reporting.py:5-66`) |
| Salida solo en texto, con dos niveles (resumen y detalle) | Motivo no documentado | **Deducido** (`reporting.py:132-204`) |
| Ejecución interactiva con preguntas `(y/N)` para las tareas lentas o intrusivas | Advertir de que pueden tardar | **Documentado** en los propios mensajes: "it could be very slow" (`gathering1.py:547-549`), "it could take some time" (`gathering4.py:101-103`, `scan.py:232-234`) |
| Retirar el informe de vulnerabilidades con gravedades y sustituirlo por `aridi.badfiles` | Motivo no documentado | **Deducido:** `d8ef315` "minor fixes" (2019-04-05) elimina las llamadas a `report.vulns(...)` y a `dangerousperm()`; `4c08b12` "First beta" (2019-04-09) elimina `vulns_data`. Quedan restos (`reporting.py:96-97`, `gathering0.py:193-208`). |
| Añadir `graphviz` como dependencia opcional | Motivo no documentado; es la única excepción a la librería estándar | **Deducido:** `6919f87` "Added graphviz to make graphs" (2019-04-08) |
| `services.csv` como base de puertos y como lista de escaneo | Motivo y origen no documentados | **Deducido:** añadido en `765ee3d` (2019-04-07) |
| Licencia GPL v3 | Motivo no documentado | **Documentado:** `LICENSE` (2019-04-12, desde la web de GitHub) |

**Decisiones que ya se sabe que van a cambiar** (por decisión del usuario; ver
`IDEA.md` y `FUTURE.md`):

- la ejecución interactiva, que pasa a no hacer preguntas;
- la salida solo en texto, que tendrá además un resultado estructurado;
- el silencio ante los apartados perdidos, que pasarán a declararse;
- el escaneo sin perímetro, que se limitará a redes autorizadas;
- `graphviz` en el colector, que se retira y pasa a la web;
- la ausencia de componente central, de ejecución remota y de histórico.

---

## Deuda y riesgos

**Acoplamiento y diseño**

- **El estado compartido es mutable y sin forma.** `Reporting` y `Precheck` reciben
  atributos sobre la marcha (`gathering1.py:429,478`) y hay globales de módulo
  (`gathering3.py:16-17`, `scan.py:12-14`). Cualquier cambio de orden entre fases puede
  romper otra. Separar recogida, modelo y presentación es caro, porque cada subapartado
  produce el texto final a la vez que extrae los datos.
- **Se importan funciones privadas entre fases** (`gathering3.py:5-6`, `scan.py:9`), que
  escriben en `report` como efecto secundario.
- **La presentación está mezclada con los datos.** El mapa de infraestructura guarda los
  papeles como frases en inglés y luego se clasifican por prefijo de texto
  (`scan.py:155-169`). Cambiar un mensaje cambia el comportamiento.
- **Datos en listas posicionales** (`mounted[part][5]`, `process[pid][7]`), sin tipos ni
  nombres.
- **Funciones casi idénticas duplicadas:** `_getetc` y `_getlog`, `_getetcfqdn` y
  `_getlogfqdn` (`gathering4.py`); ramas INPUT y OUTPUT de iptables (`gathering2.py:304-377`).

**Fragilidad frente a los sistemas actuales** (observado en `MVP.md`)

- **El análisis por columnas de la salida de los binarios** ya está roto con el `lsblk`
  actual (`gathering1.py:243-247`) y con `yum` en Fedora 44 (`gathering1.py:361-363`).
- **Las suposiciones sobre los datos del sistema** anulan apartados enteros:
  - nombre de interfaz igual en `ip link` y en `ip addr` (`gathering2.py:183,192`);
  - todo uid o miembro de grupo está en `passwd` (`gathering2.py:112`,
    `gathering3.py:638,652`);
  - al menos 10 procesos con CPU (`gathering3.py:136-152`).
- **Solo IPv4,** en todos los módulos.
- **30 secuencias de escape inválidas** en expresiones regulares, que dan `SyntaxWarning`
  en Python 3.12 o superior: `gathering0.py`, `gathering2.py`, `gathering3.py` y
  `gathering4.py`.

**Sin red de seguridad**

- **No hay pruebas, CI ni manifiesto.** Cualquier corrección se verifica solo a mano.
- **El log solo se escribe al final** (`aridi.py:23-26`). Un fallo fuera de los `try`, o un
  Ctrl-C, no deja rastro.
- **Los `except:` desnudos** ocultan los errores reales (lista en *Gestión de errores*).

**Recursos y concurrencia**

- **Esperas activas** que consumen CPU (`scan.py:94-103,131-136`).
- **Sockets que no se cierran** (`scan.py:19,51,109`) y un hilo receptor que puede no
  terminar si no llegan paquetes (`scan.py:21-22`).
- **Lectura sin límite** de ficheros completos (`gathering4.py`) y **recorrido de `/`
  atravesando montajes** (`gathering1.py:299`).

**Dependencias y versiones**

- **`graphviz` sin versión fijada** ni declarada (`graph.py:6`).
- **Ninguna versión de Python declarada.** Se ha observado funcionando de 3.6.8 a 3.14.8.
  RHEL/CentOS 6 (Python 2.6) queda fuera sin decirlo en ningún sitio.
- **`services.csv`** no tiene origen, fecha ni columna de protocolo.

**Código muerto** (detalle en `MVP.md` *Abandonadas*)

- `Reporting.vulns()` (`reporting.py:96-97`).
- `Precheck.dangerousperm()` y `_perm()` (`gathering0.py:193-208`).
- La lectura de NTP, inalcanzable (`gathering2.py:260`).
- Las categorías de `interesting_files` (`gathering0.py:12-71`).
- `Reporting.filename`, `Reporting.packages` y `Reporting.usb` (`reporting.py:9,40,23`).
- `report.total` (`gathering1.py:429`).
