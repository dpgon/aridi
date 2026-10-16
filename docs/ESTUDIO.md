# Estudio del proyecto aridi

> Estudio hecho el 2026-10-15 leyendo el código del commit `4ab279e` (rama `master`).
> No se ha ejecutado el programa. Lo único que se ha ejecutado son comprobaciones que
> no ejecutan el código del proyecto: `git log`, `grep`, contar líneas y *compilar* los
> fuentes con `compile()` de Python 3.9.6 para ver qué avisos da el compilador.
> Las referencias van en la forma `archivo:línea`. Cuando algo es una inferencia y no
> sale directamente de un archivo, aparece marcado como **suposición**.

---

## 1. En una página

**Qué es.** aridi es una herramienta de línea de comandos en Python 3. Se ejecuta *en
local* sobre una máquina Linux y genera un **informe de texto** con el perfil del
sistema: hardware, distribución, paquetes instalados, discos, usuarios, servicios,
red, cortafuegos, procesos, conexiones y sesiones. Opcionalmente también busca IPs y
nombres de dominio en `/etc` y `/var/log`, hace un barrido ARP de la red local y un
escaneo de puertos TCP contra las IPs que ha descubierto. La descripción que da el
propio repositorio es "Linux information gathering and infrastructure scanner"
(`README.md:2`).

**Cómo está hecho.** Son unas 3.460 líneas de Python repartidas en 11 módulos planos
(no hay paquetes ni subdirectorios), más una tabla de 5.877 puertos (`services.csv`).
No tiene manifiesto de dependencias, ni pruebas, ni empaquetado. Usa solo la librería
estándar, con **una excepción**: el paquete `graphviz` de PyPI, que se importa de forma
opcional para dibujar el grafo de red (`graph.py:6`). Además llama a **muchos binarios
del sistema** (`lsblk`, `ip`, `systemctl`, `utmpdump`, `iptables`, el gestor de
paquetes y otros).

**En qué estado está.** Lo escribió una sola persona en tres semanas, entre el
2019-03-21 y el 2019-04-12: 45 commits, y no se ha tocado desde entonces. El código se
autodenomina `"Development"` (`aridi.py:8`) y los últimos commits se titulan "First
beta". Es una **beta funcional pensada para un uso interactivo**: hace siete preguntas
`(y/N)` por consola durante la ejecución, y la salida es texto con forma de árbol, no
datos estructurados. La lectura del código revela:

- **Fallos que hacen que los datos sean incorrectos sin dar ningún error.** Un ejemplo
  es que los hashes `yescrypt` de las contraseñas se clasifican como "No password".
  `yescrypt` es el formato por defecto en las distribuciones de 2021 en adelante.
- **Puntos de las distribuciones modernas que no ve.** Solo lee IPv4 (no ve
  `/proc/net/tcp6`), no consulta journald, no conoce nftables a secas, y no trata `dnf`
  ni `apk` como gestores propios.
- **Riesgos de seguridad.** Escribe los ficheros de salida con nombre fijo en el
  directorio actual, y puede llegar a escanear puertos de IPs de terceros que solo
  aparecen en los logs.

**Distancia a lo que se quiere.** El usuario quiere un servicio remoto que se envíe por
SSH, se ejecute en la máquina y devuelva los datos a un componente central que compare
ejecuciones. Nada de eso existe todavía: no hay modo no interactivo, no hay salida en
JSON, no hay identificación de máquina ni de ejecución y no hay nada que compare un
informe con otro.

---

## 2. Qué hace, funcionalmente

Lo que se consigue con cada opción de la línea de comandos (`aridi.py:43-71`):

| Opción | Lo que obtienes | Dónde se implementa |
|---|---|---|
| `-g` / por defecto | **Inventario general:** CPU (sockets, núcleos, flags, *bugs* de CPU), RAM y swap, dispositivos USB, kernel, distribución y versión, versión de libc, lista de paquetes instalados con su versión, discos y particiones con su ocupación. Opcionalmente, tras preguntar, un recorrido completo de `/` buscando directorios escribibles por todos sin *sticky bit*, ficheros escribibles por todos y binarios SUID/SGID, que vuelca en `aridi.badfiles`. | `gathering1.py:408` |
| `-s` | **Configuración específica** (incluye `-g`): hostname, dominio, hostid, banners (`issue`, `motd`); usuarios y grupos, con el algoritmo del hash de la contraseña si se ejecuta como root; servicios systemd en ejecución, fallidos y en otros estados, o los de SysV vía `chkconfig`; interfaces, IPs, rutas y DNS; reglas `iptables` de INPUT y OUTPUT. | `gathering2.py:511` |
| `-v` | **Estado en vivo:** procesos con su estado, top 10 por CPU y por RAM, y zombis; memoria detallada; carga y uptime; uso de CPU desde el arranque y en el último segundo; carga de disco en el último segundo; descriptores e inodos; usuarios conectados, últimos accesos (`wtmp`) e intentos fallidos (`btmp`) con las IPs de origen; sockets TCP y UDP con el proceso que los abrió. | `gathering3.py:782` |
| `-c` | **"Carving":** busca IPs y FQDN en todos los ficheros de `/etc` y `/var/log`, con la opción (preguntada) de resolverlos por DNS. | `gathering4.py:253` |
| `-a` | Todo lo anterior. | `aridi.py:80-84` |
| `--scan` | **Escaneo:** barrido ARP de las subredes locales de /23 o menores (solo como root), y escaneo TCP *connect* de los 5.877 puertos de `services.csv` contra las categorías de IPs que el usuario elige de forma interactiva. | `scan.py:217` |
| `--graph` | Un grafo de red (`network.dot` y su render) con las pasarelas, las subredes, la máquina y las IPs descubiertas. Requiere `pip install graphviz`. | `graph.py:4` |
| `-os` / `-od` / `-of` / `-oi` | El informe resumido (por defecto), el detallado, el completo, o solo el árbol de "infraestructura" (IP → lo que se sabe de ella). | `reporting.py:132-244` |
| `FILE` | Guarda el informe en un fichero en vez de imprimirlo. | `aridi.py:29`, `aridi.py:199-229` |
| `-V n` | Ajusta qué niveles van al log (`aridi.log`). | `aridi.py:75-77`, `reporting.py:114` |

Hay una idea transversal que es valiosa: el **"mapa de infraestructura"**. Todos los
módulos van anotando cada IP que encuentran junto con su papel: "Local machine", "DNS
Server", "Logged", "Failed logging", "IPTables allowed input IP", "Connected at
port…", "Named in file…", "MAC…" (`reporting.py:99`). El resultado es una vista de con
quién habla la máquina, y es probablemente lo más diferencial del proyecto.

---

## 3. Cómo está hecho

- **Lenguaje:** Python 3. No se declara ninguna versión mínima en ningún sitio. Por las
  APIs que usa (`subprocess.DEVNULL`, `ipaddress`, `print(..., end="")`) bastaría con
  Python 3.3 o superior (**suposición** a partir de las APIs; no hay f-strings ni
  sintaxis moderna).
- **Dependencias de Python:** solo la librería estándar (`os`, `re`, `subprocess`,
  `socket`, `struct`, `threading`, `ipaddress`, `platform`, `resource`, `locale`,
  `argparse`, `datetime`), con una excepción:
  - `graphviz` (PyPI), que se usa solo en `--graph` y se importa de forma perezosa con
    un fallback si falta (`graph.py:5-10`). Además necesita el binario `neato` de
    Graphviz (`graph.py:23`, `engine='neato'`).
- **No hay** `requirements.txt`, `pyproject.toml`, `setup.py`, Makefile, Dockerfile ni
  CI. `__init__.py` solo contiene metadatos (`__init__.py:1-5`), y los módulos se
  importan entre sí como si fueran de primer nivel (`import reporting`,
  `from gathering1 import …`). Por eso **no funciona como paquete importable**, solo como
  script.
- **Dependencias de binarios del sistema operativo.** Son la parte importante, porque
  contradicen la idea de "Python puro":

| Binario | Para qué | Dónde |
|---|---|---|
| `lsusb` | Dispositivos USB | `gathering1.py:17` |
| `lsblk`, `findmnt`, `df` | Discos, particiones y ocupación | `gathering1.py:240,261,278` |
| `yum`, `dpkg-query`, `zypper`, `apt`, `pacman` | Paquetes instalados | `gathering1.py:346-405,477-491` |
| `hostname`, `dnsdomainname`, `hostid` | Identidad | `gathering2.py:19,31,40` |
| `ip` | Interfaces y direcciones | `gathering2.py:181,188` |
| `iptables` | Reglas del cortafuegos (solo como root) | `gathering2.py:296` |
| `runlevel`, `systemctl`, `chkconfig` | Servicios | `gathering2.py:409,429,453` |
| `utmpdump` | Sesiones (`utmp`, `wtmp`, `btmp`) | `gathering3.py:208-308` |
| `nslookup` o `dig` | Resolución DNS | `gathering0.py:136-171` |

  La comprobación de que un binario existe (`Precheck.checkcommand`, `gathering0.py:101`)
  busca primero en el directorio actual y después en `$PATH`. Sin embargo, la ejecución
  real usa el nombre sin ruta (`check_output(["lsblk", …])`), así que lo que se comprueba
  y lo que se ejecuta pueden no ser el mismo fichero.
- **Lo que lee directamente del kernel o de ficheros, sin binarios:** `/proc/cpuinfo`,
  `/proc/meminfo`, `/proc/net/route`, `/proc/net/tcp`, `/proc/net/udp`, `/proc/<pid>/*`,
  `/proc/stat`, `/proc/loadavg`, `/proc/diskstats`, `/proc/sys/fs/*`, `/sys/block`,
  `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/hosts`, `/etc/resolv.conf` y los
  ficheros de release.
- **Red cruda:** el barrido ARP construye las tramas a mano con sockets
  `AF_PACKET`/`SOCK_RAW` (`scan.py:47-71`) y escucha las respuestas en otro socket crudo
  (`scan.py:17-44`).

---

## 4. Estructura

Todo está en la raíz del repositorio; no hay subdirectorios.

| Módulo | Responsabilidad | Piezas clave |
|---|---|---|
| `aridi.py` | Punto de entrada: interpreta argumentos, hace el *precheck*, llama a cada fase dentro de su propio `try` y emite el informe y `aridi.log`. | `main()` `:34`, `finish()` `:23` |
| `gathering0.py` | Contexto de ejecución: uid y grupos, qué ficheros "interesantes" son legibles, localización de binarios, resolución DNS y carga de `services.csv`. | `class Precheck` `:8`, `interesting_files` `:12`, `checkcommand` `:101`, `nslookup` `:132` |
| `gathering1.py` | Fase **general**: hardware, sistema operativo, libc, paquetes, discos y el recorrido de permisos. | `getgeneralinfo` `:408`, `_checkpermissions` `:287`, `_get{yum,dpkg,zypper,apt,pacman}` |
| `gathering2.py` | Fase **específica**: identidad, usuarios y grupos, servicios, red e iptables. | `getspecificinfo` `:511`, `_getusers` `:67`, `_getnetinfo` `:163`, `_getiptables` `:288`, `_getrunningservices` `:402` |
| `gathering3.py` | Fase **volátil**: procesos, RAM, CPU, disco, sesiones y sockets. | `getvolatileinfo` `:782`, `_getprocessdata` `:25`, `_getnetdata` `:618`, `_getuserdata` `:192` |
| `gathering4.py` | Fase **carving**: IPs y FQDN en `/etc` y `/var/log`. | `getotherinfo` `:253`, `_getetc` `:10`, `_getlog` `:129`, `_get*fqdn` |
| `scan.py` | Barrido ARP (con sockets crudos) y escaneo TCP *connect* con un hilo por puerto. | `scaninfrastructure` `:217`, `_localnetworkarpscan` `:74`, `_ipscan` `:120` |
| `graph.py` | Grafo de red con `graphviz`. | `makegraph` `:4` |
| `reporting.py` | Acumula los textos del informe (resumen y detalle, 6 secciones), el mapa de infraestructura y el log, y los formatea. También sirve de "bolsa" de estado compartido entre las fases. | `class Reporting` `:5`, `infrastructure()` `:99`, `view_*` |
| `utils.py` | Formato de cabeceras, conversión de IPs hexadecimales de `/proc/net/*` y barra de progreso. | `converthex2ip` `:31`, `percentagebar` `:42` |
| `services.csv` | 5.877 líneas `nombre\|puerto\|descripción`, sin columna de protocolo. Se usa para dar nombre a los puertos y como **lista de puertos a escanear**. De dónde sale no consta; **suposición:** del registro de IANA. | `gathering0.py:82` |
| `__init__.py` | Solo metadatos (autor, licencia "GPL", versión 1.0). No hace nada. | — |
| `LICENSE` | GPL v3. | — |

---

## 5. Flujo principal

1. **Arranque:** `python3 aridi.py [opciones] [FILE]` → `main()` (`aridi.py:243-244`).
2. **Se crea el contenedor de estado `Reporting()`** (`aridi.py:37`). Ese objeto es a la
   vez el informe, el log y la memoria compartida entre las fases: se le añaden atributos
   sobre la marcha, como `report.total` (`gathering1.py:429`), que no está en `__init__`.
3. **Se interpretan los argumentos** (`aridi.py:43-89`). `-a` activa todas las fases y
   `-s` activa también la general. Si no se pide `-v` ni `-c`, se fuerza la fase general.
4. **Precheck** (`aridi.py:96-126`):
   - `Precheck()` guarda el uid y los grupos, y marca la legibilidad y los permisos de unos
     60 ficheros de `interesting_files` (`gathering0.py:73-79,179-185`).
   - `loadports("./services.csv")` (`aridi.py:101`) busca el fichero **relativo al
     directorio actual**, no al del script. Si no lo encuentra, desactiva `--scan`.
   - Si no se ejecuta como root, **pregunta por consola** si se quiere continuar
     (`aridi.py:115-120`).
5. **Fases**, cada una aislada en su `try` (`aridi.py:129-167`):
   `getgeneralinfo` → `getspecificinfo` → `getvolatileinfo` → `getotherinfo`. Cada
   función interna devuelve un par de cadenas `(summ, detail)`, que se añaden con
   `report.summarized(n, …)` y `report.detailed(n, …)`. Por el camino se rellenan atributos
   de `report` (`users`, `ifaces`, `routes`…) y el mapa `infrastructure_data`. Si una fase
   necesita datos de otra que no se ha ejecutado, la vuelve a llamar por su cuenta:
   `gathering3.py:789-790` llama a `_getusers` y `:852-853` a `_getnetinfo`;
   `scan.py:223-224` también llama a `_getnetinfo`.
6. **Escaneo** (`aridi.py:170-178`): el barrido ARP pregunta antes de empezar
   (`scan.py:232-235`), y el escaneo de puertos pregunta qué categorías de IP escanear
   (`scan.py:171-179`).
7. **Grafo** (`aridi.py:181-191`): pregunta si se dibuja todo o solo el segmento local
   (`graph.py:13-15`).
8. **Salida** (`aridi.py:194-233`): se elige la vista y se imprime o se guarda en `FILE`.
9. **Cierre:** `finish()` escribe `aridi.log` en el directorio actual y sale
   (`aridi.py:23-26`).

**Preguntas interactivas que bloquean una ejecución desatendida** (`input()`):
`aridi.py:118`, `gathering1.py:550`, `gathering4.py:105`, `gathering4.py:229`,
`scan.py:179`, `scan.py:235` y `graph.py:15`. Sin una terminal, `input()` lanza un
`EOFError`. En el caso del *precheck* sin root, eso acaba en "Failed in the precheck
stage" (`aridi.py:123-126`).

---

## 6. Datos e interfaces

- **Almacenamiento:** no hay base de datos ni estado entre ejecuciones. Todo vive en
  memoria, dentro del objeto `Reporting` y de los globales de módulo `process` y `uptime`
  (`gathering3.py:16-17`) y `waiting`, `ipmac` y `ports` (`scan.py:12-14`).
- **Ficheros que escribe**, todos en el **directorio actual**, con nombre fijo,
  sobrescribiéndolos y con los permisos que dé la umask:
  - `aridi.log` (`aridi.py:24`).
  - `aridi.badfiles` (`gathering1.py:588`).
  - `network.dot` y su render (`graph.py:23,75`).
  - `FILE`, si se indica (`aridi.py:30`).
- **Formato de salida:** solo **texto libre** con formato de árbol ASCII de 80 columnas
  (`utils.py`). No hay JSON, CSV ni ningún otro formato estructurado. Los datos
  estructurados sí existen en memoria (`report.users`, `report.ifaces`,
  `report.infrastructure_data`, etc.), pero nunca se serializan.
- **Formatos que lee:** `services.csv` (`nombre|puerto|descripción`); los formatos de
  `/proc` (incluidas las IPs en hexadecimal *little-endian*, `utils.py:31-46`); la salida
  textual de los binarios de la sección 3, cuyo análisis depende de columnas y espacios
  (`gathering1.py:243-247`, `gathering2.py:433-442`); y la salida de `utmpdump`
  (`gathering3.py:221-228`).
- **Red:**
  - Consultas DNS a través de `nslookup` o `dig` (`gathering0.py:132`).
  - Tramas ARP crudas por cada interfaz con IP y prefijo mayor que /22 (`scan.py:245-249`).
  - Conexiones TCP *connect* con un hilo por puerto, a las IPs elegidas (`scan.py:108-138`).
  - No expone ningún puerto ni API, y no habla con ningún servidor.
- **CLI:** la tabla de la sección 2. No usa códigos de salida distintos según el error:
  `sys.exit(mensaje)` devuelve 1 y `finish(report, 0)` devuelve 0 (`aridi.py:26`).

---

## 7. Construcción, ejecución y pruebas

**Construcción:** no hay nada que construir.

**Ejecución.** Estos son comandos leídos del código, **no comprobados**, porque no se ha
ejecutado el programa:

```sh
cd /ruta/a/aridi            # necesario: services.csv se busca en ./ (aridi.py:101)
sudo python3 aridi.py       # resumen de la fase general, por pantalla
sudo python3 aridi.py -a -od informe.txt   # todo, informe detallado a fichero
sudo python3 aridi.py -a --scan -oi        # todo + escaneo, árbol de infraestructura
pip install graphviz && sudo python3 aridi.py -s --graph   # con grafo
```

**Lo que sí se ha comprobado:** se compilaron los 11 `.py` con `compile()` en Python
3.9.6, sin ejecutarlos. Todos compilan, pero `gathering0.py` (3 avisos),
`gathering2.py` (2), `gathering3.py` (13) y `gathering4.py` (12) generan avisos de
**secuencia de escape no válida** (`"\d"` en expresiones regulares que no son *raw
strings*, por ejemplo `gathering0.py:133`). En 3.9 es un `DeprecationWarning`
silencioso. En Python 3.12 o superior pasa a ser un `SyntaxWarning` que se ve en
pantalla, y está anunciado que en el futuro será un error.

**Pruebas:** no hay ninguna. No hay directorio `tests`, ni `unittest` o `pytest`, ni CI.

---

## 8. Estado

### Terminado (al nivel de una beta)

- **Las cuatro fases de recolección y las vistas de informe están implementadas de
  principio a fin**, con aislamiento de errores por fase y por subapartado. Cada bloque
  va en un `try` que deja el error en el log (`gathering1.py:411-503`, etc.).
- **La detección de distribución** cubre `os-release`, `lsb-release`, CentOS, Red Hat,
  Fedora y SuSE (`gathering1.py:155-222`).
- **La detección del gestor de paquetes** cubre yum, dpkg, zypper, apt y pacman, en ese
  orden de prioridad (`gathering1.py:477-491`).
- **El mapa de infraestructura** se alimenta desde todos los módulos.

### A medias o con fallos (por lectura de código; ninguno se ha reproducido)

**Datos incorrectos sin error visible:**

- **Hashes modernos tratados como "sin contraseña".** Solo se reconocen `$1$`, `$2a$`,
  `$2y$`, `$5$` y `$6$` (`gathering2.py:93-104`). `yescrypt` (`$y$`), que es el formato
  por defecto en las distribuciones actuales, `$2b$`, y las cuentas bloqueadas (`!`, `*`)
  acaban en `"No password"`.
- **El contador de MD5 siempre es 0.** `umd5` nunca se incrementa (`gathering2.py:117,152`).
- **Nombres que se pierden en el resumen.** Al partir las líneas largas de usuarios y
  grupos, el elemento que provoca el salto se descarta (`gathering2.py:121-125,131-135,145-149`).
- **El detalle de `dnsdomainname` imprime el hostname** en lugar del dominio
  (`gathering2.py:35`).
- **UDP en escucha siempre sale como 0.** Se aplica la tabla de estados TCP a UDP, y un
  socket UDP en escucha aparece en `/proc/net/udp` con el estado 07, no con LISTEN (10)
  (`gathering3.py:648,756`).
- **La "carga de disco en %" sale cien veces menor.** Se divide entre 1000 un tiempo en
  milisegundos medido durante un segundo, lo que da una fracción, no un porcentaje
  (`gathering3.py:425-434`).
- **El porcentaje de ocupación compara cifras con unidades distintas.** Los valores de
  `df -h` se comparan sin normalizar unidades (`gathering3.py:416-418`): "1T" frente a
  "500G" da un resultado erróneo.
- **La versión de cada paquete en Debian es la del paquete fuente**
  (`${source:Version}`, `gathering1.py:396`), no la del binario instalado.
- **Los paquetes no se guardan donde se espera.** Se guardan en `precheck.packages`
  (`gathering1.py:478-490`), no en `report.packages`, que se declara y queda vacío
  (`reporting.py:40`).

**Fallos que anulan un apartado entero (el `try` lo captura y el apartado desaparece):**

- **El top 10 de procesos asume que hay al menos 10 procesos con CPU y con RSS**
  (`gathering3.py:136,152`). En un contenedor, el apartado de procesos falla con
  `IndexError`.
- **Un uid sin entrada en `/etc/passwd`** hace fallar todo el apartado de sockets
  (`report.pidusers[uid]`, `gathering3.py:638,652`). Es el caso habitual con LDAP, SSSD o
  contenedores. Lo mismo pasa con un miembro de grupo que no está en `passwd`
  (`gathering2.py:112`).
- **Interfaces con `@`** (`eth0@if5`, VLANs, veth). `ip -o link` las nombra con `@` y
  `ip -o address` sin él, así que la búsqueda `interfaces[line[1]]` lanza `KeyError` y se
  pierde toda la información de red (`gathering2.py:183,192`). **Suposición** sobre la
  salida exacta de `ip`; habría que contrastarla en una máquina real.
- **Un PID de `utmp` que ya no existe en `process`** provoca un `KeyError` y se pierden
  las sesiones (`gathering3.py:238,241`).
- **El mapa de infraestructura puede recibir la clave `None`.** Ocurre cuando
  `nslookup()` no resuelve, por ejemplo con un DNS IPv6 en `resolv.conf`
  (`gathering2.py:254`, `gathering0.py:132-171`). Después, `sorted()` falla al mezclar
  `None` con `IPv4Address` en `-oi` (`reporting.py:209-210`) y en `--scan`
  (`scan.py:155`). Se ha comprobado aparte que Python lanza ese `TypeError`.

**Mal implementado:**

- **El barrido ARP:** un hilo y un socket crudo por cada IP, sin cerrar ningún socket;
  esperas activas con `while …: pass` (`scan.py:94-103,131-136`); y el hilo que escucha
  solo termina al recibir otro paquete (`scan.py:21-22`). El tamaño de red admitido es
  incoherente: cuenta las redes de /22 (`scan.py:229`) pero solo escanea las mayores de
  /22 (`scan.py:246`).
- **La opción `(f) IPTables allowed` del escaneo se ofrece** (`scan.py:171`) **pero no se
  procesa** (`scan.py:181-195`).
- **Si falla el `open` de `aridi.badfiles`, el `finally: f.close()` lanza
  `UnboundLocalError`** (`gathering1.py:587-611`).
- **NTP nunca se lee.** `/etc/ntp.conf` no está en `interesting_files`, así que
  `shouldread` siempre devuelve falso (`gathering2.py:260`, `gathering0.py:12-71`). El
  resumen de NTP, además, consulta `len(report.dns)` en vez de `len(report.ntp)`
  (`gathering2.py:274`).

### Muerto

- **`Precheck.dangerousperm()` y `_perm()`** (`gathering0.py:193-208`) **nunca se llaman**
  (verificado con grep). La comprobación de permisos de `passwd` y `shadow` no llega al
  informe.
- **`Reporting.vulns()`** (`reporting.py:96-97`) **no se llama nunca y está roto**:
  `self.vulns_data` no existe.
- **El segundo campo de `interesting_files`** (los números del 0 al 18 que agrupan
  categorías, `gathering0.py:12-71`) se guarda pero no se usa para nada.
  `/var/log/message` (sin la `s` final) y `/etc/debian-version` (el fichero real es
  `debian_version`) apuntan a rutas que no existen; también
  `/suse/etc/SuSE-release`. **Suposición** sobre las rutas canónicas, que son las
  habituales.
- **`report.total`** (`gathering1.py:429`), **`Reporting.filename`** (`reporting.py:9`) y
  **`report.usb`** (`reporting.py:23`) se asignan o declaran pero no se leen.
- **Código comentado:** `gathering3.py:231-236`. No hay ningún
  `TODO`/`FIXME`/`XXX` (verificado con grep).
- **`__init__.py`:** el proyecto no se puede importar como paquete.

### Compatibilidad con distribuciones modernas (por lectura de código)

- **Solo IPv4.** Lee `/proc/net/tcp` y `udp` pero no `tcp6` ni `udp6`
  (`gathering3.py:626,640`); solo `inet` en `ip -o address` (`gathering2.py:191`); solo
  la ruta IPv4 (`gathering2.py:212`). Los servicios que escuchan en `[::]`, que es lo
  habitual hoy, no aparecen.
- **No usa journald.** `journalctl` no aparece en el código (verificado con grep). Las
  distribuciones que ya no instalan rsyslog por defecto no tienen `auth.log`, `secure` ni
  `syslog`, así que la fase de carving encontrará mucho menos. **Suposición** sobre los
  valores por defecto de cada distribución.
- **Cortafuegos:** solo `iptables -S` (`gathering2.py:296`). En un sistema con nftables
  puro no verá nada. No mira `ip6tables`, `nft`, `firewalld` ni `ufw`. Las reglas FORWARD
  nunca se añaden (`gathering2.py:302-377`).
- **Paquetes:** no llama a `dnf` ni a `apk` por su nombre. Depende de que `yum` exista
  como alias y de analizar su salida en bloques de 3 *tokens* (`gathering1.py:364-368`),
  que se descuadra con cualquier línea que no tenga exactamente 3 columnas. Alpine,
  sin `apt`, `dpkg` ni `yum`, cae en "Packages manager not found".
- **Init:** systemd o `chkconfig`. OpenRC y runit no.
- **Sesiones:** depende de `utmpdump` y de los ficheros `utmp`, `wtmp` y `btmp`. Algunas
  distribuciones recientes están migrando a `wtmpdb`/`lastlog2` por el problema del año
  2038 (**suposición**: está por verificar distribución a distribución).
- **Python:** los avisos de escape inválido de la sección 7.

### Seguridad

- **Salida con nombres fijos en el directorio actual, como root.** `open("aridi.log", "w")`,
  `open("aridi.badfiles", "w")` y `network.dot` siguen los enlaces simbólicos. Si se
  ejecuta como root en un directorio escribible por otros (por ejemplo `/tmp`), cualquier
  usuario local puede hacer que root sobrescriba un fichero arbitrario
  (`aridi.py:24`, `gathering1.py:588`, `graph.py:23`).
- **Informes sensibles con permisos por defecto.** El informe y `aridi.badfiles` contienen
  usuarios, algoritmos de hash, servicios, puertos abiertos y la lista de ficheros
  escribibles por todos y SUID. Se crean con la umask del proceso, normalmente 644: legibles
  por cualquiera.
- **Escaneo de terceros.** La categoría "Carved IPs" (y "a", todas) incluye IPs que solo
  aparecen en logs o en `btmp`, como las de atacantes o servicios externos. El escaneo
  lanzaría 5.877 conexiones TCP a cada una (`scan.py:155-209`, `gathering3.py:306-324`,
  `gathering4.py:129-195`). Es un riesgo legal y operativo si se automatiza.
- **Carga de ficheros enteros en memoria.** Todos los ficheros de `/etc` y `/var/log` se
  leen completos con `readlines()` (`gathering4.py:30-31,149-151`), incluidos logs y
  ficheros binarios grandes. Los errores se ignoran con `except: pass`.
- **Datos no fiables en el informe.** Los banners (`issue`, `motd`) y las líneas de logs se
  copian tal cual (`gathering2.py:47-62`, `gathering4.py:186`). Hoy es solo texto, pero si
  se muestra en una consola web central será un vector de inyección.
- **Resolución de binarios.** `checkcommand` mira primero el directorio actual
  (`gathering0.py:103-104`) y lee `os.environ["PATH"]` sin valor por defecto: si `PATH`
  no existe, lanza `KeyError`. La ejecución depende del `PATH` heredado, cosa relevante
  si se lanza con `sudo` por SSH.
- **Robustez.** Hay `except:` desnudos por todo el código (`gathering0.py:97`,
  `gathering4.py:68,97,189,222`, `scan.py:116`, etc.), que ocultan los fallos.

---

## 9. Lo que el proyecto dice y no cumple

| Afirmación | Fuente | Lo que dice el código |
|---|---|---|
| "Sin depender de librerías externas, solo Python puro" | Usuario | Cierto **solo para los módulos de Python**, y con la excepción de `graphviz` (`graph.py:6`). El programa depende de una docena de binarios del sistema y del análisis de su salida en texto (sección 3). La cadena de suministro se reduce a lo que trae la distribución, pero no es "puro". |
| "Monitorizar sistemas Linux" | Usuario | Es un **perfilado puntual**: una ejecución, un informe de texto. No guarda histórico, no tiene formato estructurado y no compara ejecuciones. |
| "Se ajusta automáticamente a distribuciones y gestores de paquetes" | Usuario | Lo hace con las de 2019: yum, dpkg, zypper, apt y pacman, más systemd o chkconfig. No contempla dnf de forma explícita, apk, OpenRC, nftables, IPv6 ni journald (sección 8). Algunas rutas de release están mal escritas. |
| "Obtiene toda la información que puede" | Usuario | Casi: los fallos se aíslan por apartado y el programa sigue adelante. Pero varios apartados desaparecen enteros por un solo dato inesperado (sección 8, "anulan un apartado"), y no queda rastro en el informe, solo en `aridi.log` si `-V 3`. |
| "Se ejecuta en local" | Usuario | Cierto, pero de forma **interactiva**: 7 preguntas por consola. Sin terminal, falla en el *precheck* si no es root. |
| "Linux information gathering and infrastructure scanner" | `README.md:2` | Correcto, y es lo único que dice el README: no hay instrucciones de uso. |
| Licencia "GPL" | `__init__.py:2`, `aridi.py:5` | `LICENSE` es GPL **v3**. Los ficheros fuente no llevan cabecera de licencia. |
| Nombre del programa | — | Los mensajes dicen "aridy.py" (`aridi.py:114-116`, `gathering1.py:547`, `gathering1.py:607`), pero el fichero se llama `aridi.py`. |
| Opción `-g` | `aridi.py:47` | Se presenta como "default option", pero si se pasa `-v` o `-c` sin `-g`, la fase general no se ejecuta (`aridi.py:87-89`). Es coherente con el código, pero la ayuda no lo explica. |
| Ayuda de `FILE` | `aridi.py:70-71` | El texto de ayuda ("Shows a report with the infrastructure") está copiado de `-oi`. En realidad es el fichero donde se guarda el informe. |

---

## 10. Huecos y preguntas abiertas

1. **¿Funciona hoy en distribuciones reales?** Todo lo de la sección 8 sale de leer el
   código. Para confirmarlo habría que ejecutarlo, como root y como usuario normal, en
   máquinas o contenedores desechables con Debian 12/13, Ubuntu 24.04, RHEL/Alma/Rocky 9,
   Fedora reciente, openSUSE, Arch y Alpine, guardando el `aridi.log` con `-V 3`.
   **No se ha hecho: requiere tu permiso**, y lo recomendable es hacerlo en VMs o
   contenedores, nunca en una máquina con datos.
2. **¿Qué versión de Python hay en las máquinas destino?** Esto condiciona la nueva
   versión: en RHEL 8 el `python3` del sistema es la 3.6, en RHEL 9 la 3.9, y Debian 12
   trae la 3.11. Hace falta tu lista de sistemas objetivo.
3. **El origen y la licencia de `services.csv`.** No consta en el repositorio. Habría que
   compararlo con el registro de IANA o con `/etc/services`.
4. **Autoría.** Los 43 primeros commits son de "Daniel Pozo" y los 2 últimos del usuario
   de GitHub `dpgon`, que coincide con el remoto `git@github.com:dpgon/aridi.git`. La
   identidad de git configurada hoy en esta máquina es otra. No afecta al código, pero
   conviene confirmar quién tiene los derechos antes de cambiar la licencia o publicar.
5. **¿Debe conservarse la parte ofensiva** (barrido ARP y escaneo de puertos) en un
   producto de inventario y monitorización centralizado? Es una decisión de alcance, no
   técnica.
6. **El comportamiento exacto de `ip -o link` y `ip -o address`** con interfaces `@` y su
   efecto en `_getnetinfo`. Se determina con una sola ejecución en un contenedor.
7. **Rendimiento:** el recorrido de `/` (`gathering1.py:299`) no excluye otros puntos de
   montaje (NFS, montajes de red, `/proc` en el `walk`). Lo mismo pasa con el carving de
   `/var/log` y el bucle de `readlink` en `/proc/*/fd` (`gathering3.py:654-675`). Cuánto
   tarda en una máquina grande solo se sabe midiéndolo.

### Historia (resumen)

- **45 commits entre el 2019-03-21 y el 2019-04-12**, todos de la misma persona: 43 con
  la identidad local y 2 creados desde la web de GitHub (`LICENSE` y `README.md`). Una
  sola rama, `master`, sin etiquetas.
- **El ritmo fue intenso y corto:** soporte de pacman y zypper el 21 y 22 de marzo,
  ajustes para RH 6 el 23 de marzo, la fase volátil el 26 de marzo, red e iptables el 2 de
  abril, carving el 3 y 4 de abril, escaneo el 6 de abril, graphviz el 8 de abril y
  "First beta" el 9 y 10 de abril.
- **Último cambio de código:** `gathering1.py`, `gathering2.py` y `utils.py`, el
  2019-04-10. **Más modificados:** `gathering2.py` (20 commits) y `gathering1.py` (17).
- **Abandonado desde abril de 2019**, hace siete años y medio.
