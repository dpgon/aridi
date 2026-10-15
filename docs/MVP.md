# aridi: alcance entregado (estado a 2026-10-15)

> Este documento **mide** lo que aridi entrega hoy; no lo diseña. Se apoya en
> [`ESTUDIO.md`](ESTUDIO.md) (lectura del código) y en [`IDEA.md`](IDEA.md) (hacia dónde va).
> Lo que está previsto se describe en [`FUTURE.md`](FUTURE.md).

## Qué es hoy

aridi es hoy una **herramienta de consola que se ejecuta a mano, como root y con alguien
delante**, en una sola máquina Linux. Produce un informe de texto con el perfil de esa
máquina: distribución, kernel, paquetes, memoria y CPU, usuarios, permisos peligrosos,
IPs mencionadas en la configuración y los registros, y puertos abiertos. Ya le sirve a un
administrador o a un auditor que quiera una **fotografía rápida y legible de una máquina
Debian, Ubuntu o de la familia Red Hat**, siempre que lea el informe sabiendo dos cosas:
varios apartados pueden faltar sin aviso, y algunos datos son erróneos (ver
*Funcionalidades a medias*). No hay componente central ni ejecución remota, no guarda
histórico y no avisa de cambios.

## Cómo se ha medido

Ninguna funcionalidad tiene pruebas automáticas: el proyecto no tiene ninguna
(`ESTUDIO.md` §7). Para esta medición, aridi se ha ejecutado **sin modificarlo** (commit
`4ab279e`) en contenedores Docker desechables (Docker 29.8, arm64, kernel `linuxkit`) en
los que solo se instaló Python y algunas herramientas básicas de red:

| Etiqueta | Imagen base | Python |
|---|---|---|
| debian12 | `debian:12` | 3.11.2 |
| ubuntu2404 | `ubuntu:24.04` | 3.12.3 |
| rocky9 | `rockylinux:9` | 3.9.25 |
| fedora | `fedora:latest` (Fedora 44) | 3.14.8 |
| alpine320 | `alpine:3.20` | 3.12.13 |
| centos7 | `centos:7` (repositorios *vault*) | 3.6.8 |

**Ejecuciones:**

- **Las 6 distribuciones, como root:**
  `printf 'y\nn\nn\nn\nm\n' | python3 aridi.py -a --scan -V 3 -of report.txt`.
  Sin red (`--network none`); el escaneo, limitado a la propia máquina.
- **Debian 12 y CentOS 7, sin privilegios** (`--user 65534`), **y sin terminal**
  (`< /dev/null`).
- **Escenarios preparados en Debian 12 y Fedora:**
  - el usuario `alice`, con contraseña puesta por `chpasswd`;
  - un servidor TCP en `[::]:8080`;
  - un socket UDP en `0.0.0.0:5353`;
  - 12 procesos `sleep`;
  - un proceso con uid 4242, que no está en `/etc/passwd`;
  - en la red *bridge* de Docker, la interfaz `eth0@ifN`.
- **Pruebas puntuales:**
  - el escaneo contra un servidor en `127.0.0.1:8080`;
  - el arranque desde otro directorio;
  - `--graph` sin `graphviz`;
  - los permisos de los ficheros de salida.

**Límites de la medición:** son contenedores, no máquinas completas. No había systemd en
marcha, ni USB, ni discos físicos, ni red local, ni sesiones reales. Todo es arm64, así que
x86_64 está sin verificar. Lo que no se ha podido observar está en
*Implementadas, sin verificar*.

**Categorías y criterio** (decididos con el usuario):

- **Entregada:** funciona y da datos correctos en todas las distribuciones probadas.
- **Entregada con limitaciones:** funciona y da datos correctos, pero tiene huecos en
  casos poco comunes o fuera de la configuración por defecto.
- **A medias:** da **datos erróneos sin avisar**, o desaparece entera en la configuración
  por defecto de alguna distribución o entorno dentro del alcance de `IDEA.md`.
- **Implementada, sin verificar:** hay código invocado desde el arranque, pero no se ha
  podido observar. No cuenta como entregada.
- **Abandonada:** hay código, pero nunca se ejecuta.

---

## Funcionalidades que funcionan hoy

### 1. Ejecución local completa en distribuciones actuales y antiguas — *entregada con limitaciones*

Se lanza `python3 aridi.py` en una máquina; recorre las fases pedidas y termina sin
romperse aunque fallen apartados concretos.

- **Criterios de aceptación (observados):**
  - Con `-a --scan -V 3 -of report.txt` termina con `exit=0` en las 6 distribuciones,
    de Python 3.6.8 a 3.14.8.
  - Cada fallo de un apartado queda en `aridi.log` como `ERROR` y la ejecución continúa.
    Código: cada apartado va en su propio `try` (`gathering1.py:411-503`, etc.).
- **Limitaciones:**
  - Con Python 3.12 o superior (Ubuntu 24.04, Fedora 44, Alpine 3.20) imprime 30 avisos
    `SyntaxWarning: invalid escape sequence` por la salida de error.
  - El código de salida es 0 aunque se pierdan apartados.
  - Hay que ejecutarlo **desde su directorio**. Lanzado desde `/`, no encuentra
    `services.csv` y desactiva el escaneo (en el log: `aridi can't load port names. Scan
    flag was disabled`; ruta relativa en `aridi.py:101`).
- **Casos no cubiertos:** sin terminal (ver *A medias*, n.º 21) y versiones de Python
  anteriores a 3.6 (RHEL/CentOS 6, sin probar).

### 2. Identificación del sistema: distribución, kernel y libc — *entregada con limitaciones*

- **Criterios de aceptación (observados):**
  - La distribución sale con nombre y versión en 5 de 6:
    - "Debian GNU/Linux 12 (bookworm)";
    - "Ubuntu 24.04.5 LTS (Noble Numbat)";
    - "Rocky Linux 9.3 (Blue Onyx)";
    - "Fedora Linux 44 (Container Image)";
    - "CentOS Linux 7 (AltArch)".
  - El kernel sale completo (`Linux 7.0.14-linuxkit …`) y la libc también
    (`glibc 2.36` en Debian 12).
  - Código: `gathering1.py:146-229`.
- **Limitaciones:**
  - En Alpine sale "Alpine Linux" **sin versión**: solo se lee `VERSION=`, y Alpine solo
    publica `VERSION_ID=3.20.10`.
  - Las rutas alternativas `/etc/debian-version` y `/suse/etc/SuSE-release` están mal
    escritas (`gathering0.py:17,21`), así que no sirven como respaldo.
- **Casos no cubiertos:** distribuciones sin `/etc/os-release`, salvo las que tengan
  ficheros de release de CentOS, Red Hat o Fedora (sin probar).

### 3. Paquetes instalados en las familias Debian y Red Hat (con `yum` o dnf4) — *entregada con limitaciones*

- **Criterios de aceptación (observados):**

  | Distribución | Herramienta | aridi | Base de paquetes |
  |---|---|---|---|
  | Debian 12 | dpkg | 141 | 141 (`dpkg-query -W`) |
  | Ubuntu 24.04 | dpkg | 118 | — |
  | Rocky 9 | yum | 153 | 154 (`rpm -qa`) |
  | CentOS 7 | yum | 161 | 163 (`rpm -qa`) |

  La lista detallada de nombre y versión aparece con `-od`. Código:
  `gathering1.py:359-405,473-503`.
- **Limitaciones:**
  - Las diferencias en Rocky 9 y CentOS 7 son de 1 y 2 paquetes. **Suposición:** son las
    claves `gpg-pubkey`, que `rpm -qa` cuenta y `yum` no.
  - En Debian la versión que se muestra es la del paquete fuente (`${source:Version}`,
    `gathering1.py:396`).
- **Casos no cubiertos:** Fedora y Alpine (ver *A medias*, n.º 14); zypper y pacman, sin
  probar.

### 4. Memoria, CPU en uso, carga y uptime — *entregada*

- **Criterios de aceptación (observados):** en las 6 distribuciones aparecen la memoria
  total (`Total memory of 7934 MB`), los porcentajes de memoria usada, en búferes y libre,
  la swap, la carga a 1, 5 y 15 minutos, y el uso de CPU desde el arranque y en el último
  segundo. Código: `gathering3.py:468-615`.
- **Limitaciones:**
  - El uptime depende de que el apartado de procesos haya llegado a leer `/proc/uptime`
    (`gathering3.py:63-64`). Si ese apartado falla antes, sale 0 (**suposición** por
    lectura).
  - La medida "en el último segundo" añade un segundo de espera.
- **Casos no cubiertos:** ninguno conocido.

### 5. Búsqueda de permisos peligrosos → `aridi.badfiles` — *entregada con limitaciones*

Recorre el sistema de ficheros y lista los directorios escribibles por todos sin *sticky
bit*, los ficheros escribibles por todos y los binarios SUID y SGID.

- **Criterios de aceptación (observados):**
  - Tras responder `y` a la pregunta, genera `aridi.badfiles` en las 6 distribuciones,
    con entre 2 (Alpine) y 67 (Ubuntu) entradas.
  - En Debian 12 lista 9 SUID, frente a 8 de `find / -xdev -perm -4000`. **Suposición:**
    la diferencia viene de recorrer también otros sistemas de ficheros montados.
  - Código: `gathering1.py:287-343,545-616`.
- **Limitaciones:**
  - Solo se ejecuta si alguien responde `y` por consola.
  - Atraviesa todos los puntos de montaje, incluidos los de red.
  - Si no puede crear `aridi.badfiles`, el `finally` lanza otro error
    (`gathering1.py:611`).
  - El fichero queda `-rw-r--r--` en el directorio actual.
- **Casos no cubiertos:** sistemas de ficheros grandes. No se ha medido el tiempo.

### 6. Identidad y banners — *entregada con limitaciones*

- **Criterios de aceptación (observados):** muestra el hostname (`c04fb26201b0`) y el
  contenido de `issue`, `issue.net` y `motd` cuando existen. Código:
  `gathering2.py:9-64`.
- **Limitaciones:** en el detalle, el dominio muestra el hostname en su lugar
  (`gathering2.py:35`, por lectura).
- **Casos no cubiertos:** sin probar en máquinas con dominio DNS configurado.

### 7. IPs mencionadas en `/etc` y `/var/log` (carving) — *entregada con limitaciones*

- **Criterios de aceptación (observados):** con terminal, en las 6 distribuciones aparece
  "2 ips found in /etc", y cada IP queda en el mapa de relaciones con el fichero y la línea
  donde aparece. Código: `gathering4.py:10-74,129-195`.
- **Limitaciones:**
  - Solo IPv4.
  - No lee journald.
  - Lee cada fichero entero en memoria.
  - La resolución de FQDN exige responder por consola.
  - Sin terminal, la parte de `/etc` se pierde junto con la pregunta (ver n.º 21).
- **Casos no cubiertos:** máquinas con muchos registros (sin medir) e IPv6.

### 8. Escaneo de puertos TCP de las IPs elegidas — *entregada con limitaciones*

- **Criterios de aceptación (observados):** con un servidor en `127.0.0.1:8080` y la
  categoría `m` (máquina local), el informe dice `Total IPs to scan: 1` y
  `1 open ports found` en 1 segundo. Código: `scan.py:108-214`.
- **Limitaciones:**
  - La categoría ofrecida `(f) IPTables allowed` no hace nada (`scan.py:171,181-195`).
  - Con `a` o `x` escanea también IPs de terceros sacadas de los registros
    (`ESTUDIO.md` §8).
  - Prueba los 5.877 puertos de `services.csv`, con un hilo por puerto.
  - Solo IPv4.
- **Casos no cubiertos:** escaneo de IPs remotas (no probado a propósito: la prueba se
  hizo sin red).

### 9. Informes: resumido, detallado, completo y de infraestructura; salida a fichero y log — *entregada con limitaciones*

- **Criterios de aceptación (observados):**
  - `-os`, `-od`, `-of` y `-oi` producen sus vistas, y `FILE` las guarda en un fichero.
  - `-V 3` deja en `aridi.log` las trazas completas de cada error (`INFO` y `DEBUG`).
  - La vista `-oi` separa "Local Machine" y "Remote IP Address" con los papeles de cada IP
    (por ejemplo, `192.168.65.7 → DNS Server`).
  - Código: `reporting.py:99-273`, `aridi.py:194-240`.
- **Limitaciones:**
  - Solo texto, sin formato estructurado.
  - El informe, `aridi.log` y `aridi.badfiles` quedan `-rw-r--r--`, con nombre fijo, en el
    directorio actual.
  - El mapa puede recibir una clave `None` que rompe `-oi` (`ESTUDIO.md` §8; observado
    solo con Python, no en una ejecución de aridi).
- **Casos no cubiertos:** ninguno más conocido.

### 10. Ejecución sin privilegios, en una terminal — *entregada con limitaciones*

- **Criterios de aceptación (observados):** como `nobody`, en Debian 12 y CentOS 7 avisa
  de que no es root, pregunta si continuar y, con `y`, termina con `exit=0`. Omite
  `iptables` y el barrido ARP. Código: `aridi.py:110-120`, `gathering2.py:290`,
  `scan.py:219`.
- **Limitaciones:** sin terminal aborta (n.º 21).
- **Casos no cubiertos:** ninguno más conocido.

---

## Funcionalidades a medias

Cada entrada dice qué hay, qué falla (observado u obtenido por lectura) y dónde está el
código.

| N.º | Funcionalidad | Qué hay | Qué falta o falla | Código |
|---|---|---|---|---|
| 11 | **Hardware: CPU** | Arquitectura, sockets, fabricante, modelo, núcleos, flags, *bugs* | **Observado en arm64:** `CPU: 1 x` sin fabricante ni modelo y "0 cores", porque el formato de `/proc/cpuinfo` en ARM es otro. x86_64 sin verificar. | `gathering1.py:49-143` |
| 12 | **Usuarios, grupos y hashes** | Usuarios, grupos, pertenencias y tipo de hash | **Observado:** `alice` con hash `$y$` (yescrypt) sale sin contraseña ("0 with password") en Debian 12 y Fedora 44. **Observado:** en Alpine, un miembro de grupo sin usuario (`kvm`) anula el apartado entero. **Por lectura:** el contador de MD5 siempre vale 0 y se pierden nombres en el resumen. | `gathering2.py:67-160` |
| 13 | **Discos y particiones** (y carga de disco) | `lsblk`, `findmnt` y `df` | **Observado:** `IndexError` con el `lsblk` actual, que pone los puntos de montaje múltiples en líneas de continuación, en Debian 12, Ubuntu 24.04, Rocky 9 y Fedora 44; funciona en CentOS 7. Se pierden "disk information" y "Disk live information". **Por lectura:** el % de carga sale cien veces menor y el % de ocupación compara unidades distintas. | `gathering1.py:232-284`, `gathering3.py:367-465` |
| 14 | **Paquetes en Fedora y Alpine** | La detección de `yum`/`apk`… | **Observado:** en Fedora 44, `yum list installed --noplugins` termina con error y se pierde la lista. **Observado:** en Alpine, `'Precheck' object has no attribute 'packages'`; no hay soporte para apk. zypper y pacman, sin probar. | `gathering1.py:346-391,473-503` |
| 15 | **Red: interfaces, rutas, DNS** | `ip -o link/address`, `/proc/net/route`, `resolv.conf` | **Observado:** con `eth0@if381` (red *bridge* de Docker) se pierde **toda** la red con `KeyError: 'eth0'` en Debian 12 y Fedora 44. Afecta a VLAN, veth y contenedores. Solo IPv4. | `gathering2.py:163-257` |
| 16 | **Conexiones con su proceso** | `/proc/net/tcp` y `udp` + `/proc/*/fd` | **Observado:** un servidor en `[::]:8080` no aparece (sin `tcp6`). Un UDP en escucha sale como `CLOSE`. Un proceso con uid 4242 sin usuario anula el apartado (`KeyError: 4242`). También se pierde con una interfaz `@` (n.º 15). | `gathering3.py:618-779` |
| 17 | **Procesos** | Estado, top CPU y RAM, zombis | **Observado:** se pierde en las 6 distribuciones (`IndexError`, `gathering3.py:137`), porque exige 10 procesos con CPU mayor que 0. Pasa en contenedores incluso con 12 procesos; en máquinas completas, **suposición:** no pasa. | `gathering3.py:25-189` |
| 18 | **Cortafuegos** | `iptables -S` (INPUT/OUTPUT) | **Observado:** falla sin permiso de red en los contenedores. **Por lectura:** no ve nftables a secas, `ip6tables`, firewalld ni ufw, y las reglas FORWARD nunca se añaden. | `gathering2.py:288-399` |
| 19 | **Servicios** | systemd (`systemctl list-units`) o SysV (`chkconfig`) | **Observado:** si `systemctl` existe pero systemd no está en marcha (CentOS 7 en contenedor), el apartado se pierde en lugar de recurrir a otra vía. Con systemd en marcha está *sin verificar*. | `gathering2.py:402-508` |
| 20 | **USB** | `lsusb` | **Observado:** sin `lsusb` (5 de 6 imágenes; habitual en servidores mínimos) se pierde el apartado. No lee `/sys` directamente. | `gathering1.py:9-46` |
| 21 | **Ejecución sin terminal** | — | **Observado:** como root termina con `exit=0`, pero pierde por `EOF` los permisos, el carving de `/etc` y `/var/log` y el escaneo. Sin root aborta con `exit=1` ("Failed in the precheck stage"). | 7 llamadas a `input()`: `aridi.py:118`, `gathering1.py:550`, `gathering4.py:105,229`, `scan.py:179,235`, `graph.py:15` |

## Implementadas, sin verificar

Hay código invocado desde el arranque, pero no se ha podido observar en esta medición.
**No cuentan como entregadas.**

| Funcionalidad | Por qué no se ha observado | Riesgos vistos por lectura | Código |
|---|---|---|---|
| Barrido ARP de la red local | Necesita una red local real y aislada | Esperas activas, sockets sin cerrar, un hilo que puede no terminar y un umbral incoherente (/22) | `scan.py:17-105,217-267` |
| Servicios con systemd en marcha o con SysV | Sin systemd en los contenedores | Análisis por columnas de `systemctl list-units` | `gathering2.py:402-508` |
| Sesiones activas, últimos accesos y accesos fallidos | Sin sesiones reales | Un PID que ya no existe anula el apartado; depende de `utmpdump` | `gathering3.py:192-364` |
| `iptables` con reglas, como root y con permisos | Contenedor sin capacidad de red | Ver n.º 18 | `gathering2.py:288-399` |
| USB con `lsusb` presente | Sin USB | — | `gathering1.py:9-46` |
| Grafo de red con `graphviz` instalado | No se instaló la dependencia de terceros | Depende también del binario `neato` | `graph.py` |
| Paquetes con zypper o pacman | No se probó openSUSE ni Arch | Análisis por columnas | `gathering1.py:346-378` |
| Datos de CPU en x86_64 | Todo se probó en arm64 | — | `gathering1.py:49-143` |
| RHEL/CentOS 6 | No se probó (Python 2.6 de serie) | — | — |

## Abandonadas

| Funcionalidad | Prueba | Código |
|---|---|---|
| Lectura de NTP | `/etc/ntp.conf` no está en la lista de ficheros que se comprueban, así que `shouldread` siempre es falso; nunca se ejecuta | `gathering2.py:260`, `gathering0.py:12-71` |
| Comprobación de permisos de `passwd`, `group`, `shadow` y `gshadow` | `dangerousperm()` no se llama desde ningún sitio (grep) | `gathering0.py:193-208` |
| Registro de vulnerabilidades | `Reporting.vulns()` no se llama y usa un atributo que no existe | `reporting.py:96-97` |
| Categorías de ficheros interesantes (0 a 18) | Se guardan pero no se usan | `gathering0.py:12-71` |
| Uso como paquete importable | `__init__.py` solo tiene metadatos; los imports son de primer nivel | `__init__.py` |

---

## Fuera de lo entregado

Para que la frontera no admita dudas, aridi **no** hace hoy nada de lo siguiente:

- **Ejecución remota.** No llega a otras máquinas por SSH ni de ninguna otra forma.
- **Componente central, inventario, histórico o búsqueda en el parque.** No guarda nada
  entre ejecuciones.
- **Comparación entre ejecuciones y alertas.**
- **Programación de recogidas.**
- **Interfaz web, usuarios o roles.**
- **Resultado estructurado e importable.** Solo hay texto con formato de árbol.
- **Declaración de lo que no se ha podido ver.** Lo que falla se omite del informe y solo
  queda en `aridi.log`.
- **Funcionamiento desatendido.** Hace 7 preguntas por consola.
- **IPv6** en ningún apartado. **journald, nftables, OpenRC, apk y dnf5** no se
  contemplan.
- **Exploración acotada a redes autorizadas.** El escaneo actual no tiene perímetro.

**Lo que el proyecto promete y el código no cumple.** El README solo afirma "Linux
information gathering and infrastructure scanner" (`README.md:2`), y eso sí lo cumple. Las
diferencias con lo que el usuario entendía del proyecto están en `ESTUDIO.md` §9. Las
principales:
- no es Python puro, porque depende de una docena de binarios del sistema;
- no monitoriza, sino que hace una fotografía puntual;
- su adaptación a las distribuciones se quedó en las de 2019.

## Definición de terminado que se dio el proyecto

**El proyecto no mantenía ninguna definición de terminado explícita.** Lo que se observa:

- **Pruebas:** ninguna, ni automáticas ni documentadas. Los commits "Little modification
  for RH 6" (2019-03-23) sugieren pruebas manuales en máquinas concretas
  (**suposición**).
- **Calidad:** el criterio implícito era que el programa no se rompa. Cada apartado se
  aísla en un `try` y el error va al log. No hay revisión de estilo, análisis estático ni
  control de avisos: hay 30 secuencias de escape inválidas.
- **Documentación:** un README de una línea, la ayuda de `argparse` y comentarios
  escasos. No hay instrucciones de uso.
- **Versionado:** `__version__ = "1.0"` y `__status__ = "Development"`
  (`__init__.py:3-5`). No hay etiquetas de git; los últimos commits se titulan "First
  beta".
