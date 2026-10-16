# aridi: lo que está previsto

> Parte de lo que mide [`MVP.md`](MVP.md) y va hacia lo que describe [`IDEA.md`](IDEA.md).
> Aquí no se toman decisiones tecnológicas: describe capacidades, no soluciones. Las
> decisiones están en [`CAMBIO.md`](CAMBIO.md) y el trabajo, en [`TODO.md`](../TODO.md).
>
> **Revisado en la fase 4 de `TODO.md`** (2026-10-16), al retirar el código de 2019.
> Donde una entrada dice «en 2019», se refiere a la medición de ese código (`MVP.md` de
> 2026-10-15, commit `4ab279e`); sus ficheros (`gathering*.py`, `scan.py`,
> `reporting.py`…) solo siguen en la historia de git.

## Origen de cada entrada

Cada funcionalidad lleva su procedencia, y los tres orígenes no se mezclan:

- **[declarado]:** lo que el propio proyecto anuncia (roadmap, TODO, issue, comentario
  del autor). **El proyecto de 2019 no declaraba ningún futuro en ninguna parte.** No
  había roadmap, `TODO`/`FIXME`/`XXX` (verificado con grep), issues en el repositorio ni
  comentarios del autor sobre planes. Por eso ninguna entrada de este documento tiene
  este origen.
- **[deducido]:** lo que dejaba ver el código de 2019: un módulo a medias, una función
  preparada que no se usaba, un fallo observado. Se cita el archivo o la observación de
  `MVP.md`.
- **[usuario]:** lo que el usuario ha decidido el 2026-10-15 (`IDEA.md` y la
  conversación del alcance).

**El orden de las etapas** lo ha decidido el usuario: se construye por capas, y cada
etapa se apoya en la anterior. El motivo es que el éxito depende de confiar en los datos,
y nada de lo central vale si el colector se equivoca.

**Numeración.** Las etapas siguen la ruta de `CAMBIO.md` (*Ruta por etapas*), que añade
la etapa 0. Cada etapa se entrega en unas fases concretas de `TODO.md`:

| Etapa | Fases de `TODO.md` | Estado |
|---|---|---|
| 0. Base y corpus | 0 y 1 | **Hecha** |
| 1. Un colector fiable | 2, 3 y 4 | **Hecha** salvo lo que se indica en cada entrada |
| 2. Inventario central | 5 | Prevista: **no existe nada** |
| 3. Cambios y alertas | 6 | Prevista: **no existe nada** |
| 4. Exploración de red acotada | 3.17 (parte pasiva, adelantada) y 7 | Parte pasiva hecha; el escaneo activo, previsto |

Una entrada se da por **hecha** solo si las pruebas que se citan pasan en
`tests/run.sh all`. La correspondencia completa con las funcionalidades de 2019 está en
[`tests/parity.md`](../tests/parity.md).

---

## Etapa 0: base y corpus — **hecha**

**Tema:** poder medir antes de cambiar nada. Es [usuario], a partir de [deducido]: en
2019 no había ninguna prueba (`MVP.md`, *Definición de terminado*).

- **Entregado** (fases 0 y 1 de `TODO.md`):
  - un único punto de entrada de pruebas, todo en Docker: `tests/run.sh`;
  - un **corpus de muestras reales** (`tests/corpus/`): 10 imágenes de contenedor
    (Debian 12 y 13, Ubuntu 24.04, Rocky 9, Fedora 44, Alpine 3.20, openSUSE Leap 15.6,
    Arch, CentOS 7 y CentOS 6), cada una en tres variantes (mínima, con herramientas de
    servidor, y en red *bridge*), más 3 VMs con systemd y sesiones reales (Debian 12
    arm64 y amd64, Rocky 9 arm64);
  - un escenario común (`tests/corpus/scenario.sh`) que reproduce los casos que rompían
    el aridi de 2019, y unos hechos de referencia (`facts.txt`) con los que se contrasta
    cada dato.

---

## Etapa 1: un colector fiable — fases 2 a 4

**Tema:** que una sola recogida, en cualquier máquina del alcance, diga la verdad, la diga
entera y diga lo que no sabe.

### 1.1 Datos correctos en lo que estaba a medias — [deducido]

Corregir las funcionalidades n.º 11 a 20 de `MVP.md`.

- **Criterios de aceptación:** en las distribuciones del alcance (1.6), cada apartado da
  datos que coinciden con lo que obtiene una herramienta de referencia en la misma
  máquina. Como mínimo:
  - **Hashes:** reconoce yescrypt (`$y$`), `$2b$` y las cuentas bloqueadas (`!` y `*`),
    y las distingue de "sin contraseña". En 2019: n.º 12.
  - **Usuarios:** un miembro de grupo o un uid sin entrada en `passwd` no anula ningún
    apartado. En 2019: n.º 12 y 16.
  - **Discos:** se ven con el `lsblk` actual, incluidos los montajes múltiples, y los
    porcentajes de carga y ocupación son correctos. En 2019: n.º 13.
  - **Red:** se ve con interfaces `@` (VLAN, veth, contenedores). En 2019: n.º 15.
  - **Conexiones:** se ve IPv6 y el UDP en escucha se clasifica como tal. En 2019:
    n.º 16.
  - **Procesos:** se ven con pocos procesos. En 2019: n.º 17.
  - **CPU:** se ve correctamente en ARM y en x86_64. En 2019: n.º 11.
  - **Distribución:** la versión aparece aunque solo exista `VERSION_ID` (Alpine). En
    2019: n.º 2.
- **Fuera:** ampliar lo que se recoge; eso es 1.7.
- **Estado: hecho** [observado]. Cada punto tiene sus pruebas contra los hechos de
  referencia del corpus y contra el aridi de 2019 en la misma máquina: filas 11 a 20 de
  `tests/parity.md` y `tests/test_parity.py`.

### 1.2 Funcionamiento sin preguntas — [usuario] — **hecha**

En 2019 se hacían 7 preguntas por consola (`MVP.md` n.º 21).

- **Criterios de aceptación:**
  - Una recogida sin terminal, como root o sin root, completa todos los apartados
    habilitados.
  - Lo que se preguntaba (búsqueda de permisos, resolución de FQDN, escaneo) se decide
    de antemano, con valores por defecto prudentes: lo costoso o lo que genera tráfico,
    desactivado.
  - El código de salida distingue entre "completa", "completa con huecos" y "fallida".
- **Por qué está hecha** [observado]:
  - El script no pregunta nada: cada comando lee de `/dev/null`, y se prueba lanzado por
    `sh -s` (sin terminal) como root y como uid 65534 en las 10 imágenes del corpus, con
    cada shell disponible (`tests/run.sh collector`).
  - Lo que se preguntaba queda decidido: la búsqueda de permisos se hace siempre, pero
    solo en el sistema de ficheros raíz (`-xdev`) y con un límite de 60 s por comando;
    la resolución de FQDN se abandona (*Ideas aparcadas*); el escaneo sale de la máquina
    (4.1).
  - `aridi report` sale con 0 (completa), 1 (con huecos) o 2 (paquete inválido o
    fallido) (`src/aridi/cli.py`; `test_cli:CliTest.test_complete_exit_code`). El
    script sale siempre con 0: el resultado lo dice el paquete, no su código.

### 1.3 Declarar lo que no se ha podido ver — [usuario] — **hecha**

- **Criterios de aceptación:**
  - Cada recogida incluye, por apartado, si se obtuvo o no.
  - Cuando no, incluye el motivo: sin permisos, herramienta ausente, no aplica en este
    sistema o error.
  - Un apartado que falla nunca desaparece en silencio, como pasaba en 2019.
- **Por qué está hecha** [observado]: cada sección del paquete y cada una de las 17
  áreas de la fotografía llevan su estado (`ok`, `denied`, `missing`, `na`, `timeout`,
  `error`) y su motivo, y las áreas pueden declarar además huecos parciales
  (`docs/FORMATO.md`). La fotografía siempre trae las 17 áreas, y el informe termina con
  «What could not be seen» (`test_interpret:InterpretTest.test_every_area_present_without_parsers`,
  `test_text:TextTest.test_every_area_and_the_gaps_section`). En las 33 muestras del
  corpus ninguna área queda en `error`
  (`test_relations:GlobalRegressionTest.test_no_area_in_error_in_any_sample`).

### 1.4 Resultado estructurado y exportable — [usuario] — **hecha**

Además del informe legible, cada recogida produce un resultado que otra herramienta puede
leer sin interpretar texto, y que el componente central podrá importar (etapa 2).

- **Criterios de aceptación:**
  - Todo lo que aparece en el informe legible está en el resultado estructurado.
  - El resultado identifica la máquina, el momento de la recogida y la versión de aridi.
- **Por qué está hecha** [observado]: hay dos resultados versionados
  (`docs/FORMATO.md`): el **paquete en bruto** v1 que sale de la máquina, y la
  **fotografía** JSON v1 que produce `aridi interpret`, con `machine` (`machine_id` y
  `hostname`), `collected_at`, `collector_version` y `bundle_format`
  (`test_model:ModelTest.test_json_round_trip`, `test_cli:CliTest.test_interpret_to_stdout`).
  El informe legible se genera desde la fotografía (`src/aridi/views/text.py`), así que
  no puede mostrar nada que no esté en ella [deducido del diseño]. Cuál de los dos
  importará el central se decide en la fase 5 (*Ideas aparcadas*).

### 1.5 Ningún rastro y ninguna exigencia en la máquina — [usuario] — **hecha**

- **Criterios de aceptación:**
  - No necesita instalar nada.
  - Tras una recogida no queda ningún fichero en la máquina, salvo los que el usuario
    pida expresamente en modo local.
  - Funciona sea cual sea el directorio desde el que se lanza. En 2019 dependía de él:
    `MVP.md` n.º 1.
  - Si falta una herramienta del sistema, usa otra vía o lo declara (1.3). Por ejemplo,
    USB sin `lsusb` (`MVP.md` n.º 20) o servicios con `systemctl` pero sin systemd
    (n.º 19).
- **Por qué está hecha** [observado]:
  - El script llega por la entrada estándar (`sh -s`) y solo necesita un `sh` POSIX.
  - No escribe nada: todo sale por la salida estándar. `tests/run.sh collector`
    comprueba en cada imagen, con `find / -xdev -newer`, que no crea ni modifica ningún
    fichero. Esa prueba descubrió que `rpm -qa` como root escribe en `/var/lib/rpm`, y
    por eso el script lo ejecuta como uid 65534 (`docs/FORMATO.md`).
  - No depende del directorio: no lee nada relativo a él, y `services.csv` va dentro del
    paquete Python (`src/aridi/data/`).
  - Sin una herramienta, usa otra vía o lo declara: USB desde `/sys/bus/usb`
    (`test_hardware:SyntheticTest.test_without_sys_bus_usb_is_na_not_error`), servicios
    sin systemd en marcha (`test_services:CorpusTest.test_centos7_container_systemctl_without_systemd`),
    red sin `ip` (`test_network:SyntheticTest.test_addresses_without_ip_tool`).

### 1.6 Cobertura de plataformas — [usuario]

- **Criterios de aceptación:** las recogidas cumplen 1.1 a 1.5 en:
  - Debian y Ubuntu con soporte vigente;
  - RHEL y derivadas (Alma, Rocky);
  - Fedora (en 2019 fallaban los paquetes: `MVP.md` n.º 14);
  - SUSE/openSUSE;
  - Arch;
  - Alpine (en 2019 no había paquetes: n.º 14);
  - RHEL/CentOS 6 y 7;
  - contenedores en ejecución;
  - máquinas físicas y virtuales, en x86_64 y en ARM.
- **Cómo se cubren RHEL 6 y los contenedores sin Python** [decidido en `CAMBIO.md`;
  observado]: la recogida es un script `sh`, así que en la máquina no hace falta ningún
  intérprete de Python; solo hace falta Python 3.12 donde se interpreta el paquete. CentOS
  6 (bash 4.1, sin Python 3) y las variantes mínimas de todas las imágenes (sin Python)
  están en el corpus y en `tests/run.sh collector`.
- **Estado** [observado]: probado en contenedores de Debian 12 y 13, Ubuntu 24.04,
  Rocky 9, Fedora 44, openSUSE Leap 15.6, Arch, Alpine 3.20, CentOS 7 y CentOS 6, y en
  VMs de Debian 12 (x86_64 y arm64) y Rocky 9 (arm64). **Sin verificar:** máquinas
  físicas, Alma, Ubuntu en VM, y CentOS 6 y 7 en VM (solo en contenedor). Arch y CentOS 6
  se probaron con emulación amd64 sobre arm64.

### 1.7 Cobertura de los subsistemas modernos — [deducido] de `MVP.md` *Fuera de lo entregado*

- **Criterios de aceptación:** se recogen, cuando existen:
  - IPv6 en interfaces, rutas y conexiones;
  - cortafuegos nftables, firewalld y ufw;
  - el registro del sistema de journald (accesos y fallos);
  - inits distintos de systemd y SysV (OpenRC, runit);
  - sesiones en sistemas que han sustituido `wtmp`.
- **Estado** [observado]: IPv6, nftables, firewalld, journald y OpenRC, **hechos** con
  muestras reales (`tests/parity.md` n.º 15, 16, 18 y 19). **Solo con datos sintéticos**,
  porque ninguna imagen del corpus los trae: ufw
  (`test_firewall_timesync:FirewallSyntheticTest.test_ufw`) y runit
  (`test_services:SyntheticTest.test_openrc_and_runit`). **`wtmpdb`, sin verificar:** el
  script lo consulta (`wtmpdb last -F`) y el analizador lo lee con el mismo código que la
  salida de `last -F`, que solo se prueba con datos sintéticos
  (`test_volatile:SessionsTest.test_last_and_who_fallback`); no hay ninguna muestra de
  `wtmpdb` (Debian 13 y openSUSE 15.6 en contenedor dan `missing`).

### 1.8 Recuperar lo abandonado — [deducido] — **hecha**

- **NTP o sincronización de hora:** en 2019 el código existía pero era inalcanzable
  (`gathering2.py:260`). Se recupera, incluidos los servicios de hora actuales.
- **Comprobación de permisos de `passwd`, `group`, `shadow` y `gshadow`:** estaba
  escrita y no se llamaba (`gathering0.py:193-208`). Pasa a formar parte de los permisos
  peligrosos.
- **Criterio de aceptación:** ambos aparecen en el resultado de toda recogida en la que
  sean aplicables.
- **Por qué está hecha** [observado]: área `timesync` (chrony, systemd-timesyncd y ntpd)
  y `permissions.account_files` (`tests/parity.md`, *Abandonadas en 2019*).

### 1.9 Seguridad del propio colector — [deducido] de `ESTUDIO.md` §8 y `MVP.md`

- **Criterios de aceptación:**
  - Ningún fichero de salida se crea con un nombre predecible en un directorio compartido.
  - Ninguno queda legible por otros usuarios (en 2019 `-rw-r--r--`: `MVP.md` n.º 9).
  - Los datos que vienen de la máquina (banners, líneas de registro) se tratan como
    texto no fiable allá donde se muestren.
  - Ninguna recogida puede generar tráfico de red hacia fuera de la máquina si no se ha
    autorizado (ver etapa 4).
- **Estado** [observado]: **hecha en el modo local.** El script no escribe ficheros; la
  CLI solo escribe el fichero que se le pide, nuevo, con modo 0600, sin sobrescribir ni
  seguir enlaces (`test_cli:CliTest.test_interpret_to_new_file_0600`,
  `test_cli:CliTest.test_interpret_never_overwrites_nor_follows_symlinks`). El texto de
  la máquina se neutraliza en la vista (`test_text:TextTest.test_untrusted_text_is_escaped`)
  y el texto de las líneas donde el *carving* encuentra IPs ni siquiera sale de ella (las
  líneas de `sshd` de los registros sí salen, para el área de sesiones). El colector no envía
  nada a la red: los vecinos se leen de la tabla del sistema. Además, lo sensible se
  filtra en origen (`docs/FORMATO.md`). Cuando exista el central, sus propios ficheros
  y vistas tendrán que cumplir lo mismo (etapa 2).

### 1.10 Grafo fuera del colector — [usuario] — **hecha**

El grafo, que en 2019 dependía de `graphviz` (`graph.py:6`), sale del colector, y el
colector queda **sin dependencias ajenas**. El mapa de relaciones sigue en el resultado;
su dibujo pasa a la etapa 2 o 3 (2.7).

- **Por qué está hecha** [observado]: el colector no dibuja nada y no tiene ninguna
  dependencia: el script solo usa `sh` y las herramientas del sistema, y el núcleo solo
  la librería estándar (`test_core_isolation:CoreIsolationTest.test_only_stdlib_imports`).
  El mapa de relaciones va en la fotografía, con IPv4 e IPv6
  (`test_relations:RelationsTest.test_corpus_map_has_v4_and_v6`), y en la vista de
  infraestructura del informe.

### 1.11 Verificación repetible — [deducido] de `MVP.md` *Definición de terminado*

En 2019 no había pruebas, y la medición se hizo a mano.

- **Criterio de aceptación:** existe una forma repetible de comprobar 1.1 a 1.9 en las
  plataformas de 1.6, incluidas las funcionalidades que en 2019 estaban *implementadas,
  sin verificar* (barrido ARP, systemd, sesiones, `iptables` con reglas, zypper y
  pacman, x86_64).
- **Estado** [observado]: **hecha** con `tests/run.sh all` sobre el corpus, y con la
  comparación contra el aridi de 2019 en la misma máquina (`tests/test_parity.py`). Para
  cada funcionalidad *sin verificar* de 2019, `tests/parity.md` dice qué la cubre. El
  barrido ARP se abandona en la máquina (4.1); `iptables` con reglas solo se prueba con
  datos sintéticos, porque las VMs usan nftables.

---

## Etapa 2: inventario central — fase 5

**Tema:** que el equipo tenga todas sus máquinas en un solo sitio, al día y consultables.
Todo es [usuario] (`IDEA.md`). **Nada de esta etapa existe todavía.**

### 2.1 Ejecución remota por SSH — [usuario]

- **Criterios de aceptación:**
  - Desde el componente central, una recogida llega a una máquina por SSH, se ejecuta y
    devuelve el resultado por el mismo canal.
  - En la máquina no queda nada (1.5).
  - Si la máquina no responde, se registra como recogida fallida y con su motivo.

### 2.2 Programación y recogida a demanda — [usuario]

- **Criterios de aceptación:**
  - Se pueden programar recogidas por máquina o por grupo con una periodicidad.
  - Se pueden lanzar a demanda sobre una máquina, varias o un grupo.

### 2.3 Importación de recogidas locales — [usuario]

- **Criterio de aceptación:** el resultado de una recogida hecha en modo local (1.4) se
  importa y queda como una fotografía más de su máquina.

### 2.4 Inventario e histórico — [usuario]

- **Criterios de aceptación:**
  - Se ve la ficha actual de cada máquina y todas sus fotografías anteriores.
  - Se ve lo que no se pudo recoger en cada una y desde cuándo.
  - Las máquinas se organizan en grupos.

### 2.5 Búsqueda en el parque — [usuario]

- **Criterio de aceptación:** se responde a preguntas como "¿qué máquinas tienen este
  paquete o esta versión?", "¿dónde escucha este puerto?" o "¿dónde existe este usuario?",
  con la fecha de la fotografía de cada máquina.

### 2.6 Interfaz web con dos roles — [usuario]

- **Criterios de aceptación:**
  - **Administración:** gestiona máquinas, grupos, accesos, programación, reglas y redes
    autorizadas.
  - **Consulta:** solo ve.
  - Hay una instalación por equipo; no hay separación de clientes dentro de una
    instalación.

### 2.7 Mapa de relaciones en la web — [usuario], a partir de [deducido]

El mapa de infraestructura que el colector ya construye (en 2019, `reporting.py:99`; hoy,
las relaciones de la fotografía y `src/aridi/relations.py`) se muestra en la interfaz
web, en sustitución del grafo de 2019 (1.10). En `TODO.md` está en la fase 6 (6.5).

- **Criterio de aceptación:** para una máquina, se ven las IPs con las que se relaciona y
  el papel de cada una.

---

## Etapa 3: cambios y alertas — fase 6

**Tema:** enterarse de lo que importa sin tener que mirar. Todo es [usuario]. **Nada de
esta etapa existe todavía.**

### 3.1 Comparación entre fotografías — [usuario]

- **Criterios de aceptación:**
  - Para cualquier máquina se pueden comparar dos fotografías y ver qué ha aparecido, qué
    ha desaparecido y qué ha cambiado en cada área.
  - Un dato que pasa de "recogido" a "no recogido" se muestra como tal, no como si
    hubiera desaparecido.

### 3.2 Criterio de cambio significativo de serie, ajustable — [usuario]

- **Criterios de aceptación:**
  - Hay un conjunto de reglas de serie con niveles de gravedad. Ejemplos de `IDEA.md`:
    usuario nuevo con acceso o privilegios, puerto nuevo a la escucha, servicio que pasa
    a fallar, nuevo binario con privilegios elevados, cambio de kernel, disco casi lleno.
  - El administrador puede ajustar o silenciar reglas por máquina o por grupo.
  - La lista exacta de reglas está pendiente.

### 3.3 Avisos externos — [usuario]

- **Criterios de aceptación:**
  - Las alertas se ven en la web y se envían por canales externos (correo, chat,
    webhook).
  - Los canales concretos están pendientes.

### 3.4 Alerta por máquinas que dejan de responder — interpretación de `IDEA.md`, pendiente de confirmar

- **Criterio de aceptación:** una máquina que deja de responder, o que deja de enviar
  datos que antes enviaba, genera una alerta.

---

## Etapa 4: exploración de red acotada — 3.17 y fase 7

**Tema:** conservar la capacidad de descubrir la red sin que sea ofensiva.

### 4.1 Descubrimiento pasivo en la máquina y escaneo desde el central — [usuario], sobre [deducido]

En 2019, la propia máquina barría la red local con ARP (*implementado, sin verificar*) y
escaneaba puertos TCP (*entregado con limitaciones*), incluso de IPs de terceros sacadas
de los registros (`scan.py`; `MVP.md` n.º 8). `CAMBIO.md` lo divide en dos partes:

- **Descubrimiento pasivo, en la máquina** — **hecho** (fase 3.17) [observado]:
  - el colector no envía nada a la red: lee la tabla de vecinos que ya tiene el sistema
    (`ip neigh`, o `/proc/net/arp` sin `ip`), IPv4 e IPv6, y la añade al mapa de
    relaciones (`test_carving:NeighboursTest.test_vms_see_their_gateway`,
    `test_carving:NeighboursTest.test_container_without_ip_uses_proc_arp`);
  - **se pierde** el descubrimiento de equipos de la red local que nunca hayan hablado
    con la máquina, y el escaneo visto desde la propia máquina (`CAMBIO.md`, *Qué se
    pierde*).
- **Escaneo activo, desde el componente central** — previsto (fase 7); **no existe**:
  - **Criterios de aceptación:**
    - Está desactivado por defecto.
    - Solo actúa sobre redes que el administrador ha autorizado de forma explícita.
    - Nunca toca una IP fuera de ese perímetro, aunque aparezca en el inventario o en
      los registros, como sí hacía el escaneo de 2019.
    - Ve la red desde la posición del central; un cortafuegos puede hacer que vea algo
      distinto de lo que se ve desde la máquina, y el resultado lo indica como tal.
    - El resultado se integra en el inventario y en el mapa de relaciones (el papel
      `scan_open_port` ya está reservado en la fotografía, `docs/FORMATO.md`).
  - La categoría `(f) IPTables allowed` de 2019, ofrecida y sin efecto (`scan.py:171`),
    desaparece con el código de 2019; si se quiere escanear lo que el cortafuegos
    permite, será una regla más de las redes autorizadas.

---

## Ideas aparcadas

Merecen recordarse, pero todavía no tienen sitio:

- **Registro de vulnerabilidades** — [deducido] de `Reporting.vulns()` de 2019
  (`reporting.py:96-97`), que estaba roto y no se usaba. El autor pensó en clasificar
  hallazgos por gravedad. Se aparca porque roza el no objetivo de cumplimiento normativo
  de `IDEA.md`; parte de la idea revive en la gravedad de las alertas (3.2).
- **Resolución DNS de los FQDN encontrados en `/etc` y `/var/log`** — [deducido]
  (`gathering4.py:77-126,198-250` de 2019). El colector nuevo **no la hace**
  (`CAMBIO.md`, *Qué se pierde*): lista los nombres candidatos del área `carving`, pero
  no los resuelve, porque generaría tráfico DNS desde la máquina y tardaría. Si se
  recupera, tendría que hacerse fuera de la máquina (por ejemplo, desde el central) y de
  forma opcional.
- **Guardar el paquete en bruto para reinterpretarlo** — [usuario], pendiente. Si el
  central guardara el paquete en bruto además de la fotografía, podría reinterpretar las
  recogidas antiguas cuando mejore un analizador, a cambio de guardar más datos
  sensibles. `CAMBIO.md` (*Modelo de datos*) tomó la decisión menor y revisable de no
  guardarlo, y la decisión 5.0 de `TODO.md` la deja en manos del usuario. Si 5.0 no lo
  adopta, queda aquí.
- **Categorías de ficheros interesantes** — [deducido] (`gathering0.py:12-71` de 2019,
  números del 0 al 18 que no se usaban). Pensadas para declarar huecos por área, que el
  colector nuevo ya declara por sección (1.3). Se conserva la idea solo por si hiciera
  falta agrupar fuentes de otra forma.
- **Pendientes de `IDEA.md`** — [usuario]: el tamaño real del parque, cuánto tiempo se
  guarda el histórico, los canales concretos de aviso y la lista exacta de reglas de
  serie.
