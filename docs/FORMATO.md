# aridi: formato del paquete en bruto y de la fotografía (v1)

> Este documento es el **contrato** entre las tres piezas: el script
> (`collector/aridi-collect.sh`) escribe el paquete en bruto, el núcleo (`src/aridi`) lo lee
> y produce la fotografía, y el central (fase 5) guarda fotografías. Las decisiones de fondo
> están en [`CAMBIO.md`](CAMBIO.md) (*Formatos y contratos*). Lo que aquí se describe está
> implementado y probado en la fase 2 de `TODO.md`; cuando algo es una decisión pendiente,
> se dice.

## Paquete en bruto v1

### Ejemplo

Salida real del script en `debian:12` (fase 2, solo secciones `meta.*`), recortada:

```
ARIDI-BUNDLE 1 2.0.0.dev0
boundary a40bb826632d5be73176738ab1e57dc6
--a40bb826632d5be73176738ab1e57dc6 begin meta.date_utc kind=cmd tool=date limit=4194304
2026-10-15T16:41:25Z

--a40bb826632d5be73176738ab1e57dc6 end meta.date_utc status=ok rc=0
--a40bb826632d5be73176738ab1e57dc6 begin meta.machine_id kind=file path=/etc/machine-id limit=4194304

--a40bb826632d5be73176738ab1e57dc6 end meta.machine_id status=na rc=-
--a40bb826632d5be73176738ab1e57dc6 note meta.machine_id not found: /etc/machine-id
--a40bb826632d5be73176738ab1e57dc6 close sections=7
```

### Estructura

El paquete es una secuencia de bytes. Las **líneas de control** son ASCII y terminan en
`\n`; el **contenido** de cada sección son bytes arbitrarios.

1. **Cabecera:** `ARIDI-BUNDLE <formato> <versión_script>`. El formato es un entero
   (hoy `1`); la versión del script, una palabra sin espacios.
2. **Frontera:** `boundary <B>`, donde `<B>` son de 16 a 64 caracteres `[0-9A-Za-z]`. El
   script la genera **al azar en cada ejecución** con 16 bytes de `/dev/urandom` (32
   caracteres hexadecimales). Si no hay `/dev/urandom`, usa la hora y el PID, y lo declara
   en `meta.env` (`boundary_source=weak`).
3. **Secciones**, en el orden en que se recogen. Cada una:
   ```
   --<B> begin <nombre> <campo>=<valor>...
   <contenido>
   --<B> end <nombre> status=<estado> rc=<código>
   --<B> note <nombre> <texto>          (opcional)
   ```
4. **Cierre:** `--<B> close sections=<n>`, con el número de secciones. Después no puede
   haber nada más que espacios en blanco.

**Reglas de la sección:**

- **Nombre:** `[a-z0-9][a-z0-9_.-]*`, de hasta 100 caracteres, **único** en el paquete. El
  prefijo hasta el primer punto es el área (`system.os_release` → `system`). El prefijo
  `meta.` es la identidad de la ejecución y no pertenece a ningún área.
- **Campos de `begin`:** `clave=valor` sin espacios. Hoy:
  - `kind`: `cmd` (salida de un comando), `file` (contenido de un fichero) o `text` (valor
    calculado por el propio script);
  - `tool` o `path`: el comando o la ruta leída;
  - `limit`: bytes máximos del contenido.

  Un lector debe ignorar los campos que no conozca.
- **Contenido:** los bytes que produjo la fuente, **sin escapar**. El script escribe
  siempre un `\n` adicional tras el contenido, de modo que la línea `end` empieza a
  principio de línea. **Ese `\n` no forma parte del contenido.** Un contenido vacío es
  válido.
- **Fin del contenido:** la primera aparición de `\n--<B> end <nombre> ` tras el `begin`.
  Como `<B>` es aleatoria y nunca se pasa a ningún proceso hijo, un contenido no puede
  contenerla salvo por azar (2⁻¹²⁸). Un texto con aspecto de frontera, pero con otra
  frontera u otro nombre, es contenido.
- **Límite de tamaño:** el script deja pasar como mucho `limit + 1` bytes. Si el lector
  recibe más de `limit`, **corta a `limit` y marca la sección como truncada**. Así el
  script no tiene que contar bytes (ver *Decisiones*).
- **`status`** (estado de la recogida):

  | Estado | Cuándo lo pone el script |
  |---|---|
  | `ok` | El comando terminó con 0, o con SIGPIPE (141) porque su salida superaba el límite |
  | `denied` | El fichero no es legible, o el comando falló y su stderr dice `Permission denied` u `Operation not permitted` |
  | `missing` | La herramienta no existe (`command -v`), o el comando devolvió 127 |
  | `na` | El fichero no existe: esa fuente no aplica a esta máquina |
  | `timeout` | Hay `timeout` y el comando devolvió 124, 137 o 143 |
  | `error` | Cualquier otro código distinto de 0 |

- **`rc`:** el código de salida del comando, o `-` si no se ejecutó nada.
- **`note`:** como mucho una por sección, de una línea y como mucho 400 bytes. Es el
  comienzo de stderr del comando, o el motivo de que no se ejecutara. Los bytes de
  control y los no ASCII se sustituyen por `?` en origen.

### Cómo se ejecuta el script

- `sh aridi-collect.sh > m.aridi`, o por SSH: `ssh host sh -s < aridi-collect.sh`.
- Solo POSIX `sh`. Probado con `dash`, `bash` (incluido el 4.1 de CentOS 6) y busybox
  `ash`, en las 10 imágenes del corpus (`tests/run.sh collector`).
- **Nunca escribe en disco:** todo sale por stdout, sin ficheros temporales. `umask 077` y
  `LC_ALL=C`. La prueba comprueba con `find / -xdev -newer` que no crea ni modifica nada.
- **Cada comando lee de `/dev/null`:** el script puede llegar por stdin, y un comando que
  la leyera se comería el resto del script.
- **Límites:** 4 MiB por sección (`ARIDI_SECTION_LIMIT`) y 60 s por comando
  (`ARIDI_SECTION_TIMEOUT`), con `timeout` (coreutils) o `timeout -t` (busybox antiguo).
  Si no hay ninguno, los comandos se ejecutan sin límite de tiempo y se declara en
  `meta.env` (`timeout=none`).
- **PATH fijo,** con los directorios del sistema primero:
  `/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin`.
- **Sin privilegios** (uid 65534) termina igual, con 0, y marca `denied` lo que no puede
  leer.
- **Código de salida:** 0 siempre que llegue al cierre. Lo que falle se declara en su
  sección, no en el código.

### Secciones `meta.*` (identidad de la ejecución)

| Sección | Fuente | Para qué |
|---|---|---|
| `meta.env` | El propio script (`kind=text`) | Shell, herramienta de `timeout`, límites, origen de la frontera y PATH |
| `meta.date_utc` | `date -u +%Y-%m-%dT%H:%M:%SZ` | `collected_at` |
| `meta.uid` | `id -u` | Con qué privilegios se recogió |
| `meta.machine_id` | `/etc/machine-id` | `machine.machine_id` |
| `meta.dbus_machine_id` | `/var/lib/dbus/machine-id` | Respaldo del anterior |
| `meta.hostname` | `/proc/sys/kernel/hostname` | `machine.hostname` |
| `meta.uname` | `uname -a` | Kernel y arquitectura en bruto |

**Observado en el corpus (2026-10-15):** ninguna de las 30 muestras de contenedor tiene
un `machine_id` utilizable:
- en Debian, Alpine, openSUSE, Arch y CentOS 6 el fichero no existe (`na`);
- en Ubuntu, Rocky, Fedora y CentOS 7 existe pero está vacío (`ok` con 0 bytes), que es
  la convención de systemd para las imágenes base.

En ambos casos la fotografía da `machine_id: null`. Las 3 VMs de Lima sí lo tienen. El
central tendrá que identificar las máquinas sin `machine_id` por su destino SSH (fase 5).

### Lo que el script nunca emite

- **Hashes de contraseñas:** de `/etc/shadow` y `/etc/gshadow` solo salen el usuario y el
  prefijo del algoritmo (`$y$`, `$6$`, `!`, `*`…), filtrados en origen (área de usuarios,
  fase 3).
- **Contenido de claves privadas:** ni SSH (`/etc/ssh/ssh_host_*_key`, `~/.ssh/id_*`) ni
  TLS. Como mucho, su existencia, permisos y huella de la clave pública.
- **Variables de entorno de los procesos** (`/proc/*/environ`).
- **La propia frontera** en argumentos de procesos hijos.

Cada área de la fase 3 que lea datos sensibles añade su prueba de que no salen.

## Fotografía v1

Es el JSON que produce `aridi interpret`. Ejemplo recortado:

```json
{
  "schema_version": 1,
  "machine": {"machine_id": null, "hostname": "corpus-debian12"},
  "collected_at": "2026-10-15T16:43:46Z",
  "collector_version": "2.0.0.dev0",
  "bundle_format": 1,
  "outcome": "gaps",
  "sections": {
    "system": {"status": "no_parser", "reason": "no analyzer for this area yet",
               "data": null, "volatile": false},
    "processes": {"status": "no_parser", "reason": "no analyzer for this area yet",
                  "data": null, "volatile": true}
  },
  "relations": [
    {"ip": "2001:db8::40", "role": "named_in_file", "source": "carving",
     "detail": "/etc/hosts:3"}
  ]
}
```

**Campos:**

- **`schema_version`:** entero, hoy `1`.
- **`machine`:** `machine_id` (32 hexadecimales en minúscula, o `null` si no hay o tiene
  otro formato) y `hostname` (o `null`).
- **`collected_at`:** fecha UTC de la máquina, `AAAA-MM-DDThh:mm:ssZ`, o `null` si no se
  pudo leer o tiene otro formato.
- **`collector_version`** y **`bundle_format`:** los de la cabecera del paquete.
- **`outcome`:** `complete` si todas las áreas están en `ok`, `gaps` si alguna no. Se
  deriva de `sections` y no se lee al cargar.
- **`sections`:** **siempre las 17 áreas, en este orden**, aunque no haya datos:

  | Grupo (2019) | Áreas |
  |---|---|
  | General | `system`, `hardware`, `packages`, `storage`, `permissions` |
  | Específica | `identity`, `users`, `services`, `network`, `firewall`, `timesync` |
  | Volátil | `processes`, `load`, `sessions`, `connections` |
  | Carving y vecinos | `carving`, `neighbours` |

  Cada área tiene:
  - `status`: los seis estados del paquete más dos del núcleo:
    - `not_collected`: el paquete no trae ninguna sección del área;
    - `no_parser`: este núcleo no tiene todavía analizador para el área.

    Un analizador que lanza una excepción deja su área en `error`, con el tipo y el
    mensaje en `reason`, y las demás áreas continúan.
  - `reason`: texto para personas, o `null` si `status` es `ok`;
  - `data`: lo que produce el analizador; su forma la fija cada área en la fase 3;
  - `volatile`: `true` en `processes`, `load`, `connections` y `neighbours`.
- **`relations`:** lista de `{ip, role, source, detail}`:
  - `ip`: IPv4 o IPv6 en forma canónica (`ipaddress`);
  - `source`: el área que la encontró;
  - `detail`: texto libre opcional (fichero y línea, puerto…);
  - `role`: **un código de esta lista, nunca una frase.** Un papel desconocido es un
    error al cargar.

    | Papel | Significado |
    |---|---|
    | `local` | Dirección de la propia máquina |
    | `dns_server` | Servidor DNS configurado |
    | `ntp_server` | Servidor de hora configurado |
    | `login_source` | Origen de un inicio de sesión |
    | `failed_login_source` | Origen de un inicio de sesión fallido |
    | `fw_allowed_in` | Origen permitido por el cortafuegos |
    | `fw_allowed_out` | Destino permitido por el cortafuegos |
    | `peer_in` | Extremo remoto de una conexión entrante |
    | `peer_out` | Extremo remoto de una conexión saliente |
    | `named_in_file` | Mencionada en un fichero de `/etc` o `/var/log`, o en journald |
    | `neighbour` | Vista en la tabla ARP o NDP |
    | `scan_open_port` | Con un puerto abierto en un escaneo del central (fase 7) |

## Política de versiones

- **Las dos versiones son independientes:** `bundle_format` (paquete) y
  `schema_version` (fotografía).
- **Sube `bundle_format`** cualquier cambio que un lector v1 no pueda leer o pueda leer
  mal: la sintaxis de las líneas de control, el significado de un estado o la regla del
  `\n` final.
- **No sube `bundle_format`:**
  - añadir secciones o campos de `begin`, porque el lector ignora lo que no conoce;
  - cambiar el contenido de una sección. De eso se encarga el analizador del área, que
    debe aceptar las variantes que el script haya emitido desde su versión.
- **Sube `schema_version`:**
  - quitar o renombrar un campo;
  - cambiar su tipo o su significado;
  - quitar un área o un papel.

  Añadir un área, un papel o un campo opcional **también la sube**, porque los lectores
  rechazan los papeles desconocidos.
- **Compatibilidad hacia atrás:** `aridi interpret` lee todos los formatos de paquete que
  hayan existido desde la v1. Cuando exista una v2, la v1 se seguirá leyendo con su propio
  lector, y habrá muestras v1 del corpus en las pruebas.
- **Versión desconocida:** un error explícito, nunca una interpretación aproximada.
  - Para un paquete, `UnsupportedVersion`: `aridi` sale con código 2 y el mensaje
    `bundle format N is not supported`.
  - Para una fotografía, `SnapshotError`.
- **El central** guarda la fotografía con su `schema_version`. Al cambiarla, se migran las
  guardadas (fase 5; `CAMBIO.md`, *Riesgos*).

## CLI del núcleo

| Orden | Hace | Código de salida |
|---|---|---|
| `aridi validate <paquete>` | Comprueba el formato y resume los estados | 0 válido, 2 inválido o ilegible |
| `aridi interpret <paquete> [-o f.json]` | Escribe la fotografía en stdout o en un fichero **nuevo** (`0600`, sin seguir enlaces: `O_CREAT\|O_EXCL\|O_NOFOLLOW`) | 0 completa, 1 con huecos, 2 fallida |
| `aridi report <paquete> [--detail]` | Informe de texto: cabecera, las 17 áreas y al final «What could not be seen» con área, estado y motivo | 0, 1 o 2, como `interpret` |

`-v` y `-vv` añaden mensajes de log en stderr. El informe escapa los caracteres de control
del contenido (`\x1b`…), así que un banner con secuencias ANSI no puede alterar la
terminal.

## Decisiones tomadas en la fase 2

- **El número de bytes lo calcula el lector, no el script.** `TODO.md` 2.1 pedía los
  bytes en el paquete. Contarlos en `sh`, sin ficheros temporales, exige `dd` (su resumen
  cambia entre coreutils y busybox) o `tee /dev/fd/N` (depende de `/proc`). Como el fin del
  contenido ya está delimitado, el lector obtiene un número exacto, y la truncación se
  detecta con el byte de más del límite. *Revisable* si hiciera falta detectar corrupción
  en tránsito; SSH ya la detecta.
- **Las secciones `meta.*`** son la identidad de la ejecución y no cuentan como área.
- **`neighbours` es volátil:** la tabla ARP cambia continuamente y sus cambios no deben
  generar alertas (`CAMBIO.md`, volátiles sin alertas). *Revisable* en la fase 6.
- **`sessions` no es volátil como área.** El historial de accesos (orígenes nuevos) sí
  debe poder alertar. La parte activa (quién está conectado ahora) se separará al
  implementar el área 3.14.
- **`denied` se deduce del texto de stderr** en `LC_ALL=C` (`Permission denied`,
  `Operation not permitted`). Un comando que falle por permisos con otro mensaje queda en
  `error`, con su `note`. El analizador del área puede corregirlo.
