# Corpus de muestras

Muestras reales de máquinas Linux con las que se prueba todo el colector (`TODO.md`,
fase 1). Cada muestra es el resultado de ejecutar `collector/aridi-collect.sh` como root
en una máquina desechable preparada con un escenario conocido, junto con la «verdad de
referencia» obtenida con las herramientas del propio sistema.

> **Estado:** desde la fase 2, el colector solo emite las secciones `meta.*` (identidad
> de la ejecución, `docs/FORMATO.md`). Al cerrar cada área de la fase 3 se vuelve a
> capturar el corpus completo.

## Estructura

```
tests/corpus/
  images.txt            imágenes de contenedor, fijadas por digest
  scenario.sh           escenario común (se ejecuta dentro de la máquina)
  facts.sh              verdad de referencia (se ejecuta dentro de la máquina)
  capture.sh            captura en contenedor
  <nombre>/<variante>/  una muestra
    bundle.aridi        paquete en bruto escrito por el colector
    facts.txt           salida de facts.sh
    scenario.txt        qué preparó el escenario (ok) y qué no pudo (skip)
    meta.txt            imagen, digest, plataforma, red, fecha, códigos de salida
    collector.stderr    solo si el colector escribió algo en stderr
tests/lima/             VMs (Lima 2.x) para lo que no dan los contenedores
  <vm>.yaml, scenario-vm.sh, capture-vm.sh
tests/corpus/vm-<vm>/vm/  muestras de VM, con los mismos ficheros
```

## Cómo se regenera

**Todo se ejecuta en máquinas desechables, nunca en el anfitrión:**

```sh
tests/corpus/capture.sh all                  # 10 imágenes × 3 variantes (contenedores)
tests/corpus/capture.sh debian12 bridge      # una sola muestra
tests/lima/capture-vm.sh all                 # 3 VMs (crea, captura y borra cada una)
tests/lima/capture-vm.sh rocky9-arm64        # una sola VM
```

**Duración observada** (Mac arm64, 2026-10-15): unos 100 s para las 30
muestras de contenedor, con las imágenes `server` ya construidas, y unos 4 min para las 3
VMs, la x86_64 emulada incluida.

**Variantes de contenedor:**

- **`minimal`:** la imagen tal cual, sin Python añadido, con `--network none`.
- **`server`:** la imagen más `iproute2`, `procps`, `util-linux`, `nftables`, `iptables`
  y `socat` (`nc` en CentOS 6), con `--network none`.
- **`bridge`:** la imagen `server` en una red Docker `--internal`, que da la interfaz
  `eth0@ifN` sin acceso a Internet.

Las imágenes `server` se construyen una vez, con red, y se guardan como
`aridi-corpus:<nombre>-server`. Para reconstruirlas: `docker rmi aridi-corpus:<nombre>-server`.

**Requisitos de las VMs:** `brew install lima lima-additional-guestagents` (el segundo,
solo para la VM x86_64). Las VMs no montan ningún directorio del anfitrión
(`mounts: []`). La VM x86_64 se emula con QEMU y tarda varios minutos.

## Qué contiene cada muestra (escenario)

`scenario.sh` reproduce los casos que rompían el aridi de 2019 (`docs/MVP.md`):

| Caso | Para qué |
|---|---|
| Usuario `alice` con contraseña (algoritmo por defecto de la distribución) | yescrypt `$y$` en Debian 12/13, Ubuntu 24.04, Fedora 44 y Arch; SHA-512 `$6$` en el resto (n.º 12) |
| Usuario `bob` bloqueado | Cuentas bloqueadas frente a «sin contraseña» |
| Grupo `ghostgrp` con el miembro `ghostuser`, sin cuenta | Miembro de grupo sin usuario (n.º 12) |
| Proceso `sleep` con uid 4242, sin cuenta | Uid sin nombre en procesos y sockets (n.º 16) |
| Escucha TCP en `[::]:8080`, TCP en `127.0.0.1:8081` y UDP en `0.0.0.0:5514` | IPv6 y UDP en escucha (n.º 16). Solo en `server`, `bridge` y en `minimal` con Python (Rocky 9). |
| `/usr/local/bin/aridi-suid-test` (SUID) y `/srv/world-writable` (777 sin *sticky bit*) | Permisos peligrosos (n.º 5) |
| `/etc/issue.net` con secuencia ANSI y `<script>` | Datos no fiables en las vistas |
| `/etc/hosts` con entradas v4 y v6, y un DNS IPv6 en `resolv.conf` | Resolución y relaciones (`ESTUDIO.md` §8) |
| `/etc/aridi-corpus.conf` y `/var/log/aridi-corpus.log` con IPs, versiones y prefijos de red | Carving |
| Montajes: tmpfs en `/srv/scratch` y *bind* de solo lectura en `/srv/bind` (además de los *bind* de Docker para `/etc/hosts`…) | Montajes múltiples (n.º 13) |
| Red `bridge`: interfaz `eth0@ifN` | n.º 15 |

En las VMs, `tests/lima/scenario-vm.sh` añade:
- systemd en marcha, con un servicio que falla a propósito (`aridi-fails.service`);
- sesiones SSH reales de `alice` (terminadas y una abierta, desde `127.0.0.1` y `::1`);
- un intento fallido para un usuario inexistente;
- una tabla nftables `inet aridi_corpus` con reglas INPUT, OUTPUT y FORWARD;
- una regla de firewalld (Rocky);
- servidores de hora fijos (timesyncd en Debian y chrony en Rocky).

En las VMs, las escuchas y el proceso con uid 4242 son unidades transitorias de systemd
(`systemd-run`). El uid 4242 se consigue con `setpriv`, porque `User=` falla con un uid sin
cuenta. Una unidad solo se marca `ok` si sigue activa un segundo después de arrancar.

| VM | Arquitectura | hash de `alice` | Extra |
|---|---|---|---|
| `vm-debian12-arm64` | aarch64 | `$y$` | timesyncd |
| `vm-rocky9-arm64` | aarch64 | `$6$` | firewalld y chrony |
| `vm-debian12-amd64` | x86_64 (QEMU) | `$y$` | timesyncd |

**Dos trampas que ya se encontraron** (afectan también al colector):

- **stdin:** los scripts que llegan por `sh -s` comparten stdin con sus comandos. Un `ssh`
  sin `-n` se come el resto del script; con bash, que lee línea a línea, se corta sin
  avisar. Por eso `capture-vm.sh` copia los escenarios dentro de la VM y los ejecuta con
  `</dev/null`.
- **Puerto 5353:** en Debian lo ocupa `systemd-resolved` (mDNS), así que el UDP del
  escenario usa el 5514.

Lo que de verdad contiene cada muestra está en su `scenario.txt`. Una línea `skip`
significa que ese caso **no** está en la muestra.

## Qué no cubre

- **USB real:** no hay en contenedores ni en VMs. Las pruebas de USB usan datos
  sintéticos (`tests/test_parsers/data/usb/`).
- **btrfs y subvolúmenes:** las imágenes de Lima usan ext4 o xfs.
- **`btmp` con intentos fallidos:** necesita una petición de contraseña interactiva. Los
  intentos fallidos solo quedan en journald.
- **systemd en contenedores:** no está en marcha. Esto es intencionado: es el caso «hay
  `systemctl` pero no hay systemd» (n.º 19).
- **Cortafuegos en contenedores:** sin `CAP_NET_ADMIN`, `nft` e `iptables` fallan. También
  es intencionado: es el caso «sin permiso».
- **Bloqueo de `bob` en Alpine:** el `passwd -l` de busybox no lo aplica (ver
  `alpine320/*/scenario.txt`).
- **Arquitectura:** las imágenes de contenedor son arm64, salvo Arch y CentOS 6 (amd64
  emulado). La VM `debian12-amd64` aporta un x86_64 completo.
