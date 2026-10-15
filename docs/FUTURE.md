# aridi: lo que está previsto

> Parte de lo que mide [`MVP.md`](MVP.md) y va hacia lo que describe [`IDEA.md`](IDEA.md).
> Aquí no se toman decisiones tecnológicas: describe capacidades, no soluciones.

## Origen de cada entrada

Cada funcionalidad lleva su procedencia, y los tres orígenes no se mezclan:

- **[declarado]:** lo que el propio proyecto anuncia (roadmap, TODO, issue, comentario
  del autor). **El proyecto no declara ningún futuro en ninguna parte.** No hay roadmap,
  `TODO`/`FIXME`/`XXX` (verificado con grep), issues en el repositorio ni comentarios del
  autor sobre planes. Por eso ninguna entrada de este documento tiene este origen.
- **[deducido]:** lo que deja ver el código: un módulo a medias, una función preparada
  que no se usa, un fallo observado. Se cita el archivo o la observación de `MVP.md`.
- **[usuario]:** lo que el usuario ha decidido el 2026-10-15 (`IDEA.md` y la
  conversación del alcance).

**El orden de las etapas** lo ha decidido el usuario: se construye por capas, y cada
etapa se apoya en la anterior. El motivo es que el éxito depende de confiar en los datos,
y nada de lo central vale si el colector se equivoca.

---

## Etapa 1: un colector fiable

**Tema:** que una sola recogida, en cualquier máquina del alcance, diga la verdad, la diga
entera y diga lo que no sabe.

### 1.1 Datos correctos en lo que hoy está a medias — [deducido]

Corregir las funcionalidades n.º 11 a 20 de `MVP.md`.

- **Criterios de aceptación:** en las distribuciones del alcance (1.6), cada apartado da
  datos que coinciden con lo que obtiene una herramienta de referencia en la misma
  máquina. Como mínimo:
  - **Hashes:** reconoce yescrypt (`$y$`), `$2b$` y las cuentas bloqueadas (`!` y `*`),
    y las distingue de "sin contraseña". Hoy: n.º 12.
  - **Usuarios:** un miembro de grupo o un uid sin entrada en `passwd` no anula ningún
    apartado. Hoy: n.º 12 y 16.
  - **Discos:** se ven con el `lsblk` actual, incluidos los montajes múltiples, y los
    porcentajes de carga y ocupación son correctos. Hoy: n.º 13.
  - **Red:** se ve con interfaces `@` (VLAN, veth, contenedores). Hoy: n.º 15.
  - **Conexiones:** se ve IPv6 y el UDP en escucha se clasifica como tal. Hoy: n.º 16.
  - **Procesos:** se ven con pocos procesos. Hoy: n.º 17.
  - **CPU:** se ve correctamente en ARM y en x86_64. Hoy: n.º 11.
  - **Distribución:** la versión aparece aunque solo exista `VERSION_ID` (Alpine). Hoy:
    n.º 2.
- **Fuera:** ampliar lo que se recoge; eso es 1.7.

### 1.2 Funcionamiento sin preguntas — [usuario]

Hoy se hacen 7 preguntas por consola (`MVP.md` n.º 21). Pasan a decidirse antes de
empezar.

- **Criterios de aceptación:**
  - Una recogida sin terminal, como root o sin root, completa todos los apartados
    habilitados.
  - Lo que hoy se pregunta (búsqueda de permisos, resolución de FQDN, escaneo) se decide
    de antemano, con valores por defecto prudentes: lo costoso o lo que genera tráfico,
    desactivado.
  - El código de salida distingue entre "completa", "completa con huecos" y "fallida".

### 1.3 Declarar lo que no se ha podido ver — [usuario]

- **Criterios de aceptación:**
  - Cada recogida incluye, por apartado, si se obtuvo o no.
  - Cuando no, incluye el motivo: sin permisos, herramienta ausente, no aplica en este
    sistema o error.
  - Un apartado que falla nunca desaparece en silencio, como pasa hoy.

### 1.4 Resultado estructurado y exportable — [usuario]

Además del informe legible, que se conserva ([deducido]: `reporting.py:132-244`), cada
recogida produce un resultado que otra herramienta puede leer sin interpretar texto, y que
el componente central podrá importar (etapa 2).

- **Criterios de aceptación:**
  - Todo lo que aparece en el informe legible está en el resultado estructurado.
  - El resultado identifica la máquina, el momento de la recogida y la versión de aridi.

### 1.5 Ningún rastro y ninguna exigencia en la máquina — [usuario]

- **Criterios de aceptación:**
  - No necesita instalar nada.
  - Tras una recogida no queda ningún fichero en la máquina, salvo los que el usuario
    pida expresamente en modo local.
  - Funciona sea cual sea el directorio desde el que se lanza. Hoy depende de él:
    `MVP.md` n.º 1.
  - Si falta una herramienta del sistema, usa otra vía o lo declara (1.3). Por ejemplo,
    USB sin `lsusb` (`MVP.md` n.º 20) o servicios con `systemctl` pero sin systemd
    (n.º 19).

### 1.6 Cobertura de plataformas — [usuario]

- **Criterios de aceptación:** las recogidas cumplen 1.1 a 1.5 en:
  - Debian y Ubuntu con soporte vigente;
  - RHEL y derivadas (Alma, Rocky);
  - Fedora (hoy fallan los paquetes: `MVP.md` n.º 14);
  - SUSE/openSUSE;
  - Arch;
  - Alpine (hoy no hay paquetes: n.º 14);
  - RHEL/CentOS 6 y 7;
  - contenedores en ejecución;
  - máquinas físicas y virtuales, en x86_64 y en ARM.
- **Riesgo conocido:** RHEL/CentOS 6 trae de serie un intérprete antiguo y muchos
  contenedores no traen ninguno. Cómo cumplir aquí la regla de no exigir nada se decide
  en la arquitectura.

### 1.7 Cobertura de los subsistemas modernos — [deducido] de `MVP.md` *Fuera de lo entregado*

- **Criterios de aceptación:** se recogen, cuando existen:
  - IPv6 en interfaces, rutas y conexiones;
  - cortafuegos nftables, firewalld y ufw;
  - el registro del sistema de journald (accesos y fallos);
  - inits distintos de systemd y SysV (OpenRC, runit);
  - sesiones en sistemas que han sustituido `wtmp`.

### 1.8 Recuperar lo abandonado — [deducido]

- **NTP o sincronización de hora:** el código existe pero es inalcanzable
  (`gathering2.py:260`). Se recupera, incluidos los servicios de hora actuales.
- **Comprobación de permisos de `passwd`, `group`, `shadow` y `gshadow`:** está escrita y
  no se llama (`gathering0.py:193-208`). Pasa a formar parte de los permisos peligrosos.
- **Criterio de aceptación:** ambos aparecen en el resultado de toda recogida en la que
  sean aplicables.

### 1.9 Seguridad del propio colector — [deducido] de `ESTUDIO.md` §8 y `MVP.md`

- **Criterios de aceptación:**
  - Ningún fichero de salida se crea con un nombre predecible en un directorio compartido.
  - Ninguno queda legible por otros usuarios (hoy `-rw-r--r--`: `MVP.md` n.º 9).
  - Los datos que vienen de la máquina (banners, líneas de registro) se tratan como
    texto no fiable allá donde se muestren.
  - Ninguna recogida puede generar tráfico de red hacia fuera de la máquina si no se ha
    autorizado (ver etapa 4).

### 1.10 Grafo fuera del colector — [usuario]

El grafo, que hoy depende de `graphviz` (`graph.py:6`), sale del colector, y el colector
queda **sin dependencias ajenas**. El mapa de relaciones sigue en el resultado; su
dibujo pasa a la etapa 2 o 3 (2.7).

### 1.11 Verificación repetible — [deducido] de `MVP.md` *Definición de terminado*

Hoy no hay pruebas, y esta medición se hizo a mano.

- **Criterio de aceptación:** existe una forma repetible de comprobar 1.1 a 1.9 en las
  plataformas de 1.6, incluidas las funcionalidades hoy *implementadas, sin verificar*
  (barrido ARP, systemd, sesiones, `iptables` con reglas, zypper y pacman, x86_64).

---

## Etapa 2: inventario central

**Tema:** que el equipo tenga todas sus máquinas en un solo sitio, al día y consultables.
Todo es [usuario] (`IDEA.md`).

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

El mapa de infraestructura que el código ya construye (`reporting.py:99`) se muestra en la
interfaz web, en sustitución del grafo del colector (1.10).

- **Criterio de aceptación:** para una máquina, se ven las IPs con las que se relaciona y
  el papel de cada una.

---

## Etapa 3: cambios y alertas

**Tema:** enterarse de lo que importa sin tener que mirar. Todo es [usuario].

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

## Etapa 4: exploración de red acotada

**Tema:** conservar la capacidad de descubrir la red sin que sea ofensiva.

### 4.1 Descubrimiento y escaneo solo en redes autorizadas — [usuario], sobre [deducido]

Parte del barrido ARP (*implementado, sin verificar*) y del escaneo TCP (*entregado con
limitaciones*) actuales (`scan.py`).

- **Criterios de aceptación:**
  - Está desactivado por defecto.
  - Solo actúa sobre redes que el administrador ha autorizado de forma explícita.
  - Nunca toca una IP fuera de ese perímetro, aunque aparezca en el inventario o en los
    registros. Hoy sí lo hace: `MVP.md` n.º 8.
  - La categoría `(f) IPTables allowed`, ofrecida y sin efecto (`scan.py:171`), se
    resuelve o se retira.
  - El resultado se integra en el inventario y en el mapa de relaciones.

---

## Ideas aparcadas

Merecen recordarse, pero todavía no tienen sitio:

- **Registro de vulnerabilidades** — [deducido] de `Reporting.vulns()`
  (`reporting.py:96-97`), que está roto y no se usa. El autor pensó en clasificar
  hallazgos por gravedad. Se aparca porque roza el no objetivo de cumplimiento normativo
  de `IDEA.md`; parte de la idea revive en la gravedad de las alertas (3.2).
- **Resolución DNS de los FQDN encontrados en `/etc` y `/var/log`** — [deducido]
  (`gathering4.py:77-126,198-250`). Genera tráfico DNS y tarda. Queda por decidir si se
  mantiene, si pasa a ser opcional o si se retira.
- **Categorías de ficheros interesantes** — [deducido] (`gathering0.py:12-71`, números
  del 0 al 18 que no se usan). Podrían servir para declarar los huecos por área (1.3).
- **Pendientes de `IDEA.md`** — [usuario]: el tamaño real del parque, cuánto tiempo se
  guarda el histórico, los canales concretos de aviso y la lista exacta de reglas de
  serie.
