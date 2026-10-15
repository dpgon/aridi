# aridi: la idea

> Cada afirmación lleva una marca de procedencia:
> **[observado]** es algo que el proyecto ya hace hoy, y se cita el archivo que lo demuestra;
> **[decidido]** es una intención nueva, acordada con el usuario el 2026-10-15.
> El detalle técnico de lo observado está en [`ESTUDIO.md`](ESTUDIO.md).

---

## Propósito

aridi permite saber con certeza **qué hay en cada máquina Linux de un parque y cómo
cambia con el tiempo**. Visita cada máquina sin instalar nada en ella, toma una
fotografía completa (hardware, sistema, software, usuarios, servicios, red, actividad y
con quién se relaciona), se trae esa fotografía y la guarda junto a las anteriores. Con
ellas mantiene un inventario fiable y consultable, y avisa cuando algo cambia de forma
significativa entre una visita y la siguiente. Nunca modifica las máquinas que observa.

---

## Problema y contexto

**El problema.** Quien administra un parque de máquinas Linux rara vez tiene una imagen
fiable de lo que hay en él. Las fichas de inventario se mantienen a mano y se quedan
desfasadas. Las máquinas cambian sin que nadie lo registre: aparecen paquetes, usuarios,
servicios y puertos, se modifican permisos, se actualiza el kernel. Cuando hace falta
responder "¿qué máquinas tienen esta versión?" o "¿qué ha cambiado en este servidor desde
la semana pasada?", la respuesta exige entrar máquina por máquina.

**Para quién.** Para el equipo que responde de esas máquinas y, de forma secundaria, para
quienes las vigilan o las auditan (ver *Usuarios objetivo*).

**Por qué no bastan las opciones existentes.** Este apartado es una interpretación: el
usuario no ha comparado aridi con productos concretos. Recoge las exigencias que el
usuario ha fijado y que descartan los enfoques habituales:

- **Nada ajeno en las máquinas.** Muchas herramientas de inventario exigen instalar un
  agente permanente o añadir dependencias de terceros, y cada pieza externa es una puerta
  a un ataque de cadena de suministro. aridi nace precisamente para evitarlo
  [observado: el programa se limita a lo que trae el propio lenguaje; ver `ESTUDIO.md` §3].
  A partir de ahora la exigencia es aún más fuerte: no instalar nada y no dejar rastro
  [decidido].
- **Parques heterogéneos y con historia.** Un mismo parque mezcla distribuciones
  distintas, versiones antiguas sin soporte y contenedores. aridi ya se adaptaba
  automáticamente a varias distribuciones y gestores de paquetes
  [observado: `gathering1.py:155-222`, `gathering1.py:477-491`], y debe hacerlo con todas
  las de hoy [decidido].
- **No solo una ficha, sino también las relaciones.** Además de describir la máquina,
  aridi reconstruye con quién se relaciona: servidores DNS, orígenes de accesos,
  conexiones entrantes y salientes, IPs mencionadas en la configuración y los registros
  [observado: `reporting.py:99`]. Pocas herramientas de inventario ofrecen esta vista.

**El contexto del proyecto.** aridi existe desde 2019 como herramienta local e
interactiva que produce un informe de texto en el momento [observado: `aridi.py:34`].
No guarda nada entre ejecuciones ni compara una con otra [observado: `ESTUDIO.md` §6].
Este documento recoge la evolución hacia un sistema centralizado que observa en el
tiempo [decidido].

---

## Usuarios objetivo

| Usuario | Prioridad | Objetivo | Experiencia |
|---|---|---|---|
| **Administrador o equipo de sistemas** que gestiona su propio parque, de unas pocas máquinas a algunos cientos (este tamaño es una **interpretación**: no se ha fijado) | Principal [decidido] | Tener un inventario fiable sin mantenerlo a mano, consultarlo y enterarse de los cambios importantes. | Alta en Linux. Sabe qué es SSH, sudo, un paquete o un servicio. |
| **Equipo de seguridad o cumplimiento** | Secundario [decidido] | Detectar desviaciones y riesgos en máquinas que quizá administran otros, y seguir su evolución. | Alta en seguridad, variable en administración. |
| **Auditor o consultor externo** | Secundario [decidido] | Llevar aridi a los sistemas de un cliente, de forma puntual o repetida, y entregar un resultado. | Alta. Trabaja en entornos ajenos, a veces aislados. |

Dentro de una instalación hay dos roles [decidido]:

- **Administración:** da de alta máquinas y accesos, programa las recogidas, ajusta las
  reglas de alerta y autoriza las redes que se pueden explorar.
- **Consulta:** ve el inventario, el histórico y las alertas.

---

## Funcionalidad principal

### 1. Recogida del perfil de una máquina

Obtiene, de una sola vez, todo lo que se puede saber de la máquina. Hoy ya cubre
[observado: `ESTUDIO.md` §2]:

| Área | Qué se obtiene | Dónde está hoy |
|---|---|---|
| **General** | Hardware (CPU, memoria, USB), kernel, distribución y versión, librería del sistema, paquetes instalados con versión, discos y particiones con ocupación, y búsqueda opcional de permisos peligrosos en el sistema de ficheros (directorios escribibles por todos sin protección, ficheros escribibles por todos, binarios con privilegios elevados). | `gathering1.py` |
| **Específica** | Identidad (nombre, dominio, identificador, banners), usuarios y grupos con el tipo de protección de su contraseña, servicios (en marcha, fallidos, otros estados), interfaces, direcciones, rutas, DNS, NTP y reglas de cortafuegos. | `gathering2.py` |
| **Volátil** | Procesos (estado, mayores consumidores, zombis), memoria, carga y uso de CPU, carga de disco, sesiones activas, últimos accesos y accesos fallidos con su origen, conexiones de red con el proceso que las abrió. | `gathering3.py` |
| **Carving** | Direcciones y nombres de máquina mencionados en la configuración (`/etc`) y en los registros (`/var/log`), con resolución opcional. | `gathering4.py` |

Lo que cambia ahora [decidido]:

- **Ninguna pregunta durante la ejecución.** Hoy hace siete preguntas por consola
  [observado: `ESTUDIO.md` §5]. Pasa a funcionar sin nadie delante.
- **Cobertura moderna y antigua.** Cubre las familias principales con soporte vigente
  (Debian/Ubuntu, RHEL y derivadas, Fedora, SUSE/openSUSE, Arch, Alpine), distribuciones
  antiguas sin soporte (RHEL/CentOS 6 y 7) y contenedores en ejecución, en máquinas
  físicas y virtuales.
- **Nada exigido, nada instalado, ningún rastro.** Recoge lo que pueda con lo que traiga
  el sistema. Si algo falta (una herramienta, un permiso, un intérprete), busca otra vía
  o renuncia a ese dato.
- **Declarar lo que no se ha podido ver.** Cada recogida dice explícitamente qué datos
  faltan y por qué: sin permisos, sin herramienta, no aplica, error. Hoy, cuando un
  apartado falla, simplemente desaparece del informe [observado: `ESTUDIO.md` §8].
- **Datos correctos.** Los defectos que hoy producen datos erróneos sin avisar se
  consideran fallos del producto, no limitaciones aceptadas. Por ejemplo, contraseñas
  modernas tratadas como "sin contraseña" o servicios en IPv6 invisibles
  [observado: `ESTUDIO.md` §8].

### 2. Mapa de relaciones (infraestructura)

Para cada IP relacionada con la máquina, registra qué papel tiene: la propia máquina,
servidor DNS, servidor NTP, origen de accesos o de accesos fallidos, permitida por el
cortafuegos, conectada hacia o desde la máquina, mencionada en un fichero
[observado: `reporting.py:99`, alimentado desde todos los módulos]. En el componente
central, ese mapa forma parte del inventario y de su histórico [decidido].

### 3. Descubrimiento de red y escaneo de puertos (opcional)

Hoy aridi puede barrer la red local y escanear puertos de las IPs que descubre, incluidas
algunas que solo aparecen en registros [observado: `scan.py`]. A partir de ahora
[decidido]:

- está **desactivado por defecto**;
- solo actúa sobre **redes que el administrador haya autorizado expresamente**;
- **nunca** toca una IP que esté fuera de ese perímetro, por muy presente que esté en el
  inventario.

### 4. Ejecución remota

Desde el componente central, aridi llega a cada máquina por SSH, hace la recogida allí y
se trae el resultado por el mismo canal, sin dejar nada instalado [decidido]. Las
recogidas se pueden **programar** por máquina o por grupo (por ejemplo, cada noche) y
**lanzar a demanda** [decidido].

### 5. Modo local autónomo

aridi sigue pudiendo ejecutarse a mano en una sola máquina, sin componente central
[observado: es el único modo actual], y produce allí mismo un **informe legible**
[observado: vistas resumida, detallada, completa y de infraestructura,
`reporting.py:132-244`]. Además genera un **resultado que se puede importar después** al
componente central [decidido]. Esto sirve para el auditor y para máquinas a las que no se
llega por SSH.

### 6. Inventario central

Es el núcleo del producto [decidido]. Guarda la última fotografía de cada máquina y todas
las anteriores, y permite:

- consultar la ficha completa de una máquina;
- **buscar en todo el parque** (por ejemplo, "¿qué máquinas tienen este paquete o esta
  versión?", "¿dónde escucha este puerto?", "¿dónde existe este usuario?");
- organizar las máquinas en **grupos**;
- ver la **evolución** de una máquina en el tiempo y comparar dos fotografías cualesquiera;
- ver qué no se pudo recoger en cada máquina y desde cuándo.

### 7. Detección de cambios y alertas

Al llegar cada nueva fotografía, aridi la compara con la anterior [decidido]:

- Trae de serie un **criterio de cambio significativo con niveles de gravedad**. Ejemplos:
  usuario nuevo con acceso o privilegios, puerto nuevo a la escucha, servicio que pasa a
  fallar, nuevo binario con privilegios elevados, cambio de kernel, disco casi lleno.
- El administrador puede **ajustar o silenciar** reglas por máquina o por grupo.
- Las alertas se ven en la interfaz web y **se envían por canales externos** (correo,
  chat, webhook). Los canales concretos están por decidir.
- También es un cambio significativo que una máquina **deje de responder** o deje de
  enviar datos que antes enviaba. Esto es una **interpretación** que se deduce del
  criterio de éxito.

### 8. Interfaz web

Es el sitio donde el equipo consulta el inventario, el histórico y las alertas, y donde
el rol de administración gestiona máquinas, grupos, accesos, programación, reglas y redes
autorizadas [decidido].

---

## Recorridos clave del usuario

### A. Incorporar una máquina y obtener su ficha

1. El administrador da de alta una máquina (o varias) en la web: cómo llegar a ella por
   SSH, en qué grupo va y con qué frecuencia se inventaría.
2. Lanza una primera recogida a demanda.
3. aridi entra en la máquina, recoge sin hacer preguntas, se trae el resultado y no deja
   nada allí.
4. La ficha de la máquina aparece en el inventario, con un apartado visible de **lo que
   no se ha podido ver y por qué**.
5. A partir de ese momento, las recogidas programadas mantienen la ficha al día.

### B. Enterarse de un cambio y entenderlo

1. Una recogida programada detecta, por ejemplo, un puerto nuevo a la escucha y un
   usuario nuevo con privilegios en un servidor.
2. aridi genera alertas con su gravedad y las envía por el canal configurado.
3. El administrador abre la alerta en la web y ve la comparación entre la fotografía
   anterior y la nueva de esa máquina.
4. Decide: investiga fuera de aridi, porque aridi no corrige nada; da el cambio por
   bueno; o ajusta la regla para esa máquina o ese grupo si era ruido.

### C. Responder una pregunta sobre todo el parque

1. Alguien pregunta "¿qué máquinas tienen esta versión de este paquete?" o "¿dónde
   existe este usuario?".
2. El usuario lo busca en el inventario y obtiene la lista de máquinas, con la fecha de
   la última fotografía de cada una.
3. Si quiere datos al minuto, lanza una recogida a demanda sobre esas máquinas.

### D. (Secundario) Auditoría de una máquina aislada

1. El auditor ejecuta aridi a mano en la máquina, que no tiene acceso SSH desde el
   componente central.
2. Obtiene allí mismo el informe legible y, además, el resultado exportable.
3. Si lo desea, lo importa después en la instalación de ese cliente, donde queda como una
   fotografía más.

---

## Principios del producto

**Lo que el proyecto ya defiende** (se ve en sus decisiones):

- **Cero dependencias ajenas.** Se limita a lo que trae el propio lenguaje para no abrir
  la puerta a ataques de cadena de suministro [observado: `ESTUDIO.md` §3; la única
  excepción es el dibujo opcional del grafo de red, `graph.py:6`].
- **Adaptarse a la máquina, no exigirle nada.** Detecta la distribución, el gestor de
  paquetes y el sistema de servicios, y usa lo que encuentra [observado:
  `gathering1.py:155-222,477-491`, `gathering2.py:402-464`].
- **Sacar todo lo posible, aunque algo falle.** Cada apartado se recoge por separado, de
  modo que un fallo no detiene el resto [observado: cada apartado va aislado, por
  ejemplo en `gathering1.py:411-503`].
- **Funcionar sin ser root, aunque se vea menos.** Si no tiene permisos, avisa y sigue
  con lo que pueda [observado: `aridi.py:110-120`, `gathering0.py:116-129`].
- **Mirar las relaciones, no solo la máquina.** El mapa de infraestructura es transversal
  a todo el producto [observado: `reporting.py:99`].
- **Dos niveles de lectura.** Un resumen para hacerse una idea y un detalle para
  investigar [observado: `reporting.py:132-204`].

**Lo que se defiende de aquí en adelante** [decidido]:

- **Solo lectura, siempre.** aridi observa, informa y recomienda; nunca modifica una
  máquina. Esto es lo que permite darle acceso privilegiado a todo el parque con
  tranquilidad.
- **Ningún rastro.** No se instala nada, no se exige nada y no queda nada en la máquina
  al terminar.
- **Honestidad sobre los huecos.** Es tan importante saber lo que no se ha podido ver
  como lo que sí. Un dato ausente se declara, nunca se omite en silencio.
- **Datos fiables antes que datos abundantes.** Un dato incorrecto es peor que uno que
  falta.
- **Nada ofensivo por defecto.** Explorar la red es una opción explícita y acotada a
  redes autorizadas.
- **Útil sin configurar, ajustable sin esfuerzo.** Las alertas funcionan desde el primer
  día con un criterio de serie, y se ajustan por máquina o por grupo.
- **Los resultados sensibles se tratan como sensibles.** Un perfil de máquina describe
  usuarios, servicios expuestos y debilidades, así que solo lo ve quien tiene acceso. Es
  una **interpretación** de lo hablado, a partir de los riesgos de `ESTUDIO.md` §8.

---

## No objetivos

- **No corrige ni configura nada** en las máquinas, ni siquiera con confirmación
  [decidido]. No es una herramienta de gestión de configuración ni de parcheo.
- **No deja nada instalado** en las máquinas: no hay agentes permanentes [decidido].
- **No es una monitorización en tiempo real.** Trabaja por fotografías periódicas o a
  demanda; no vigila métricas segundo a segundo ni sustituye a un sistema de métricas o
  de disponibilidad. Es una **interpretación**, que se deduce del modelo de recogidas
  programadas.
- **No es un escáner de redes ni una herramienta de intrusión.** Solo explora redes que
  se le autorizan expresamente, y nunca IPs de terceros por el mero hecho de aparecer en
  los registros [decidido].
- **No es un analizador ni un archivo de registros.** Busca en ellos IPs y nombres de
  máquina para el mapa de relaciones y los accesos, pero no los centraliza ni los indexa.
  Es una **interpretación** del alcance actual [observado: `gathering4.py`].
- **No inventaría sistemas que no sean Linux** (BSD, macOS, Windows) [decidido].
- **No separa varios clientes dentro de una misma instalación.** Cada equipo o cliente
  tiene su propia instalación [decidido].
- **No es un producto de cumplimiento normativo.** No evalúa contra marcos como CIS o
  ENS. Es una **interpretación**: no se ha hablado de ello y queda fuera mientras no se
  decida lo contrario.

---

## Glosario del dominio

Los términos se toman de los nombres que usa el propio código.

- **Recogida (gathering):** una ejecución de aridi en una máquina que obtiene su perfil.
  Los módulos `gathering0` a `gathering4` contienen sus fases.
- **Fotografía:** el resultado de una recogida en un momento dado. El inventario guarda
  la sucesión de fotografías de cada máquina. Es un término nuevo, sin equivalente en el
  código.
- **Precheck:** la comprobación previa del contexto (con qué permisos se ejecuta, qué
  ficheros se pueden leer, qué herramientas hay disponibles). `gathering0.py:8`.
- **Información general:** hardware, sistema operativo, paquetes, discos y permisos del
  sistema de ficheros (opción `-g`). `gathering1.py`.
- **Información específica:** identidad, usuarios, servicios, red y cortafuegos
  (opción `-s`). `gathering2.py`.
- **Información volátil:** el estado en el momento de la recogida: procesos, memoria,
  CPU, disco, sesiones y conexiones (opción `-v`). `gathering3.py`.
- **Carving:** extraer direcciones y nombres de máquina mencionados en `/etc` y
  `/var/log` (opción `-c`). `gathering4.py`.
- **Infraestructura:** el mapa que asocia cada IP con los papeles que tiene respecto a la
  máquina. `reporting.py:99`.
- **Local machine:** el papel de las IPs que pertenecen a la propia máquina inventariada.
- **Scan:** el descubrimiento de red y el escaneo de puertos (opción `--scan`).
  `scan.py`.
- **Informe resumido / detallado / completo / de infraestructura:** las cuatro vistas
  legibles de una recogida (`-os`, `-od`, `-of`, `-oi`). `reporting.py`.
- **Badfiles:** la lista de ficheros y directorios con permisos peligrosos.
  `gathering1.py:588`.
- **Hueco (dato no recogido):** un dato que aridi no ha podido obtener, junto con el
  motivo. Es un término nuevo [decidido].
- **Cambio significativo:** una diferencia entre dos fotografías que el criterio de
  alertas considera relevante, con una gravedad. Es un término nuevo [decidido].
- **Componente central:** la parte que lanza las recogidas remotas, guarda el inventario
  y su histórico, compara las fotografías y alerta. Es un término nuevo [decidido].
- **Modo local:** una ejecución manual en una sola máquina, sin componente central.
- **Red autorizada:** una red que el administrador permite explorar expresamente con el
  scan [decidido].

---

## De dónde sale este documento

Esta idea se ha reconstruido el 2026-10-15 a partir de dos fuentes:

- **El código existente**, estudiado en [`ESTUDIO.md`](ESTUDIO.md). De ahí sale todo lo
  marcado como **[observado]**.
- **Una conversación con el usuario**, donde se decidió lo marcado como **[decidido]**:
  el usuario principal y los secundarios, el núcleo de inventario, el scan opcional y
  acotado, las plataformas, la regla de no exigir ni dejar nada, el criterio de alertas,
  la programación, la interfaz web con avisos externos, la conservación del modo local,
  la naturaleza de solo lectura, el modelo de acceso y el criterio de éxito.

**Son interpretaciones**, y están marcadas como tales en el texto: el tamaño orientativo
del parque, la comparación con otras herramientas, la alerta por máquinas que dejan de
responder, el trato de los resultados como datos sensibles, y los no objetivos sobre
monitorización en tiempo real, análisis de registros y cumplimiento normativo.

**Quedan pendientes**, porque no cambian la idea:
- el tamaño real del parque;
- cuánto tiempo se guarda el histórico;
- los canales concretos de aviso;
- la lista exacta de reglas de alerta de serie.

**Criterio de éxito** [decidido]: el equipo deja de mantener su inventario a mano y
confía en aridi como fuente de verdad. Todas las máquinas del parque se inventarían con
regularidad, cada máquina declara claramente qué no se ha podido ver, y ningún cambio
importante pasa sin alerta.
