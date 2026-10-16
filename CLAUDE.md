# CLAUDE.md: cómo se trabaja en aridi

Este es el acuerdo de trabajo para agentes de IA y personas que contribuyan a este
repositorio. Se lee como instrucciones. Si algo de aquí choca con lo que pide el usuario,
pregunta antes de actuar.

## Qué es

aridi es una herramienta de inventario de máquinas Linux. Tiene dos piezas:

- **El colector, que ya existe:**
  - un script POSIX `sh` sin dependencias que recoge en bruto, en la máquina, 17 áreas;
  - un núcleo en Python 3.12, solo con la librería estándar, que interpreta ese paquete
    en cualquier equipo y produce una fotografía JSON y un informe de texto.

  Es el **modo local en dos pasos**.
- **El componente central, que existe desde la fase 5:** Django 5.2 con SQLite en
  `docker compose`. Recoge por SSH (a demanda o programado), importa recogidas locales,
  guarda el histórico y los huecos, y busca en el parque, con una web de dos roles.
  Desde la fase 6 compara fotografías, alerta con 9 reglas de serie ajustables, avisa por
  correo o webhook y dibuja el mapa de relaciones. **Sigue previsto y sin existir** el
  descubrimiento y escaneo desde el central (fase 7).

**Su estado real está medido en `docs/MVP.md`:** léelo antes de dar nada por
funcionando. La reescritura se decidió en `docs/CAMBIO.md` y se ejecuta por fases según
`TODO.md`. **Sigue `TODO.md` en orden y marca las tareas al terminarlas.**

El aridi de 2019 (un único programa en Python) se retiró en la fase 4, al alcanzar la
paridad (`tests/parity.md`). Su código queda en la historia de git: en la raíz hasta el
commit `4ab279e`, y en `legacy/` desde `6f749d6` hasta su retirada. Las referencias del
código del tipo «2019 gathering2.py:35» se refieren a esos ficheros (las líneas no
cambiaron al moverlos).

## Arquitectura en breve

Versión completa: `docs/ARCHITECTURE.md`. Contrato de datos: `docs/FORMATO.md`.

| Ruta | Qué es |
|---|---|
| `collector/aridi-collect.sh` | Script POSIX de recogida en bruto: 17 áreas, con filtrado en origen de lo sensible |
| `src/aridi/` | Núcleo, solo con la librería estándar: `bundle.py` (lector del paquete), `model.py` (fotografía, estados, huecos y papeles de relación), `interpret.py` (registro de áreas), `parsers/` (un analizador por área), `relations.py`, `views/text.py` y `cli.py` (`aridi validate\|interpret\|report`) |
| `src/aridi/data/services.csv` | Nombres de puertos (`nombre\|puerto\|descripción`), copiado sin cambios de 2019 |
| `src/aridi_central/` | Central Django: `settings.py` (todo por variables `ARIDI_*`), `inventory/` (máquinas, fotografías, huecos, índices, importación), `collection/` (`ssh.py`, cola `Job`, `Schedule`, `worker.py`), `changes/` (`diff.py`, `rules.py`, `evaluate.py`, `channels.py`: comparación, reglas, alertas y avisos), `web/` (vistas, roles, mapa SVG y plantillas), `discovery/` vacía |
| `Dockerfile`, `compose.yaml` | Imagen del central (base fijada por *digest*) y despliegue: `web` (gunicorn), `worker` y el volumen `aridi-data` |
| `tests/` | `run.sh` (punto de entrada), pruebas `unittest`, `collector/` (script en todas las imágenes), `corpus/` (muestras), `lima/` (VMs), `parity/` y `parity.md` (regresión frente a 2019) |
| `requirements/` | `central.in` y `central.txt`: dependencias del central, fijadas con hashes |
| `docs/` | Estudio, idea, alcance medido, futuro, arquitectura, cambio y formato, en español |
| `pyproject.toml` | Distribución `aridi`: núcleo sin dependencias; extra `central` |

## Estándares de código

- **Formato:** 4 espacios, sin tabuladores; líneas de hasta unos 100 caracteres.
- **Linter y formateador:** ninguno configurado. No reformatees ficheros enteros.
- **Nombres:** PEP 8. Funciones y variables en `snake_case` (`build_parser`), clases en
  `CamelCase` y funciones internas con prefijo `_`.
- **Python:** 3.12 o superior (f-strings, `dataclasses` y `pathlib` permitidos).
  Expresiones regulares siempre en *raw string*.
- **`sh`:** solo POSIX, sin *bashisms*. Tiene que funcionar con `dash`, `bash` (incluido
  el 4.1 de CentOS 6) y busybox `ash`.
- **Documentación:** docstring breve por módulo; comentarios y mensajes en inglés.
- **Errores:** nunca se omiten en silencio. Lo que no se pueda recoger o interpretar se
  declara como hueco con estado y motivo (`docs/FORMATO.md`). Nada de `except:` desnudos.
- **Logging:** el módulo `logging` hacia stderr. Nada de `print` para diagnóstico.
- **Un área nueva, o un cambio en una, sigue el patrón de la fase 3 de `TODO.md`:**
  - **(a)** secciones en el script, con varias fuentes ordenadas (primero `/proc`,
    `/sys` o `/etc`; si no, binarios);
  - **(b)** analizador en `src/aridi/parsers/<área>.py`;
  - **(c)** vista en `src/aridi/views/text.py`;
  - **(d)** recaptura del corpus y pruebas contrastadas con `facts.txt`;
  - **(e)** regresión: ningún valor de `tests/parity/` empeora.

## Pruebas

- **El único punto de entrada es `tests/run.sh`:** `tests/run.sh all` o una parte
  concreta (`unit`, `collector`, `central`, `golden`). Todo corre en Docker, así que el
  Python del anfitrión (3.9 en macOS) no se usa nunca.
- **`unit`:** `python -m unittest discover -s tests -t .` en `python:3.12-slim`, con el
  repositorio montado en solo lectura. Las pruebas van en `tests/`, en ficheros
  `test_*.py`, con la librería estándar `unittest` (sin pytest).
- **`collector`:** `tests/collector/test_script.sh` ejecuta el script en las 10 imágenes
  del corpus, con cada shell disponible, como root y como uid 65534. Comprueba que
  termina con 0, que no deja rastro (`find -newer`) y que los estados (`denied`,
  `timeout`…) son los esperados; después valida los paquetes con el lector del núcleo.
- **`central`:** `tests/central/run.sh` construye la imagen de pruebas
  (`requirements/central.txt` con hashes) y ejecuta `check --deploy`, `manage.py test`,
  la recogida SSH real contra un contenedor desechable (`tests/central/ssh-target.sh`) y
  la prueba de humo de `docker compose` (`tests/central/smoke.sh`). Las pruebas del central
  van en `src/aridi_central/*/tests/` y usan el corpus.
- **Aceptación del central:** `tests/lima/central-acceptance.sh [inventory|alerts]`,
  contra una VM de Lima desechable (`alerts`, la de la fase 6, con un webhook de prueba).
- **`golden`:** `tests/run.sh golden` regenera el informe de referencia de
  `tests/test_core/test_text.py`. Hay que hacerlo tras recapturar el corpus o cambiar el
  informe, **revisando el diff**.
- **Corpus:** `tests/corpus/capture.sh all` (contenedores) y `tests/lima/capture-vm.sh
  all` (VMs) recapturan las muestras. Hay que hacerlo **cada vez que cambia el script**.
- **Paridad:** `tests/test_parity.py` compara con lo que el aridi de 2019 vio en las
  mismas máquinas (`tests/parity/`, datos congelados). `tests/parity.md` asocia cada
  funcionalidad de 2019 a sus pruebas, y `tests/test_parity_doc.py` comprueba que esas
  pruebas existen.
- **Toda tarea que cambie comportamiento incluye sus pruebas** (`TODO.md`). No digas que
  algo funciona sin haberlo visto pasar en `tests/run.sh`.

## Compilar y ejecutar

- No hay nada que compilar.
- **Núcleo:** `PYTHONPATH=src python3.12 -m aridi.cli validate|interpret|report <paquete>`
  o, tras `pip install .`, `aridi …`. `pip install .` descarga `setuptools` de PyPI para
  construir; la forma con `PYTHONPATH` no descarga nada.
- **Modo local:** `sh collector/aridi-collect.sh > m.aridi` (solo en máquinas
  desechables, regla 2) y `aridi report m.aridi`.
- **Dependencias del central:** `pip install --require-hashes -r requirements/central.txt`.
  Para regenerarlo, sigue el comando de `requirements/central.in`.
- **Central en desarrollo:** `ARIDI_DEBUG=1 ARIDI_DB_PATH=/tmp/aridi.db python
  src/aridi_central/manage.py migrate|runserver|aridi_worker`, dentro de la imagen de
  pruebas. **Despliegue:** `docker compose up -d --build` (variables en `README.md`).

## Flujo de git

- **Lo que muestra el historial hasta 2019:** 45 commits de una sola persona, todos
  directos a `master`, sin ramas, etiquetas ni PR, con mensajes cortos en inglés.
- **A partir de ahora:**
  - no hagas commits ni push si no te lo piden;
  - cuando te lo pidan, escribe mensajes en inglés, breves y **descriptivos** (qué cambia
    y dónde), no "Minor fixes";
  - un cambio lógico por commit;
  - usa `git mv` para mover ficheros y conservar la historia.
- **Hay `.gitignore`.** Aun así, antes de hacer `git add` comprueba que no entran
  informes, paquetes `*.aridi` fuera de `tests/corpus/` y `tests/parity/`, ni bases de
  datos.

## Reglas de este proyecto fáciles de incumplir

1. **No añadas dependencias de terceros al núcleo ni al script, ni «solo para probar».**
   *Por qué:* el principio fundador es evitar ataques de cadena de suministro. El central
   solo puede usar lo que hay en `requirements/central.txt` (Django, asgiref, sqlparse,
   gunicorn, packaging). Cualquier paquete más necesita la decisión del usuario y su hash.
2. **No ejecutes el script en tu máquina ni en ninguna máquina real. Usa contenedores
   desechables con `--network none` o las VMs de `tests/lima/`.**
   *Por qué:* lee datos sensibles de todo el sistema (cuentas, procesos, registros,
   cortafuegos). Solo se ejecuta donde lo que lea no importe.
3. **aridi es de solo lectura: ningún cambio puede modificar el sistema inspeccionado.**
   *Por qué:* es un principio del producto (`docs/IDEA.md`), y es lo que permite darle
   root en todo un parque. Cuidado con las herramientas que escriben al leer (`rpm` como
   root) o que cargan módulos del kernel (`nft`, `iptables`): `docs/FORMATO.md` explica
   cómo se evitan, y `tests/run.sh collector` lo vigila con `find -newer`.
4. **El script nunca escribe en disco.**
   *Por qué:* todo sale por stdout, sin ficheros temporales. Un fichero temporal en una
   máquina ajena es un rastro y un riesgo (enlaces simbólicos, permisos).
5. **El script filtra lo sensible en origen.**
   *Por qué:* lo que sale de la máquina se copia, se guarda y se transmite. Nunca salen
   hashes de contraseñas (solo su algoritmo), claves privadas, variables de entorno de
   procesos ni el texto de las líneas donde aparecen IPs; las líneas de órdenes salen
   recortadas y con los valores con aspecto de secreto ocultos. Lista completa en
   `docs/FORMATO.md`, y `tests/test_corpus_hygiene.py` lo comprueba en todo el corpus.
6. **No añadas llamadas a `input()` ni preguntas interactivas.**
   *Por qué:* el producto es desatendido. En 2019, sin terminal se perdían apartados
   enteros (`tests/parity.md`, n.º 21).
7. **El formato es un contrato versionado.**
   *Por qué:* el paquete en bruto y la fotografía (`docs/FORMATO.md`) los leerán también el
   central y las versiones futuras del núcleo. Un cambio incompatible exige subir la
   versión y seguir la política de versiones de ese documento.
8. **Los papeles de relación son códigos enumerados (`Role` en `model.py`), nunca
   frases.**
   *Por qué:* en 2019, el escaneo clasificaba las IPs por el prefijo de un texto libre, y
   cambiar una frase rompía esa clasificación.
9. **El núcleo (`src/aridi`) nunca importa Django, `aridi_central` ni nada ajeno a la
   librería estándar.**
   *Por qué:* es la frontera de `docs/CAMBIO.md`. El central usa el núcleo como librería,
   nunca al revés, y `tests/test_core_isolation.py` lo vigila.
10. **No supongas que los datos del sistema son completos o tienen un formato fijo.**
    *Por qué:* en 2019, un uid sin usuario, un miembro de grupo sin usuario, una interfaz
    `eth0@if5`, menos de 10 procesos o un `lsblk` moderno anulaban apartados enteros
    (`tests/parity.md`, n.º 12-17). Cada caso así tiene su prueba.
11. **Lo que no se pueda recoger se declara; no se omite.**
    *Por qué:* es un principio decidido (`docs/IDEA.md`). Un apartado que desaparece en
    silencio hace que el informe mienta por omisión.
12. **Un dato incorrecto es peor que uno que falta.**
    *Por qué:* es el criterio de `docs/MVP.md`. Si no puedes interpretar algo con
    seguridad (por ejemplo, un tipo de hash desconocido), dilo como «desconocido», no lo
    encajes en otra categoría.
13. **El corpus es la única forma de verificar.**
    *Por qué:* nada se da por bueno leyendo código. Un dato se contrasta con `facts.txt`
    (lo que dicen las herramientas del sistema en la misma muestra) o con `tests/parity/`.
    Si un caso no está en el corpus, se añade al escenario (`tests/corpus/scenario.sh`) o
    se prueba con datos sintéticos, y se dice cuál de las dos cosas es.
14. **En los documentos de `docs/`, separa lo observado, lo deducido y la suposición.**
    *Por qué:* es la convención de todos ellos. Nunca marques algo como «entregado» sin
    haberlo visto funcionar.
15. **No escribas el futuro en el presente.**
    *Por qué:* `docs/IDEA.md`, `docs/FUTURE.md` y `docs/CAMBIO.md` describen lo previsto
    (cambios y alertas, descubrimiento y escaneo desde el central…). Hasta que una fase de `TODO.md` lo entregue, ni el
    código ni la documentación deben dar a entender que existe.
16. **El corpus no puede llevar datos del anfitrión.**
    *Por qué:* en la fase 3, las VMs de Lima montaban el directorio personal del
    anfitrión y creaban un usuario con su nombre. Las capturas usan `--mount-none`,
    volúmenes de Docker en vez de directorios del anfitrión y `docker cp`, y
    `tests/test_corpus_hygiene.py` lo comprueba.
17. **El central nunca guarda credenciales.**
    *Por qué:* su base de datos describe todo el parque; si además tuviera claves, robarla
    daría acceso a todas las máquinas. SSH usa el `ssh-agent` (socket montado) y
    `known_hosts`, y una máquina solo guarda destino, puerto, salto y modo de privilegio.
    Lo mismo con los avisos: la contraseña SMTP y las URL de los webhooks van en el
    entorno (`alerts.env`), y un canal solo guarda el nombre del webhook.
18. **`ssh` siempre con lista de argumentos, `BatchMode=yes`,
    `StrictHostKeyChecking=yes` y `--` antes del destino, y nunca con `shell=True`.**
    *Por qué:* los campos de una máquina los escribe una persona en la web; un destino
    como `-oProxyCommand=…` ejecutaría órdenes en el central. Los validadores de
    `inventory/validators.py` y `collection/ssh.py` lo impiden, y el comando remoto es fijo.
19. **Nada de `|safe`, `mark_safe` ni `{% autoescape off %}` sobre datos de máquinas.**
    *Por qué:* *banners*, nombres de procesos y líneas de registro los controla quien
    controle la máquina inventariada (`tests/corpus/scenario.sh` mete un `<script>`). La
    política CSP (`web/middleware.py`) no permite scripts, pero el escape es la defensa.
20. **La regla de `sudo` de las máquinas solo permite el script instalado.**
    *Por qué:* es la decisión de `TODO.md` 5.0. Nunca propongas `NOPASSWD: /bin/sh` ni
    `ALL`: equivale a root en todo el parque para quien tenga la clave de aridi.
21. **Una regla de alerta nueva no lee áreas volátiles y trae su par de pruebas.**
    *Por qué:* procesos, carga, conexiones y vecinos cambian en cada recogida y
    enterrarían las alertas reales. Cada regla de `changes/rules.py` tiene en
    `test_rules.py` un par de fotografías que la dispara y otro que no, y no salta entre
    dos fotografías iguales.
