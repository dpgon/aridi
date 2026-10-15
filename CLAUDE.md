# CLAUDE.md: cómo se trabaja en aridi

Este es el acuerdo de trabajo para agentes de IA y personas que contribuyan a este
repositorio. Se lee como instrucciones. Si algo de aquí choca con lo que pide el usuario,
pregunta antes de actuar.

## Qué es

aridi es una herramienta de inventario de máquinas Linux que **se está reescribiendo**.

- **El aridi de 2019** (consola en Python 3, estado *beta*) está en `legacy/`, sin
  modificar. Perfila la máquina en la que se ejecuta y produce un informe de texto:
  hardware, distribución, paquetes, discos, usuarios, servicios, red, cortafuegos,
  procesos, sesiones, un mapa de las IPs con las que se relaciona y, de forma opcional,
  un barrido ARP y un escaneo de puertos. **Su estado real está medido en
  `docs/MVP.md`: léelo antes de dar nada por funcionando.**
- **La reescritura** está decidida en `docs/CAMBIO.md` y se ejecuta por fases según
  `TODO.md`. Tiene dos piezas:
  - un colector sin dependencias: un script POSIX `sh` que recoge en bruto, más un núcleo
    en Python 3.12 que lo interpreta;
  - un componente central en Django 5.2 con SQLite, ejecución por SSH, histórico y
    alertas.

  **Sigue `TODO.md` en orden y marca las tareas al terminarlas.**

## Arquitectura en breve

Versión completa: `docs/ARCHITECTURE.md` (describe todavía el sistema de 2019). La de
destino está en `docs/CAMBIO.md`.

| Ruta | Qué es |
|---|---|
| `legacy/` | El aridi de 2019, intacto. Se borra al alcanzar la paridad (fase 4). Ver `legacy/README.md`. |
| `collector/aridi-collect.sh` | Script POSIX de recogida en bruto (vacío hasta la fase 2) |
| `src/aridi/` | Núcleo: solo librería estándar; interpreta paquetes en bruto (CLI `aridi`) |
| `src/aridi_central/` | Central Django (desde la fase 5; todavía no existe) |
| `tests/` | `run.sh` (punto de entrada), pruebas `unittest`, `legacy/` (línea base de 2019) y, más adelante, `corpus/` |
| `requirements/` | `central.in` y `central.txt`: dependencias del central, fijadas con hashes |
| `docs/` | Estudio, idea, alcance medido, futuro, arquitectura y cambio (en español) |
| `pyproject.toml` | Distribución `aridi`: núcleo sin dependencias; extra `central` |

**El aridi de 2019** (`legacy/`):

| Fichero | Qué hace |
|---|---|
| `aridi.py` | Arranque: CLI (`argparse`), precheck, invoca las fases y escribe las salidas |
| `gathering0.py` | `Precheck`: uid, ficheros legibles, búsqueda de binarios, DNS, carga de `services.csv` |
| `gathering1.py` | Fase general (`-g`): hardware, SO, paquetes, discos, permisos |
| `gathering2.py` | Fase específica (`-s`): identidad, usuarios, servicios, red, iptables |
| `gathering3.py` | Fase volátil (`-v`): procesos, RAM, CPU, disco, sesiones, sockets |
| `gathering4.py` | Fase de carving (`-c`): IPs y FQDN en `/etc` y `/var/log` |
| `scan.py` | `--scan`: ARP con sockets crudos y TCP *connect* con hilos |
| `graph.py` | `--graph`: grafo con `graphviz` (opcional) |
| `reporting.py` | `Reporting`: almacén del informe, mapa de infraestructura, log y vistas |
| `utils.py` | Cabeceras de texto, IPs en hexadecimal, barra de progreso |
| `services.csv` | `nombre\|puerto\|descripción`: nombres de puertos y lista de escaneo |

Funcionamiento interno de `legacy/`:

- **Estado compartido** en `report` (`Reporting`), `precheck` (`Precheck`) y varios
  globales de módulo.
- **Fases:** cada una expone `get*info(report, precheck)`.
- **Funciones privadas:** las `_get*()` devuelven `(summ, detail)` como texto ya
  formateado, que se añade con `report.summarized(kind, …)` y `report.detailed(kind, …)`
  (`kind`: 0 ejecución, 1 general, 2 específica, 3 volátil, 4 carving, 5 escaneo).

## Estándares de código

**En `legacy/`** no se escribe código nuevo: solo se toca si una tarea de `TODO.md` lo
pide. Si hay que tocarlo, se respeta su estilo:

- nombres en minúsculas sin separar palabras (`getgeneralinfo`), funciones internas con
  `_`;
- `str.format()`;
- **compatible con Python 3.6.**

**En el código nuevo** (`src/`, `collector/`, `tests/`):

- **Formato:** 4 espacios, sin tabuladores; líneas de hasta unos 100 caracteres, como en
  el código original.
- **Linter y formateador:** ninguno configurado. No reformatees ficheros enteros.
- **Nombres:** PEP 8. Funciones y variables en `snake_case` (`build_parser`,
  `imported_modules`), clases en `CamelCase` y funciones internas con prefijo `_`.
- **Python:** 3.12 o superior en `src/` (f-strings, `dataclasses` y `pathlib` permitidos).
  Expresiones regulares siempre en *raw string*.
- **`sh`:** solo POSIX, sin *bashisms*. Tiene que funcionar con `dash`, `bash`, busybox
  `ash` y el `sh` de CentOS 6.
- **Documentación:** docstring breve por módulo; comentarios y mensajes en inglés.
- **Errores:** nunca se omiten en silencio. Lo que no se pueda recoger o interpretar se
  declara como hueco con estado y motivo (`docs/CAMBIO.md`). Nada de `except:` desnudos.
- **Logging:** el módulo `logging` hacia stderr. Nada de `print` para diagnóstico.

## Pruebas

- **El único punto de entrada es `tests/run.sh`:** `tests/run.sh all` o una parte
  concreta (`unit`, `collector`, `central`, `legacy`). Todo corre en Docker, así que el
  Python del anfitrión (3.9 en macOS) no se usa nunca.
- **`unit`:** `python -m unittest discover -s tests -t .` en `python:3.12-slim`, con el
  repositorio montado en solo lectura. Las pruebas van en `tests/`, en ficheros
  `test_*.py`, con la librería estándar `unittest` (sin pytest).
- **`legacy`:** `tests/legacy/baseline.sh compare` ejecuta el aridi de 2019 en Debian 12 y
  CentOS 7, sin red, y comprueba que sus errores, sus secciones y su código de salida no
  cambian respecto a `tests/legacy/baseline/`. Si una tarea toca `legacy/` a propósito,
  vuelve a grabar la línea base con `record` **y explícalo**.
- **`tests/test_core_isolation.py`** falla si `src/aridi` importa algo que no sea de la
  librería estándar.
- **Toda tarea que cambie comportamiento incluye sus pruebas** (`TODO.md`). No digas que
  algo funciona sin haberlo visto pasar en `tests/run.sh`.

## Compilar y ejecutar

- No hay nada que compilar.
- **Núcleo:** `PYTHONPATH=src python3.12 -m aridi.cli …` o, tras `pip install .`,
  `aridi …`. Todavía no hace nada (fase 2).
- **Dependencias del central:** `pip install --require-hashes -r requirements/central.txt`.
  Para regenerarlo, sigue el comando de `requirements/central.in`.
- **aridi de 2019:** `cd legacy && sudo python3 aridi.py [-a|-g|-s|-v|-c] [--scan]
  [--graph] [-V N] [-os|-od|-of|-oi] [FILE]`, **solo en contenedores** (ver reglas).

## Flujo de git

- **Lo que muestra el historial:** 45 commits de una sola persona, todos directos a
  `master`, sin ramas, etiquetas ni PR. Mensajes cortos en inglés ("Minor fixes", "zypper
  support", "First beta").
- **A partir de ahora:**
  - no hagas commits ni push si no te lo piden;
  - cuando te lo pidan, escribe mensajes en inglés, breves y **descriptivos** (qué cambia
    y dónde), no "Minor fixes";
  - un cambio lógico por commit;
  - usa `git mv` para mover ficheros y conservar la historia.
- **Hay `.gitignore`.** Aun así, antes de hacer `git add` comprueba que no entran
  informes, paquetes `*.aridi` fuera de `tests/corpus/` ni bases de datos.

## Reglas de este proyecto fáciles de incumplir

1. **No añadas dependencias de terceros al núcleo ni al script, ni «solo para probar».**
   *Por qué:* el principio fundador es evitar ataques de cadena de suministro. El central
   solo puede usar lo que hay en `requirements/central.txt` (Django, asgiref, sqlparse,
   gunicorn, packaging). Cualquier paquete más necesita la decisión del usuario y su hash.
2. **No ejecutes ningún aridi en tu máquina ni en ninguna máquina real. Usa contenedores
   desechables con `--network none`.**
   *Por qué:* el de 2019 lee `/etc/shadow` y todo `/etc` y `/var/log`, escribe ficheros
   con nombre fijo siguiendo enlaces simbólicos, recorre todo `/` y, con `--scan`, lanza
   miles de conexiones. El script nuevo también lee datos sensibles.
3. **Nunca lances `--scan` con red real ni contra IPs que no sean de la propia máquina de
   prueba.**
   *Por qué:* las categorías `a` y `x` incluyen IPs de terceros sacadas de los registros, y
   escanearlas puede ser ilegal (`docs/ESTUDIO.md` §8).
4. **aridi es de solo lectura: ningún cambio puede modificar el sistema inspeccionado.**
   *Por qué:* es un principio del producto (`docs/IDEA.md`), y es lo que permite darle
   root en todo un parque. El script nuevo, además, no escribe nada en disco.
5. **No añadas llamadas a `input()` ni preguntas interactivas.**
   *Por qué:* sin terminal provocan `EOFError` y se pierden apartados (`docs/MVP.md`
   n.º 21). El producto nuevo es desatendido.
6. **`legacy/` debe seguir siendo compatible con Python 3.6.**
   *Por qué:* CentOS 7 (Python 3.6.8) está en la línea base de regresión. Fuera de
   `legacy/`, el mínimo es Python 3.12.
7. **En `legacy/`, los textos que se pasan a `report.infrastructure(ip, texto)` son un
   contrato, no mensajes.**
   *Por qué:* `legacy/scan.py:155-169` clasifica las IPs por el prefijo de esos textos. En
   el código nuevo, los papeles de relación son **códigos enumerados**, nunca frases.
8. **En `legacy/`, si tocas `_getnetinfo`, `_getusers` o `_getdisks`, revisa también
   `gathering3.py` y `scan.py`.**
   *Por qué:* se importan desde fuera de su módulo y escriben en `report` como efecto
   secundario.
9. **En `legacy/`, comprueba el orden de los parámetros antes de llamar a una función
   privada.**
   *Por qué:* hay funciones `(report, precheck)` y funciones `(precheck, report)`. El
   intérprete no avisa del cruce.
10. **No supongas que los datos del sistema son completos o tienen un formato fijo.**
    *Por qué:* en 2019, un uid sin usuario, un miembro de grupo sin usuario, una interfaz
    `eth0@if5`, menos de 10 procesos o un `lsblk` moderno anulaban apartados enteros
    (`docs/MVP.md` n.º 12-17). Cada uno de esos casos tiene que tener su prueba en el
    código nuevo.
11. **Lo que no se pueda recoger se declara; no se omite.**
    *Por qué:* es un principio decidido (`docs/IDEA.md`). Un apartado que desaparece en
    silencio hace que el informe mienta por omisión.
12. **Un dato incorrecto es peor que uno que falta.**
    *Por qué:* es el criterio de `docs/MVP.md`. Si no puedes interpretar algo con
    seguridad (por ejemplo, un tipo de hash desconocido), dilo como «desconocido», no lo
    encajes en otra categoría.
13. **El aridi de 2019 se lanza desde `legacy/`.**
    *Por qué:* `services.csv` se carga como `./services.csv` (`legacy/aridi.py:101`). Desde
    otro directorio se desactiva el escaneo sin aviso visible.
14. **En los documentos de `docs/`, separa lo observado, lo deducido y la suposición.**
    *Por qué:* es la convención de todos ellos. Nunca marques algo como «entregado» sin
    haberlo visto funcionar.
15. **No escribas el futuro en el presente.**
    *Por qué:* `docs/IDEA.md`, `docs/FUTURE.md` y `docs/CAMBIO.md` describen lo previsto
    (SSH, componente central, alertas…). Hasta que una fase de `TODO.md` lo entregue, ni el
    código ni la documentación deben dar a entender que existe.
16. **El núcleo (`src/aridi`) nunca importa Django ni `aridi_central`.**
    *Por qué:* es la frontera de `docs/CAMBIO.md`. El central usa el núcleo como librería,
    nunca al revés, y `tests/test_core_isolation.py` lo vigila.
