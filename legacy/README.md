# aridi (2019, legacy)

This directory holds the original aridi, as written in March–April 2019, **unmodified**.
It is **obsolete** and is kept only while the rewrite reaches feature parity; then it will
be deleted (see phase 4 of [`../TODO.md`](../TODO.md) and
[`../docs/CAMBIO.md`](../docs/CAMBIO.md)).

Run it **from inside this directory**, because `services.csv` and all output files use
the current directory:

```sh
cd legacy
sudo python3 aridi.py -h
```

Its measured status on current distributions, and its known bugs, are described in
[`../docs/MVP.md`](../docs/MVP.md). Do not run it on a real machine: use a disposable
container without network.

The regression baseline that guarantees it keeps behaving the same during the rewrite
is `../tests/legacy/baseline.sh`.
