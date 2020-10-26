# prom-liver

![Travis (.org)](https://img.shields.io/travis/laoleesch/prom-liver?style=flat-square) ![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/laoleesch/prom-liver?style=flat-square)

Auth ACL filter for PromQL (Prometheus, VictoriaMetrics):

Prometheus API:

- /api/v1/query
- /api/v1/query_range
- /api/v1/series
- /federate

VictoriaMetrics PromQL extended API:

- /api/v1/labels
- /api/v1/label/{label}/values

Basic / Bearer token auth. Inject labels, check labels or union inject-subqueries. YAML config.

## USAGE

You can build it or use docker image laoleesch/prom-liver:latest

```bash
docker run -d -p 8080:8080 -v /<PATH>/prom-liver-config:/prom-liver laoleesch/prom-liver:latest
```

```bash
$ ./prom-liver -h
usage: prom-liver [<flags>]

Flags:
  -h, --help                  Show context-sensitive help (also try --help-long and --help-man).
  -c, --config="config.yaml"  Configuration file
  -l, --loglevel=info         Log filtering level
  -b, --bind=":8080"          Address to listen on.
```

Please look at [config.yaml](https://github.com/laoleesch/prom-liver/blob/master/configs/config.yaml) example

Supports clients configuration reload at runtime through SIGHUP:

```bash
skill -SIGHUP prom-liver
```

or PUT/POST request:

```bash
curl -X POST http://localhost:8888/-/config/reload
```

## TODO

- [ ] /metrics
- [ ] tests =))
- [ ] more tls options for backend
- [ ] refactoring
- [ ] more tests
- [ ] not-so-shitty-code-refactoring
- [ ] tests
- [ ] htpasswd?
- [ ] oauth?
- [ ] deduplication for subqueries?
