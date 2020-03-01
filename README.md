# prom-liver

![Travis (.org)](https://img.shields.io/travis/laoleesch/prom-liver?style=flat-square) ![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/laoleesch/prom-liver?style=flat-square)

Auth ACL filter for PromQL (Prometheus, VictoriaMetrics):

Prometheus API:

- /api/v1/query
- /api/v1/query_range
- /api/v1/series
- /federate

VictoriaMetrics PromQL external API:

- /api/v1/labels
- /api/v1/label/{label}/values

Reverse-proxy. Basic / Bearer token auth. Matching labels. YAML config.

## USAGE

You can build it or use docker image laoleesch/prom-liver:latest

```bash
docker run -d -p 8080:8080 -v /<PATH>/prom-liver-config:/prom-liver laoleesch/prom-liver:latest
```

```bash
$ ./prom-liver -h
usage: prom-liver [<flags>]

ACL for PromQL

Flags:
  -h, --help                  Show context-sensitive help (also try --help-long and --help-man).
  -l, --loglevel="info"       Log level: debug, info, warning, error
  -c, --config="config.yaml"  Configuration file
```

Please look at [config.yaml](https://github.com/laoleesch/prom-liver/blob/master/configs/config.yaml) example

Supports configuration reload at runtime through SIGHUP:

```bash
skill -SIGHUP prom-liver
```

or PUT/POST request on a separate port:

```bash
curl -X POST http://localhost:8888/admin/config/reload
```

## TODO

- [ ] /liver/metrics
- [ ] ability to inject labels (with matches also)
- [ ] usage as auth middleware for nginx/traefik/etc
- [ ] vault integration (? maybe just an example on consul-template)
