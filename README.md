# prom-liver

Auth filter for prometheus:

- /api/v1/query
- /api/v1/query_range
- /api/v1/series
- /federate

## USAGE
You can build it or use docker image
```
$ ./prom-liver -h
usage: prom-liver [<flags>]

Auth-filter-reverse-proxy-server for Prometheus

Flags:
  -h, --help                  Show context-sensitive help (also try --help-long and --help-man).
  -l, --loglevel="info"       Log level: debug, info, warning, error
  -c, --config="config.yaml"  Configuration file
```
also please look at example/config.yaml

You can reload config trough SIGHUP like:
```
$ skill -s SIGHUP prom-liver
```

#### laoleesch/prom-liver:latest
```
docker run -d -p 8080:8080 -v /<PATH>/prom-liver-config:/prom-liver laoleesch/prom-liver:latest
```

## TODO:

- [ ] /healthz
- [ ] vault integration (?)
- [ ] init config relaoding throug HTTP request like prometheus
