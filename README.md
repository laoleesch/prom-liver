# prom-liver

Auth filter for prometheus federate

TODO:

- [x] go-kit logger
- [x] read bearer token, basic base64 from file
- [ ] /healthz
- [ ] vault integration
- [ ] read basic from htpasswd
- [x] several bearer tokens for one client (token-client like many-one)
- [x] SIGHUP to reload config
- [ ] HTTP POST to reload config (?)
- [x] read clients configs from files
