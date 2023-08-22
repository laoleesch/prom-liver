FROM golang:1.18 AS build-env
ENV CGO_ENABLED=0
ADD . /src
RUN cd /src && \
    go get -d -v ./... && \
    go build -o prom-liver cmd/prom-liver/main.go && \
    chmod a+x prom-liver

FROM golang:1.18-alpine
WORKDIR /prom-liver
COPY --from=build-env /src/prom-liver /usr/bin/
EXPOSE 8080/tcp
ENTRYPOINT [ "/usr/bin/prom-liver" ]