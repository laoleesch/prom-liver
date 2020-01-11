FROM golang AS build-env
ENV CGO_ENABLED=0
ADD . /src
RUN cd /src && \
    go get -d -v ./... && \
    go build -o prom-liver cmd/prom-liver/main.go && \
    chmod a+x prom-liver

FROM golang:alpine
WORKDIR /prom-liver
COPY --from=build-env /src/prom-liver /usr/bin/
EXPOSE 8080/tcp 8888/tcp
ENTRYPOINT [ "/usr/bin/prom-liver" ]