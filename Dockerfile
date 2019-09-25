FROM golang AS build-env
ENV CGO_ENABLED=0
ADD . /src
RUN cd /src && \
    go get -d -v ./... && \
    go build -o prom-liver && \
    chmod a+x prom-liver

FROM golang:alpine
WORKDIR /prom-liver
COPY --from=build-env /src/prom-liver /usr/bin/
EXPOSE 8080/tcp
ENTRYPOINT [ "/usr/bin/prom-liver" ]