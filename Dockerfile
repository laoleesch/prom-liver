FROM golang AS build-env
ENV CGO_ENABLED=0
ADD . /src
RUN cd /src && \
    go get -d -v ./... && \
    go build -o prom-liver && \
    chmod a+x prom-liver

FROM golang:alpine
WORKDIR /app
COPY --from=build-env /src/prom-liver /app/
EXPOSE 8080/tcp
ENTRYPOINT [ "/app/prom-liver" ]