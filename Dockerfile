FROM golang AS build-env
ENV CGO_ENABLED=0
ADD . /src
RUN cd /src && \
    go get -d -v ./... && \
    go build -o goapp && \
    chmod a+x goapp

FROM golang:alpine
WORKDIR /app
COPY --from=build-env /src/goapp /app/
EXPOSE 8080/tcp
ENTRYPOINT [ "/app/goapp" ]