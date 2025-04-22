FROM golang:1.23.8-alpine3.20 AS build

WORKDIR /usr/local/go/src

COPY ./app/ /usr/local/go/src

RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -mod=readonly -o login_service cmd/main.go

FROM scratch
COPY --from=build /usr/local/go/src/login_service /bin/login_service
ENTRYPOINT ["/bin/login_service"]
