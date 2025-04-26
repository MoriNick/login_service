FROM golang:1.23.8-alpine3.20 AS build

WORKDIR /app

COPY ./app/go.mod ./app/go.sum ./
RUN go mod download

COPY ./app/ ./
RUN GOOS=linux GOARCH=amd64 go build -o login_service ./cmd/main.go

FROM scratch
COPY --from=build /app/login_service /bin/login_service

EXPOSE 5000

ENTRYPOINT ["/bin/login_service"]
