FROM golang:1.23.8-alpine3.20 AS build

WORKDIR /app

COPY ./go.* ./
RUN go mod download

COPY ./ ./
RUN GOOS=linux GOARCH=amd64 go build -o login_service ./cmd

FROM scratch
COPY --from=build /app/login_service /bin/login_service

ENTRYPOINT ["/bin/login_service"]
