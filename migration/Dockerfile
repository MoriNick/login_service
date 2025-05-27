FROM golang:1.23.8-alpine3.20 AS builder

WORKDIR /migration

COPY ./go.* ./
RUN go mod download

COPY ./ ./
RUN GOOS=linux GOARCH=amd64 go build -o migrate ./cmd

FROM scratch
COPY --from=builder /migration/migrate /bin/migrate
COPY --from=builder /migration/migrations /migrations

ENTRYPOINT ["bin/migrate"]
