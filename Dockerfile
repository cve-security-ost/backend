FROM golang:1.25.1-alpine AS builder

WORKDIR /app

COPY . .

RUN go mod download


RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

FROM scratch

COPY --from=builder /app/server /server

EXPOSE 8000

ENTRYPOINT ["/server"]
