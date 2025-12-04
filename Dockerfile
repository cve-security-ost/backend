FROM golang:1.21-alpine AS builder

WORKDIR /app

# Önce dependency dosyalarını kopyala
COPY go.mod go.sum ./

# Dependencies indir
RUN go mod download

# Sonra kaynak kodu kopyala
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

FROM scratch

COPY --from=builder /app/server /server

EXPOSE 8080

ENTRYPOINT ["/server"]
