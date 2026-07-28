FROM golang:1.23-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-arm64} go build -o /out/notification-api ./main.go

FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
WORKDIR /app
COPY --from=builder /out/notification-api /app/notification-api
EXPOSE 9002
ENTRYPOINT ["/app/notification-api"]
