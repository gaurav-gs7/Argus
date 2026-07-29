FROM golang:1.26.5-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-arm64} go build -o /out/payments-api ./main.go

FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
WORKDIR /app
COPY --from=builder /out/payments-api /app/payments-api
EXPOSE 9001
ENTRYPOINT ["/app/payments-api"]
