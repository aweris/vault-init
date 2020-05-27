FROM golang:1.14-alpine AS builder

ENV GO111MODULE=on
ENV CGO_ENABLED=0

RUN apk add --no-cache git=2.24.3-r0      \
                       make=4.2.1-r2      \
                       upx=3.95-r2        \
                       binutils=2.33.1-r0

WORKDIR /src

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN make vault-init                 \
 && strip /src/build/vault-init     \
 && upx -q -9 /src/build/vault-init

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/build/vault-init /bin/vault-init

CMD ["/bin/vault-init"]
