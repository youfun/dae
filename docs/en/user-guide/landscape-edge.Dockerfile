# PoC image. The adapter ELF is built in the image; it is not part of the
# default dae eBPF objects.
FROM golang:1.26-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends llvm-15 clang-15 make \
    && rm -rf /var/lib/apt/lists/*
ENV CLANG=clang-15
WORKDIR /build
ARG VERSION=landscape-edge-poc
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The image build context must include the initialized control/kern/headers submodule.
RUN test -f control/kern/headers/errno-base.h \
    && make OUTPUT=dae VERSION="${VERSION}" GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0 \
    && CLANG=clang-15 scripts/build-landscape-adapter.sh /tmp/landscape_edge.o

FROM alpine
RUN apk add --no-cache iproute2 iputils ca-certificates
COPY --from=builder /build/dae /usr/local/bin/dae
COPY --from=builder /tmp/landscape_edge.o /usr/local/lib/dae/landscape_edge.o
COPY component/landscape/entrypoint.sh /usr/local/bin/landscape-edge-entrypoint
RUN chmod 0755 /usr/local/bin/landscape-edge-entrypoint
ENTRYPOINT ["/usr/local/bin/landscape-edge-entrypoint"]
