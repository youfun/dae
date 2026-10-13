#!/bin/sh
# Build the Landscape edge adapter object. The ELF is loaded at runtime by
# `dae landscape-edge`; it is not committed and not part of the default dae
# eBPF generation, which still comes from control/kern/tproxy.c.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
src="$root/component/landscape/kern/adapter.c"
out="${1:-$root/component/landscape/landscape_edge.o}"
clang="${CLANG:-clang}"

"$clang" -g -O2 -Wall -Werror -target bpf -c "$src" -o "$out"
echo "built $out"
