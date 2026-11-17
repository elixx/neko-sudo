#!/bin/sh
# Build + push the gate image for amd64 AND arm64, so mixed-architecture
# Swarm clusters can schedule it anywhere (a single-arch push makes
# `docker service update --force` fail on the other arch with
# "no matching manifest for linux/arm64/v8").
#
# One-time setup on the build host:
#   docker login <your-registry>
#   docker buildx create --name neko-builder --use
#   docker run --privileged --rm tonistiigi/binfmt --install arm64   # x86 host only
#
# Usage (from anywhere in the checkout):  deploy/build-multiarch.sh [tag]
#   default tag: latest
#   NEKO_SUDO_IMAGE overrides the image path (default below).
set -eu
TAG=${1:-latest}
IMAGE=${NEKO_SUDO_IMAGE:-registry.example.com/neko-sudo/gate}
cd "$(dirname -- "$0")/.."

# Fail loudly when run outside a real checkout (e.g. the gate's data dir):
# the build context must contain ./gate and ./Dockerfile, nothing else ships.
if [ ! -d gate ] || [ ! -f Dockerfile ]; then
    echo "build-multiarch: $(pwd) is not a neko-sudo checkout (need ./gate and ./Dockerfile)." >&2
    echo "  Clone the repository somewhere clean and run from there — never the data dir." >&2
    exit 1
fi

# Preflight: building the arm64 slice on a non-arm64 host needs the QEMU
# binfmt handler in the kernel; without it every RUN dies with
# "exec /bin/sh: exec format error" several slow steps into the build.
if [ "$(uname -m)" != "aarch64" ] && [ ! -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
    # /proc visibility is per mount namespace: the handler can be registered
    # kernel-wide yet not show under OUR /proc (CI: binfmt is installed
    # inside the dind daemon, whose namespace the job container lacks).
    # Probe the real build path instead — run a tiny arm64 container.
    if docker run --rm --platform linux/arm64 alpine:3 true 2>/dev/null; then
        :
    else
        echo "build-multiarch: no arm64 emulation on this host — the arm64 build steps" >&2
        echo "  would fail with 'exec format error'. Fix once, then re-run:" >&2
        echo "    docker run --privileged --rm tonistiigi/binfmt --install arm64" >&2
        echo "    docker buildx rm neko-builder 2>/dev/null || true" >&2
        echo "    docker buildx create --name neko-builder --use" >&2
        exit 1
    fi
fi

# BuildKit >=0.32 attaches provenance/SBOM attestations (OCI artifacts
# whose subject names the image manifest) and pushes them concurrently
# with it; the GitLab registry rejects the not-yet-present subject with
# "blob unknown to registry" whenever the image manifest is new — an
# intermittent failure that retries eventually win. We gain nothing from
# attestations here, so disable both and push a plain manifest list.
exec docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --provenance=false \
    --sbom=false \
    -t "$IMAGE:$TAG" \
    --push .
