# MeepCoin daemon build environment.
#
# Pins the base image by DIGEST and a PLATFORM, and pins apt to a snapshot date, so the compiler and
# library set are re-installable rather than "whatever was current".
#
# THE PROOF-OF-WORK IS COPIED IN, NOT MOUNTED. The previous image expected the meepow/ tree as a
# run-time bind mount and checked only that one header existed. Whatever bytes the host happened to
# have -- modified, dirty, a different branch -- were compiled into the daemon while the source lock
# still passed, because the lock covered the other half of the build. The locked MeepHash inputs are
# now part of the image and are verified against node/daemon-source/MEEPOW_BUILD_INPUTS.json by hash
# before cmake runs. .dockerignore names those files one by one, plus ONE separately pinned
# configure-only file (meepow/src/meepow.cpp, which CMake must see but the daemon does not compile);
# nothing else can arrive with them.
#
# Build (from the meepcoin repo root):
#   docker build --platform linux/amd64 -f node/Dockerfile -t meepcoin-build:pinned .
# Run:
#   docker run --rm -v "$PWD/out:/out" meepcoin-build:pinned
#
# EXPERIMENTAL DEVNET. Test coins, no monetary value. Not mainnet. The image compiles a daemon; it
# does not start one, and one build proves nothing about reproducibility.

# Ubuntu 24.04 LTS (noble), pinned by digest AND platform. The digest alone names a multi-platform
# INDEX, so on an arm64 host it would silently select a different base than on amd64 and produce
# different binaries from "the same" pin. --platform makes the choice explicit.
FROM --platform=linux/amd64 ubuntu@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab

ARG APT_SNAPSHOT=20250601T000000Z
ARG MONERO_TAG=v0.18.5.1
ARG MONERO_COMMIT=4f92268d7c16741cfb41e5bbe2aa46cc260a9ea5

ENV DEBIAN_FRONTEND=noninteractive \
    SOURCE_DATE_EPOCH=1785283200 \
    MEEPCOIN_TARGET_PLATFORM=linux/amd64

# The minimal pinned base has no CA bundle. Bootstrap exactly the three packages needed to establish
# normal TLS from the SAME dated snapshot, with BuildKit enforcing every downloaded byte. This is
# deliberately stronger than disabling TLS verification for the first apt run: no unsigned or
# transport-selected package can enter the image before certificate verification exists.
ADD --checksum=sha256:641de77d8f142cfd62a1a6f964ba67b20754d3337c480efb529d086075a06c9a \
    https://snapshot.ubuntu.com/ubuntu/20250601T000000Z/pool/main/c/ca-certificates/ca-certificates_20240203_all.deb \
    /tmp/ca-bootstrap/ca-certificates.deb
ADD --checksum=sha256:31df0a4d957c404c01b1898a84beca1190fd71cf2d2ac47ce5036705a24d96fc \
    https://snapshot.ubuntu.com/ubuntu/20250601T000000Z/pool/main/o/openssl/libssl3t64_3.0.13-0ubuntu3.5_amd64.deb \
    /tmp/ca-bootstrap/libssl3t64.deb
ADD --checksum=sha256:00f9b292ff5636d49832e493789ec91e21cfd4e98ccc9fd23497e92a2cc9c76a \
    https://snapshot.ubuntu.com/ubuntu/20250601T000000Z/pool/main/o/openssl/openssl_3.0.13-0ubuntu3.5_amd64.deb \
    /tmp/ca-bootstrap/openssl.deb

# Ubuntu 24.04 declares its moving archive in /etc/apt/sources.list.d/ubuntu.sources. Merely writing
# /etc/apt/sources.list leaves that Deb822 source active and silently permits current packages when
# the snapshot fails. Remove BOTH source formats first, install the checksum-pinned CA bootstrap,
# then make any snapshot update warning fatal. From this point onward every apt byte uses verified
# TLS, signed snapshot metadata, and the fixed date above.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources \
 && dpkg -i /tmp/ca-bootstrap/libssl3t64.deb \
            /tmp/ca-bootstrap/openssl.deb \
            /tmp/ca-bootstrap/ca-certificates.deb \
 && rm -rf /tmp/ca-bootstrap \
 && printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s noble main universe\n\
deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s noble-updates main universe\n' \
      "$APT_SNAPSHOT" "$APT_SNAPSHOT" > /etc/apt/sources.list \
 && test -z "$(find /etc/apt/sources.list.d -type f -print -quit)" \
 && apt-get -o APT::Update::Error-Mode=any update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config git ca-certificates \
      libboost-all-dev libssl-dev libzmq3-dev libunbound-dev libsodium-dev \
      libunwind-dev liblzma-dev libreadline-dev libexpat1-dev libpgm-dev libnorm-dev \
      libudev-dev libprotobuf-dev protobuf-compiler libusb-1.0-0-dev libhidapi-dev \
      python3 \
 && rm -rf /var/lib/apt/lists/*

# The fork base, pinned to an exact commit. This is a local MIRROR for reconstruct.sh to clone from,
# not the build tree: reconstruct.sh re-verifies the commit AND its tree before applying any patch,
# so a drifting clone cannot silently become the build input. Nothing is built here.
RUN git clone --depth 1 --branch ${MONERO_TAG} --recursive \
      https://github.com/monero-project/monero.git /src/monero \
 && cd /src/monero \
 && test "$(git rev-parse HEAD)" = "${MONERO_COMMIT}"

# The CANONICAL daemon source: an ordered, hashed patch series over the pinned Monero base, the
# Python verifier that enforces the lock's declared contract, and the MeepHash input manifest.
COPY node/daemon-source /src/daemon-source

# The locked MeepHash compile inputs. .dockerignore reduces the context to the 24 manifest-bound
# compilation inputs named in MEEPOW_BUILD_INPUTS.json PLUS one separately pinned configure-only file,
# meepow/src/meepow.cpp: CMake's generate step needs that path, the requested daemon targets must not
# compile it, and it is outside the 24-file identity. node/docker-build.sh verifies its size and
# SHA-256 before and after the build and fails if the legacy target was compiled. The layout is
# preserved (/src/meephash/meepow/...) because the manifest's paths are repo-root-relative.
COPY meepow /src/meephash/meepow

COPY node/docker-build.sh /usr/local/bin/meepcoin-build
RUN chmod +x /usr/local/bin/meepcoin-build /src/daemon-source/reconstruct.sh

# Fail at IMAGE BUILD time, not at run time, if the copied MeepHash inputs are not the locked ones.
RUN python3 /src/daemon-source/verify_lock.py meepow /src/daemon-source /src/meephash \
 && python3 /src/daemon-source/verify_lock.py contract /src/daemon-source

WORKDIR /src
ENTRYPOINT ["/usr/local/bin/meepcoin-build"]
