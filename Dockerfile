# syntax=docker/dockerfile:1.7
# StepSecurity hardened Checkov action image.
# Built on Chainguard Wolfi (continuously CVE-patched). helm and kustomize are
# installed via Wolfi's apk so the binaries are rebuilt with current Go whenever
# Wolfi refreshes — eliminating the Go stdlib CVEs that ship with the official
# upstream tarballs. Vendors the upstream entrypoint.sh + problem-matcher JSONs
# from bridgecrewio/checkov so behavior is identical to the upstream image.

ARG CHECKOV_VERSION=3.2.528

FROM cgr.dev/chainguard/python:latest-dev
USER root

ARG CHECKOV_VERSION

ENV RUN_IN_DOCKER=True \
    PATH="/usr/local/bin:${PATH}"

# Runtime tools the upstream entrypoint relies on, plus helm and kustomize
# pulled from Wolfi (continuously CVE-patched, no need to bump manually).
# tar is provided by busybox in the base image — no separate package on Wolfi.
RUN apk add --no-cache \
        bash \
        git \
        openssh-client \
        gawk \
        coreutils \
        curl \
        ca-certificates \
        jq \
        helm \
        kustomize

# Install checkov pinned to a known version
RUN pip install --no-cache-dir "checkov==${CHECKOV_VERSION}"

# Vendored upstream artifacts (entrypoint.sh patched with the StepSecurity subscription check)
COPY entrypoint.sh /entrypoint.sh
COPY checkov-problem-matcher.json /usr/local/lib/checkov-problem-matcher.json
COPY checkov-problem-matcher-softfail.json /usr/local/lib/checkov-problem-matcher-softfail.json
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
