# Runner image for Veracode Auto-Fix.
#
# Contains: Python (the autofix package), git, the Veracode CLI (Pipeline Scan +
# Veracode Fix) and the Veracode SCA agent (srcclr).
#
# The target project's build toolchain is added through BUILD_PACKAGES, e.g.
#   docker build --build-arg BUILD_PACKAGES="openjdk-17-jdk-headless maven" .
#   docker build --build-arg BUILD_PACKAGES="nodejs npm" .

FROM python:3.12-slim

ARG BUILD_PACKAGES="openjdk-17-jdk-headless maven"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates zip unzip ${BUILD_PACKAGES} \
 && rm -rf /var/lib/apt/lists/*

# Veracode CLI (installs ./veracode in the current folder)
RUN cd /usr/local/bin && curl -fsS https://tools.veracode.com/veracode-cli/install | sh \
 && veracode version

# Veracode SCA agent
RUN curl -sSL https://download.sourceclear.com/install | sh

WORKDIR /opt/veracode-auto-fix
COPY autofix ./autofix
ENV PYTHONPATH=/opt/veracode-auto-fix \
    PYTHONUNBUFFERED=1

# CI jobs run their own script; this default is handy for local runs.
ENTRYPOINT []
CMD ["python", "-m", "autofix", "--help"]
