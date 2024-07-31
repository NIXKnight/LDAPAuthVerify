FROM debian:bookworm-slim AS base

ARG DEBIAN_FRONTEND noninteractive

ENV VIRTUAL_ENV="/opt/ldap_auth_verify_venv"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
ENV GUNICORN_PORT=8000
ENV GUNICORN_WORKERS=2

RUN set -eux; \
    groupadd --system --gid 101 user; \
    useradd --system --gid user --no-create-home --shell /bin/false --uid 101 user

RUN set -eux; \
    apt-get update; \
    apt-get -y dist-upgrade; \
    apt-get -y install --no-install-recommends \
    python3 \
    libldap-2.5-0 \
    python3-venv; \
    apt-get clean all; \
    rm -rf /var/lib/apt/lists/*

FROM base AS builder

RUN set -eux; \
    apt-get update; \
    apt-get -y install --no-install-recommends \
    build-essential \
    python3-pip \
    python3-venv \
    python3-dev \
    libldap-dev \
    libsasl2-dev; \
    apt-get clean all; \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/requirements.txt

RUN set -eux; \
    python3.11 -m venv "${VIRTUAL_ENV}"; \
    pip install -r /opt/requirements.txt

FROM base AS final

COPY --from=builder /opt/ldap_auth_verify_venv /opt/ldap_auth_verify_venv
COPY LDAPAuthVerify.py /opt/ldap_auth_verify/LDAPAuthVerify.py

USER user

EXPOSE ${GUNICORN_PORT}

WORKDIR /opt/ldap_auth_verify

CMD gunicorn LDAPAuthVerify:app -w ${GUNICORN_WORKERS} -b 0.0.0.0:${GUNICORN_PORT}
