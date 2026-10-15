# One image for every testbed role. Ubuntu 24.04 matches the host
# (Python 3.12.3, Unbound 1.19.2, NSD 4.8.0). Code is bind-mounted, so edits
# do not need a rebuild; the runner records the git commit for each campaign.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv unbound nsd iproute2 ethtool tcpdump \
      dnsutils procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv
COPY requirements.txt /opt/odoq/requirements.txt
COPY requirements-hpke.txt /opt/odoq/requirements-hpke.txt
RUN /opt/venv/bin/pip install --no-cache-dir -r /opt/odoq/requirements.txt \
 && /opt/venv/bin/pip install --no-cache-dir --no-deps -r /opt/odoq/requirements-hpke.txt \
 && /opt/venv/bin/python -c "import hpke, aioquic.h3.connection, cryptography; print('deps ok', cryptography.__version__)"
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/opt/odoq/src \
    PYTHONUNBUFFERED=1
WORKDIR /opt/odoq
