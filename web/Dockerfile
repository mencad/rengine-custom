# Base image
FROM ubuntu:22.04

ARG GECKOVERSION=0.33.0
ARG GOVERSION=1.21.5
ARG KITERUNNER_VERSION=1.0.2

RUN ARCH=$(dpkg --print-architecture) \ 
    && if [ "${ARCH}" ! "arm64" ] || [ "${ARCH}" ! "amd64" ]; then \
      echo "reNgine not supported, encountered unknown architecture: ${TARGETPLATFORM}" \
      && exit 1; \
    fi

# Labels and Credits
LABEL \
    name="reNgine" \
    author="Yogesh Ojha <yogesh.ojha11@gmail.com>" \
    description="reNgine is a automated pipeline of recon process, useful for information gathering during web application penetration testing."

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres"
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Install Python
RUN apt update -y && \
    apt install -y \
    python3.10 \
    python3-dev \
    python3-pip 

# Install essential packages
RUN apt install -y --no-install-recommends \
    build-essential \
    cmake \
    geoip-bin \
    geoip-database \
    gcc \
    git \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpcap-dev \
    netcat \
    nmap \
    x11-utils \
    xvfb \
    wget \
    curl \
    python3-netaddr \
    software-properties-common

RUN add-apt-repository ppa:mozillateam/ppa

RUN ARCH=$(dpkg --print-architecture) \ 
    && (curl -fsSL https://mirrors.aliyun.com/golang/go${GOVERSION}.linux-${ARCH}.tar.gz || \
        curl -fsSL https://dl.google.com/go/go${GOVERSION}.linux-${ARCH}.tar.gz || \
        curl -fsSL https://go.dev/dl/go${GOVERSION}.linux-${ARCH}.tar.gz) | tar -xzC /usr/local

RUN ARCH=$(dpkg --print-architecture) \ 
    && if [ "${ARCH}" = "arm64" ]; then \
      GECKOPATH="geckodriver-v${GECKOVERSION}-linux-aarch64.tar.gz"; \
    elif [ "${ARCH}" = "amd64" ]; then \
      GECKOPATH="geckodriver-v${GECKOVERSION}-linux64.tar.gz"; \
    fi \
    && wget https://github.com/mozilla/geckodriver/releases/download/v${GECKOVERSION}/${GECKOPATH} \
    && tar -xvf ${GECKOPATH} \
    && rm ${GECKOPATH} \
    && mv geckodriver /usr/bin

# Install Kiterunner (kr) for API discovery
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "arm64" ]; then \
      KRPATH="kiterunner_${KITERUNNER_VERSION}_linux_arm64.tar.gz"; \
    else \
      KRPATH="kiterunner_${KITERUNNER_VERSION}_linux_amd64.tar.gz"; \
    fi \
    && wget -q https://github.com/assetnote/kiterunner/releases/download/v${KITERUNNER_VERSION}/${KRPATH} \
    && tar -xzf ${KRPATH} \
    && rm -f ${KRPATH} \
    && mv kr /usr/local/bin/kr \
    && chmod +x /usr/local/bin/kr \
    && mkdir -p /usr/src/wordlist/kiterunner \
    && wget -q https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz -O /tmp/routes-small.kite.tar.gz \
    && tar -xzf /tmp/routes-small.kite.tar.gz -C /usr/src/wordlist/kiterunner/ \
    && rm -f /tmp/routes-small.kite.tar.gz

# Install Rust for orjson
RUN set -e; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip3 install maturin

# Install x8 for hidden parameter discovery
ARG X8_VERSION=v4.3.0
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "${ARCH}" = "amd64" ]; then \
      wget -q https://github.com/Sh1Yo/x8/releases/download/${X8_VERSION}/x86_64-linux-x8.gz -O /tmp/x8.gz \
      && gzip -d /tmp/x8.gz \
      && mv /tmp/x8 /usr/local/bin/x8 \
      && chmod +x /usr/local/bin/x8; \
    else \
      cargo install x8 --root /usr/local; \
    fi

# Make directory for app
WORKDIR /usr/src/app

ENV GO111MODULE=on 
RUN printf "\
    github.com/jaeles-project/gospider@latest\n\
    github.com/tomnomnom/gf@latest\n\
    github.com/tomnomnom/unfurl@latest\n\
    github.com/tomnomnom/waybackurls@latest\n\
    github.com/projectdiscovery/httpx/cmd/httpx@latest\n\
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n\
    github.com/projectdiscovery/chaos-client/cmd/chaos@latest\n\
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\
    github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n\
    github.com/hakluke/hakrawler@latest\n\
    github.com/lc/gau/v2/cmd/gau@latest\n\
    github.com/owasp-amass/amass/v3/...@latest\n\
    github.com/ffuf/ffuf@latest\n\
    github.com/hahwul/dalfox/v2@latest\n\
    github.com/projectdiscovery/katana/cmd/katana@latest\n\
    github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\n\
    github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest\n\
    github.com/sa7mon/s3scanner@latest\n" | \
    xargs -L1 go install -ldflags="-s -w" -v && \
    rm -rf /go/pkg/* && rm -rf /root/.cache/go-build


# Update Nuclei and Nuclei-Templates
RUN nuclei -update-templates

# update chaos
RUN chaos -update

# Copy requirements
COPY ./requirements.txt /tmp/requirements.txt
RUN pip3 install --upgrade setuptools==72.1.0
RUN pip3 install -r /tmp/requirements.txt --no-cache-dir

# install eyewitness
RUN pip3 install --no-cache-dir fuzzywuzzy \
    selenium==4.9.1 \
    python-Levenshtein \
    pyvirtualdisplay \
    netaddr

# Copy source code
COPY . /usr/src/app/
