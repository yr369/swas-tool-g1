# Backend Dockerfile for SWAS mk-4
#
# Uses python:3.12-slim, which has official ARM64 builds - this matters
# because the OCI deploy target is an ARM64 (Ampere A1) server.
#
# This Dockerfile also installs the 10 scanning tools the pipeline uses.
# Most are Go binaries (ProjectDiscovery tools + dalfox), so we install Go
# temporarily to build them, then remove Go afterward to keep the final
# image smaller - this is a common pattern called a "multi-stage build."

FROM golang:1.25-bookworm AS tools-builder

# GOARCH gets set automatically by Docker based on the target platform
# (arm64 on your OCI server), so `go install` below produces the correct
# architecture binaries without us hardcoding anything.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest


FROM python:3.12-slim

WORKDIR /app

# Copy the Go-built tool binaries from the builder stage above
COPY --from=tools-builder /go/bin/ /usr/local/bin/

# IMPORTANT: the Python "httpx" library (an HTTP client, listed in
# requirements.txt for our own backend code to use) installs its own small
# CLI wrapper also named "httpx". Since pip runs AFTER this COPY step, it
# would silently overwrite the real security tool at /usr/local/bin/httpx
# with its own unrelated script - this caused a real bug where the actual
# scanner silently stopped working. Fix: rename the REAL tool to a name
# that can't collide, and update tools.py to call it by that name.
RUN mv /usr/local/bin/httpx /usr/local/bin/httpx-pd

# System dependencies needed for sqlmap (it's a Python tool but ships as
# a git-cloned script, not a pip package) and for arjun (pip package).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# sqlmap is a Python script, not a compiled binary - this wrapper script
# lets us call it as a plain "sqlmap" command from tools.py, the same way
# we call every other tool, instead of special-casing it.
RUN printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap

# Install Python dependencies first, separately from app code. This is a
# deliberate ordering: Docker caches each step, so if you only change app
# code (not requirements.txt), rebuilding skips the slow pip install step.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# arjun is a pip package
RUN pip install --no-cache-dir arjun

# Now copy the actual application code
COPY app/ ./app/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
