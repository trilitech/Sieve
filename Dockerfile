FROM golang:1.25-bookworm AS builder

WORKDIR /build

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /sieve ./cmd/sieve

# Runtime image with batteries-included Python for policy scripts
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager) and set up Python environment
# with common packages useful for policy scripts.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_PYTHON_PREFERENCE=managed
RUN uv python install 3.12 && \
    uv venv /opt/sieve-py && \
    . /opt/sieve-py/bin/activate && \
    uv pip install \
        # HTTP / API
        requests httpx \
        # Data
        pandas numpy \
        # LLM clients (for script-based policies that call LLMs)
        openai anthropic google-generativeai \
        # Parsing / formats
        beautifulsoup4 lxml pyyaml \
        # Auth / crypto
        pyjwt cryptography \
        # Text / regex
        regex \
        # JSON schema
        pydantic \
        # Templating
        jinja2 \
        # Token counting
        tiktoken
ENV PATH="/opt/sieve-py/bin:$PATH"

# Non-root user
RUN useradd -r -s /bin/false sieve && \
    mkdir -p /data /policies && \
    chown sieve:sieve /data /policies

COPY --from=builder /sieve /usr/local/bin/sieve

USER sieve

VOLUME ["/data"]
VOLUME ["/policies"]

EXPOSE 19816 19817

ENTRYPOINT ["sieve"]
CMD ["serve"]
