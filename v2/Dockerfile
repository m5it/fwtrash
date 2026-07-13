FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[dashboard]"

# Copy source code
COPY src/ ./src/

# Install the package
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd -m -u 1000 fwtrash

# State directory
RUN mkdir -p /data/state && chown -R fwtrash:fwtrash /data

USER fwtrash

EXPOSE 8080

ENTRYPOINT ["fwtrash"]
CMD ["--help"]
