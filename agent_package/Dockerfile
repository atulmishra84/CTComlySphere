FROM python:3.11-slim

LABEL maintainer="CT ComplySphere"
LABEL description="CT ComplySphere Collector Agent — discovers AI agents in customer networks"
LABEL version="1.0.0"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY agent.py .

# Non-root user for security
RUN useradd -m -u 1000 agent && chown -R agent:agent /app
USER agent

# Default environment
ENV SCAN_INTERVAL=3600
ENV LOG_LEVEL=INFO

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import requests, os; requests.get(os.environ['PLATFORM_URL'] + '/api/collector/heartbeat', headers={'Authorization': 'Bearer ' + os.environ['API_TOKEN']}, timeout=5)" || exit 1

ENTRYPOINT ["python3", "agent.py"]
