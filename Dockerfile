FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-azure.txt .
RUN pip install --no-cache-dir -r requirements-azure.txt

COPY . .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

EXPOSE 5000

RUN chmod +x /app/startup.sh

CMD ["/app/startup.sh"]
