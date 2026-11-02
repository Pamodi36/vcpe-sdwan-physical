FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 \
      iperf3 \
      chrony \
      libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

EXPOSE 9100/tcp 862/udp 5201/tcp

CMD ["sh", "-c", "uvicorn app.main:app --host ${API_BIND:-0.0.0.0} --port ${API_PORT:-9100}"]
