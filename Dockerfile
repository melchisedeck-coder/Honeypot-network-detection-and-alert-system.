FROM python:3.11-slim

LABEL maintainer="Melchisedeck Lucian Komba <lucianmerchisedeck@gmail.com>"
LABEL description="KIU Final Year Project — Low Interaction Honeypot System"

# System deps for psycopg3 binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000 5001 2222 2121 3307

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "run.py"]
