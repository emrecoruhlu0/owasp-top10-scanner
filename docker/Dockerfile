FROM python:3.11-slim

WORKDIR /app

COPY guvenlik_proje/ ./guvenlik_proje/
RUN pip install --no-cache-dir -r guvenlik_proje/requirements.txt

COPY web/requirements.txt ./web/requirements.txt
RUN pip install --no-cache-dir -r web/requirements.txt

COPY web/ ./web/

RUN mkdir -p /tmp/scans

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["web"]
