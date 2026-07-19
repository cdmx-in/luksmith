FROM python:3.12-alpine

COPY luksmith_server.py /app/luksmith_server.py

VOLUME /data
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8443/healthz',timeout=2)" || exit 1

ENTRYPOINT ["python3", "/app/luksmith_server.py", "--db", "/data/luksmith.db", "--bind", "0.0.0.0", "--port", "8443"]
