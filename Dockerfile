FROM python:3.12-slim-bookworm

WORKDIR /app
COPY drcom_auth.py .
RUN chmod 0755 /app && chmod 0644 /app/drcom_auth.py
USER 65534:65534

ENTRYPOINT ["python", "-u", "/app/drcom_auth.py"]
