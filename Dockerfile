FROM python:3.13-slim

WORKDIR /app
COPY kakao_alert.py .

USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["python", "-u", "/app/kakao_alert.py"]
