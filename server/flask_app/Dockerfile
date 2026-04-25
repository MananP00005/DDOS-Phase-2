FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "--workers=6", "--threads=1", "--worker-class=sync", "--timeout=10", "--bind=0.0.0.0:5000", "--access-logfile=-", "app:app"]
