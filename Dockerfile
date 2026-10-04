FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOOP_DATA_DIR=/var/data/loop \
    LOOP_PORT=10000 \
    LOOP_HTTPS=1

WORKDIR /app
COPY requirements-server.txt ./requirements-server.txt
RUN pip install --no-cache-dir -r requirements-server.txt
COPY app.py ./app.py
EXPOSE 10000
CMD ["python", "app.py"]