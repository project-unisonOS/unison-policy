FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY rules.yaml ./rules.yaml

EXPOSE 8083
CMD ["python", "src/server.py"]
