FROM python:3.12-slim

WORKDIR /app

# Install service requirements and shared runtime deps
COPY unison-policy/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir redis python-jose[cryptography] bleach httpx pyyaml

# Copy service source and shared library from monorepo
COPY unison-policy/src ./src
COPY unison-policy/rules.yaml ./rules.yaml
COPY unison-common/src/unison_common ./src/unison_common

ENV PYTHONPATH=/app/src

EXPOSE 8083
CMD ["python", "src/server.py"]
