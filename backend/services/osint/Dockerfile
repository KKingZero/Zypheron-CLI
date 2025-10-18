FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY osint_service_grpc.py .
COPY osint_pb2.py .
COPY osint_pb2_grpc.py .
COPY common_pb2.py .

# Create non-root user
RUN useradd -m -u 1000 osint && chown -R osint:osint /app
USER osint

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8001/health')"

# Run the service
CMD ["python", "osint_service_grpc.py"] 