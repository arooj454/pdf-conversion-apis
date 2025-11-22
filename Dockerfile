# -------------------------------
# Base image
# -------------------------------
FROM python:3.12-slim

# -------------------------------
# Install LibreOffice (cross-platform)
# -------------------------------
RUN apt-get update && \
    apt-get install -y libreoffice libreoffice-writer libreoffice-calc libreoffice-impress && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# -------------------------------
# Set working directory
# -------------------------------
WORKDIR /app

# -------------------------------
# Copy project files
# -------------------------------
COPY ./app /app

# -------------------------------
# Install Python dependencies
# -------------------------------
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------------
# Expose port
# -------------------------------
EXPOSE 8000

# -------------------------------
# Start FastAPI with Uvicorn
# -------------------------------
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
