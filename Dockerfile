# Use official Python base
FROM python:3.11-slim

# Avoid prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install LibreOffice + other tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libreoffice \
    libreoffice-writer \
    libreoffice-calc \
    libreoffice-impress \
    unzip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy your app code
COPY ./app /app

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Create upload folder
RUN mkdir -p /tmp/uploads

# Expose port
EXPOSE 8080

# Start FastAPI with Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
