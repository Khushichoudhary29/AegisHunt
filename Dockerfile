# Use an official Python slim runtime as the parent image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements first for caching docker layers
COPY requirements.txt .

# Install python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Expose port 8000 for the FastAPI server
EXPOSE 8000

# Run FastAPI server via Uvicorn by default
CMD ["python", "main.py", "--mode", "server", "--host", "0.0.0.0", "--port", "8000"]
