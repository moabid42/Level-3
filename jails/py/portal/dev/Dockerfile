FROM python:3.13-slim


# Set working directory
WORKDIR /app

# Copy dependency definitions
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port for the web server
EXPOSE 5000

# Use Gunicorn to serve the app (as defined in Procfile)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
