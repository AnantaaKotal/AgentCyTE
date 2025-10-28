FROM python:3.10-slim
WORKDIR /app
COPY . /app
# Install runtime dependencies for the web app
RUN pip install --no-cache-dir flask werkzeug lxml
EXPOSE 9090
CMD ["python", "app_backend.py"]
