FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

EXPOSE 8080
CMD ["containmentci", "serve", "--host", "0.0.0.0", "--port", "8080"]

