FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
RUN useradd --create-home --uid 10001 containmentci \
    && mkdir -p /app/.containmentci \
    && chown -R containmentci:containmentci /app/.containmentci

EXPOSE 8080
USER containmentci
CMD ["containmentci", "serve", "--host", "0.0.0.0", "--port", "8080"]

