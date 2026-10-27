# For production, pin the base image digest after vulnerability review.
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml /app/
COPY sori /app/sori
RUN pip install --no-cache-dir '.[server]' && \
    useradd --create-home --uid 10001 --shell /usr/sbin/nologin sori
COPY examples /app/examples
COPY edge /app/edge
USER 10001:10001
EXPOSE 8000
CMD ["sori", "serve", "examples/hello.sori", "--host", "0.0.0.0", "--port", "8000"]
