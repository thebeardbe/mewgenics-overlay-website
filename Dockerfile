FROM python:3.12-slim

WORKDIR /srv/bugbox

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py llm.py store.py seed_demo.py ./
COPY templates ./templates
COPY static ./static

ENV BGBOX_DATA=/data
VOLUME /data
EXPOSE 8000

# Run as an unprivileged user (never root inside the container).
RUN useradd --create-home --uid 10001 bugbox \
    && mkdir -p /data \
    && chown -R bugbox:bugbox /srv/bugbox /data
USER bugbox

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
