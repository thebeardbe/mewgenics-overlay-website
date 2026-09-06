FROM python:3.12-slim

WORKDIR /srv/bugbox

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py llm.py store.py ./
COPY templates ./templates

ENV BGBOX_DATA=/data
VOLUME /data
EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
