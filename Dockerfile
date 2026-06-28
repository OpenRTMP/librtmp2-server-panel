FROM python:alpine

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /data && adduser -D -h /app appuser && chown -R appuser:appuser /app /data
ENV PANEL_DB_PATH=/data/panel.db

USER appuser

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
