FROM python:3.11-slim
WORKDIR /app
COPY ./app /app/app
COPY requirements.txt /app/
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/* \
	&& pip install --no-cache-dir -r /app/requirements.txt

COPY ./entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

VOLUME ["/keys"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
