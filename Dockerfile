FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

ENTRYPOINT ["python", "-m", "dfir_pipeline.cli"]
CMD ["--demo"]
