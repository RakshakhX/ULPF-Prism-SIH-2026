FROM python:3.12-slim

WORKDIR /app

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY files/setup_topics.py files/worker.py files/load_gen.py files/metrics_report.py files/benchmark_metrics.py ./

ENTRYPOINT ["python"]
CMD ["worker.py", "--help"]
