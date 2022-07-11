# Dockerfile
FROM python:3.7-stretch
COPY . /app
WORKDIR /app
COPY requirment.txt .
RUN pip install -r requirment.txt
ENTRYPOINT ["python"]
CMD ["main.py"]