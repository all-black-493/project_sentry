FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

RUN apt-get -y update; apt-get -y install curl

# keep the 'app' directory inside the container as /app/app
COPY . .

EXPOSE 8000

# run the app as the package module app.main:app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
