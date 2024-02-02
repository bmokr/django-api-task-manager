FROM python:3.12

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libpq-dev

COPY . /usr/src/app
WORKDIR /usr/src/app

COPY . /app

RUN pip install -r requirements.txt

ENV ENV_PATH .env.development

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]