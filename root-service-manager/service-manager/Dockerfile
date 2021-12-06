FROM python:3.8.5-slim-buster

ADD requirements.txt /

RUN pip install -r requirements.txt

ADD . /

# TRUE for verbose logging
ENV FLASK_DEBUG=FALSE

ENV CLOUD_MONGO_URL=localhost
ENV CLOUD_MONGO_PORT=10007

EXPOSE 10100

CMD ["python", "service_manager.py"]