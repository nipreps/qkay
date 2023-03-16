FROM python:3.7-slim


ADD . /app
WORKDIR /app


RUN pip3 install -r requirements.txt
RUN pip3 install pytest
WORKDIR ./qkay
