FROM python:3.7-slim


ADD . /app
WORKDIR /app


RUN pip3 install -r requirements.txt
RUN pip3 install pytest
RUN pip install gunicorn
WORKDIR ./qkay

EXPOSE 5000

CMD [ "gunicorn", "-w", "4", "--bind", "0.0.0.0:5000", "wsgi"]