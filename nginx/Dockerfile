FROM nginx:1.15.8

RUN rm /etc/nginx/nginx.conf
COPY conf.d/nginx.conf /etc/nginx/
RUN rm /etc/nginx/conf.d/default.conf
COPY conf.d/app.conf /etc/nginx/conf.d/