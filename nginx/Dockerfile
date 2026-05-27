FROM nginx:1.25-alpine

LABEL maintainer="QA CTF Team"
LABEL description="Nginx Reverse Proxy (Vulnerable to TE.TE Smuggling)"

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
