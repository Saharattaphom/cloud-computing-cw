FROM python:3.7-alpine
WORKDIR /myapp
COPY . /myapp
COPY /certs/domain.crt /usr/local/share/ca-certificates/domain.crt
RUN update-ca-certificates
RUN pip install -U -r requirements.txt
EXPOSE 8080
CMD ["python", "app.py"]

