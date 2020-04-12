# REST API for stock trading simulation
A Flask application capable of keeping records of transactions in Cassandra database with basic hash-based authentication

Both the Flask application and Cassandra database are deployed using containers

For external REST service, IEX Cloud API is used to get stock price information

This application is implemented on AWS platform using EC2 and Elastic IP services

To serve the application over HTTPS, this application makes use of self-signed certificate using openssl

For the purpose of locating resources, this application also applies the concept of HATEOAS using flask_marshmallow

## Preparation

1. Certificate generation

```

openssl req -x509 -newkey rsa:4096 -nodes -out domain.crt -keyout domain.key -days 365

```

2. Pull cassandra image and Create database
```

docker pull cassandra:latest
docker run --name portfolio-db -p 9042:9042 -d cassandra:latest

```
```

CREATE KEYSPACE portfolio WITH REPLICATION = {'class':'SimpleStrategy', 'replication_factor':1};
CREATE TABLE portfolio.users (username text PRIMARY KEY, password_hash text);
CREATE TABLE portfolio.transactions (username text, quote text, action text, value decimal, volume int, priceref text, transactionTime timestamp, PRIMARY KEY(username, transactionTime));

```
3. Instruct every Docker daemon to trust the generated certificate
```

sudo mkdir -p /etc/docker/certs.d/XX.XXX.XXX.XXX:443
sudo cp certs/domain.crt 

```
4. Build an image of application and Run
```

docker build . --tag=cwrest:v1
docker run -p 443:443 --name registry -v /certs:/certs -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key -e REGISTRY_HTTP_ADDR=XX.XXX.XXX.XXX:443 cwrest:v1

```

## Examples

1. Create new user
```

curl --insecure -i -H "Content-Type: application/json" -X POST -d '{"username":"Becky", "password":"mypassword"}' https://ec2-XX-XXX-XXX-XXX.compute-1.amazonaws.com/users

```
--insecure is included in the request to bypass the self-signed certificate issue

2. Update password
```

curl --insecure -u Becky:mypassword -i -H "Content-Type: application/json" -X PUT -d '{"new_password":"mynewpassword"}' https://ec2-XX-XXX-XXX-XXX.compute-1.amazonaws.com/users

```
3. Get user information
```

curl --insecure https://ec2-XX-XXX-XXX-XXX.compute-1.amazonaws.com/users/Becky

```
4. Delete user
```

curl --insecure -u Becky:mynewpassword -i -H "Content-Type: application/json" -X DELETE https://ec2-XX-XXX-XXX-XXX.compute-1.amazonaws.com/users

```
5. Create transaction
```

curl --insecure -u Becky:mynewpassword -i -H "Content-Type: application/json" -X POST -d '{"quote":"twtr", "action":"sell", "volume":"100"}' https://ec2-XX-XXX-XXX-XXX.compute-1.amazonaws.com/action-port

```
6. Get portfolio status
```

curl --insecure -u Becky:mynewpassword https://ec2-XX-XXX-XXX-XXX.compute-1.amazonaws.com/status-port

```
