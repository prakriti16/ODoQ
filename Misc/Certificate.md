To create a self signed certificate using openssl, first create the .cnf file, like:
```
nano req.cnf
```
Sample contents:
```
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = XY
ST = CA 
O = Python Software Foundation
CN = localhost

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 10.230.3.93
```
Specify IP address of system with privileges (like resolver) in alt_names section.

Then create the self-signed certificate using command:
```
openssl req -x509 -nodes -newkey rsa:2048 -keyout server.key -out server.pem -sha256 -days 365 -config req.cnf
```
NOTE: Make sure you have openssl and other dependencies installed via pip.

Then to verify contents of your certificate use -noout command:
```
openssl x509 -in server.pem -text -noout
```

Image for reference:
[!Certificate creation steps](/opensslnov14cert.png)

