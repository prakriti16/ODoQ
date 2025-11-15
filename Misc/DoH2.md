doh-proxy library in python was used to set up DNS-over-HTTP2.

Sample ommand to resolve google.com domain using kdig:
```
kdig -d @10.230.3.83#443 +https +tls-host=10.230.3.83 +tls-ca=/home/prakriti/recursor-cert.pem google.com  
```
