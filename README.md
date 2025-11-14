# ODoQ
Oblivious DNS-over-QUIC implementation using aioquic library.

Local setup had IP addresses 10.230.3.93, 10.230.3.83 and 10.240.60.74 for resolver, client and proxy respectively.
Self-signed certificates used are:
1. At resolver: onlyserver.pem and onlyserver.key.
2. At proxy: onlyserver.pem, onlyproxy.pem and onlyproxy.key.
3. At client: onlyserver.pem, onlyproxy.pem.

Note: while creating onlyserver.pem and onlyserver.key make sure the IP address of only the resolver is provided in the .cnf file. Similarly, for the onlyproxy.pem and onlyproxy.key files make sure only the proxy IP address is specified while creating the certificate to maintain security.

At resolver run command:
```
python3 doq_server.py --certificate onlyserver.pem --private-key onlyserver.key --port 8053 -v --timing-log odoqnov11resolver.csv
```

At proxy:
```
python3 doq_proxy.py --certificate onlyproxy.pem --private-key onlyproxy.key --upstream-host 10.230.3.93 --upstream-port 8053 --ca-certs onlyserver.pem --insecure -v --timing-log odoqnov11proxy.csv
```

At client:
```
python doq_client.py --ca-certs onlyproxy.pem --query-type A --query-name dns.adguard.com --port 8053 --host 10.240.60.74 --server-cert onlyserver.pem --insecure -c 10 --timing-log odoqnov11client.csv
```
