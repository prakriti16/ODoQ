Run at server:
```
python3 doq_resolver_time.py --certificate onlyserver.pem --private-key onlyserver.key --port 8053 -v --timing-log doqdec2resolver1time.csv
```
To run at client ten times (specified using -c flag):
```
python doq_client_time.py --ca-certs onlyproxy.pem --query-type A --query-name dns.adguard.com --port 8053 --host 10.230.3.93 --server-cert onlyserver.pem --insecure -c 10 --timing-log odoqdec3timeclient.csv
```

