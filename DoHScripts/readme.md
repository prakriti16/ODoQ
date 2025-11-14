Refer to the aioquic library's http3 example files for the base behind these scripts. 
Install aioquic using 
```
pip install aioquic
```
and clone the aioquic repository.
Then go to the examples folder and follow the readme file there for instructions on installing dependencies for HTTP3 examples.
```
cd aioquic/examples
```
Then download the files from this repository.
Create a self signed certificate using openssl allowing your resolver and clients IP address's.

Finally login to the resolver system (say IP:10.230.3.93) and the client(say IP 10.230.3.83).

Sample command to run the resolver:
```
python3 doh_serv.py -c server.pem -k server.key --host 0.0.0.0 --port 4433 --resolver 8.8.8.8 -v
```

Sample command to run the client:
```
python3 doh_client.py --server 10.230.3.93 --server-port 4433 --query-name x.com  --query-type A --ca-certs server.pem -v --timing-log doh24oct.csv
```
