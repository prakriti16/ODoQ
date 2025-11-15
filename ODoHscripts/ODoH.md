Download the latest dnscrypt-proxy for your OS (e.g. windows 64-bit) from https://github.com/dnscrypt/dnscrypt-proxy/releases/tag/2.1.14
Then download the dnscrypt-proxy.toml file from this repository.
You can customize it by specifying the resolver and proxy to be used in routes and server_names fields. Refer https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Oblivious-DoH
On windows powershell activate command prompt:
```
cmd
```
To start the server type:
```
start dnscrypt-proxy
```
To resolve a domain, like example.com, type
```
dnscrypt-proxy -resolve example.com
```

