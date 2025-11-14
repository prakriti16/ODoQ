Download dnscrypt-proxy for your OS from their github repository.
I used dnscrypt-proxy-win64-2.1.14\win64
.If you are on windows go to powershell and type 
```
cmd
```
to open the command prompt.
Modify the .toml file as in the repository.
To start the server type
```
start dnscrypt-proxy
```
This will open up a new terminal showing which server and relay you are connected to and the rtt.
Next come back to the command prompt terminal and type 
```
dnscrypt-proxy -resolve example.com  
```
to resolve the domain example.com
.To run the experiments for the 10 domains type 
```
python test_dns.py
```
where test_dns.py is the script in this repository.
Make sure wireshark is running while you run the script to analyse and capture packet size data.
Once you export it as plaintext from wireshark you can use script packetsize_parser.py in this repository to extract the udp payload sizes in .csv format.
```
python packetsize_parser.py
```
