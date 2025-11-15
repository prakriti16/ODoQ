Referred to the installation via docker image in file https://github.com/AdguardTeam/dnsproxy/blob/master/README.md 
. Then created .yaml file with content same as https://github.com/AdguardTeam/dnsproxy/blob/master/config.yaml.dist and ran docker command with .yaml file location specified in the present working directory.
This successfully started the proxy listening but there were issues with quic://dns.adguard.com as the upstream in config.yaml not working.

