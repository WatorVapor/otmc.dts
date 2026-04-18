# otmc.dts edgeTwin builtin apps

## 
```
docker exec dts-edge-spire-agent-helper /usr/local/bin/spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock
```
```
openssl storeutl -certs -text -noout /opt/otmc/spiffe/svids/svid_bucket_cert.pem
```
