# spireAgent
## Description
SpireAgent  

## x509pop leaf certificate
### 生成 x509pop leaf 证书
```bash
mkdir -p /opt/otmc/secret/spire-agent/certs/

# 生成 leaf 密钥
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.key

# 生成公钥
openssl pkey -pubout \
  -in /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.key \
  -out /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.pub

# 计算公钥的 SHA1 哈希值
sha1sum /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.pub \
   | awk '{print $1}' \
   > /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.pub.sha1

# 计算公钥的 SHA256 哈希值
sha256sum /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.pub \
   | awk '{print $1}' \
   > /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.pub.sha256

# 生成 leaf 证书 CSR
openssl req -new -nodes \
  -key /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.key \
  -subj "/C=CN/ST=Tokyo/L=Tokyo/O=Wator/CN=SPIRE X509POP Agent Leaf" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "extendedKeyUsage = clientAuth" \
  -out /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf.csr
```

### Features
- SpireAgent 是 Spire 项目的一部分，用于在边缘设备上运行。
- SpireAgent 负责与 Spire Server 通信，获取节点的 SPIFFE ID 和 X.509 证书。
- SpireAgent 还负责将节点的 SPIFFE ID 和 X.509 证书注册到 Spire Server。



### check help
```bash
docker exec dts-edge-spire-agent /opt/spire/bin/spire-agent healthcheck --help
```
### SVID
```bash
docker exec dts-edge-spire-agent /opt/spire/bin/spire-agent api fetch -socketPath /run/spire/sockets/agent.sock 
```
### fetch key certificate
```bash
docker exec dts-edge-spire-agent /opt/spire/bin/spire-agent api fetch x509  -socketPath /run/spire/sockets/agent.sock -write /run/spire/svids
```



### Cloud Storage access memo by spireAgent certificate and key
 ```bash
 curl -vvv -X GET \
    https://dts-cloud-edge.wator.xyz 
 ```

 ```bash
 curl -vvv -X GET \
    --cert /opt/otmc/spiffe/svids/svid.0.pem \
    --key /opt/otmc/spiffe/svids/svid.0.key \
     --user "${ACCESS_KEY}:${SECRET_KEY}" \
     --aws-sigv4 "aws:amz:ap-northeast-1:s3" \
    https://dts-cloud-edge.wator.xyz/ 
 ```

 ```bash
 curl -vvv -X GET \
     --user "${ACCESS_KEY}:${SECRET_KEY}" \
     --aws-sigv4 "aws:amz:ap-northeast-1:s3" \
    https://dts-cloud-edge.wator.xyz/ 
 ```



