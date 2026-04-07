# otmc.dts spire server on cloud twin
## Description
Setup spire on cloud twin to enable secure communication between devices and cloud twin.



## Upstream ca
### 生成 Upstream ca 证书
```bash
mkdir -p /opt/otmc/secret/spire-server/ca/
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out /opt/otmc/secret/spire-server/ca/upstream-root-ca.key
openssl req -x509 -new -nodes \
  -key /opt/otmc/secret/spire-server/ca/upstream-root-ca.key \
  -subj "/C=CN/ST=Tokyo/L=Tokyo/O=Wator/CN=SPIRE Upstream CA" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "basicConstraints = critical, CA:TRUE" \
  -days 3650 -out /opt/otmc/secret/spire-server/ca/upstream-root-ca.crt
cat /opt/otmc/secret/spire-server/ca/upstream-root-ca.crt > /opt/otmc/secret/spire-server/ca/upstream-root-bundle.pem

# 生成中间 密钥
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out /opt/otmc/secret/spire-server/ca/upstream-intermediate-ca.key
# 生成中间 CA 证书请求（CSR）
openssl req -new -key /opt/otmc/secret/spire-server/ca/upstream-intermediate-ca.key \
  -subj "/C=CN/ST=Tokyo/L=Tokyo/O=Wator/CN=SPIRE Upstream Intermediate CA" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "basicConstraints = critical, CA:TRUE" \
  -out /opt/otmc/secret/spire-server/ca/upstream-intermediate-ca.csr
# 生成中间 CA 证书
openssl x509 -req -in /opt/otmc/secret/spire-server/ca/upstream-intermediate-ca.csr \
  -CA /opt/otmc/secret/spire-server/ca/upstream-root-ca.crt \
  -CAkey /opt/otmc/secret/spire-server/ca/upstream-root-ca.key \
  -CAcreateserial \
  -copy_extensions copy -days 3650 \
  -days 3650 -out /opt/otmc/secret/spire-server/ca/upstream-intermediate-ca.crt
cat /opt/otmc/secret/spire-server/ca/upstream-intermediate-ca.crt > /opt/otmc/secret/spire-server/ca/upstream-intermediate-bundle.pem

```


## x509pop ca
### 生成 x509pop ca 证书
```bash
mkdir -p /opt/otmc/secret/spire-server/ca/
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out /opt/otmc/secret/spire-server/ca/x509pop-root-ca.key
openssl req -x509 -new -nodes \
  -key /opt/otmc/secret/spire-server/ca/x509pop-root-ca.key \
  -subj "/C=CN/ST=Tokyo/L=Tokyo/O=Wator/CN=SPIRE X509POP CA" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "basicConstraints = critical, CA:TRUE" \
  -days 3650 -out /opt/otmc/secret/spire-server/ca/x509pop-root-ca.crt

# 生成中间 密钥
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.key
# 生成中间 证书
openssl req -new -nodes \
  -key /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.key \
  -subj "/C=CN/ST=Tokyo/L=Tokyo/O=Wator/CN=SPIRE X509POP Intermediate CA" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "basicConstraints = critical, CA:TRUE" \
  -out /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.csr
# 签名中间 证书
openssl x509 -req -in /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.csr \
  -CA /opt/otmc/secret/spire-server/ca/x509pop-root-ca.crt \
  -CAkey /opt/otmc/secret/spire-server/ca/x509pop-root-ca.key \
  -copy_extensions copy -days 3650 \
  -out /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.crt

cat /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.crt \
    /opt/otmc/secret/spire-server/ca/x509pop-root-ca.crt \
    > /opt/otmc/secret/spire-server/ca/x509pop-ca-bundle.pem
```
### 签名 x509pop Agent Leaf 证书
```bash
# 签名 leaf 证书
openssl x509 -req -in /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf-701bc7b1c33e54a00c9a0c6271c5173baf522a7b.csr \
  -CA /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.crt \
  -CAkey /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.key \
  -copy_extensions copy -days 3650 \
  -out /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf-701bc7b1c33e54a00c9a0c6271c5173baf522a7b.crt

cat /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf-701bc7b1c33e54a00c9a0c6271c5173baf522a7b.crt \
    /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.crt \
    > /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf-701bc7b1c33e54a00c9a0c6271c5173baf522a7b-full.pem

# 检查 leaf 证书
openssl x509 -in /opt/otmc/secret/spire-agent/certs/x509pop-agent-leaf-701bc7b1c33e54a00c9a0c6271c5173baf522a7b-full.pem -text -noout | grep -A1 "X509v3 Key Usage"
            X509v3 Key Usage: critical
                Digital Signature
                Key Encipherment
```



## 从 SPIRE Server 导出 bootstrap CA
```bash
docker exec -it dts-cloudTwin-spire-server /opt/spire/bin/spire-server bundle show -format pem 
```

## 给Agent发放 X509-SVID
### 列出再服务器上登录的agent
```bash
docker exec dts-cloudTwin-spire-server /opt/spire/bin/spire-server agent list
Found 1 attested agent:

SPIFFE ID         : spiffe://spiffe.wator.xyz/spire/agent/x509pop/77e9a7a82046bfd11168abebf29afcfad82f30c9
Attestation type  : x509pop
Expiration time   : 2026-04-07 12:45:29 +0900 JST
Serial number     : 312507295029033084434768995540504819511
Can re-attest     : true
```
### 根据上面的SPIFFE ID 创建SVID

```bash
docker exec dts-cloudTwin-spire-server /opt/spire/bin/spire-server entry create \
     -spiffeID spiffe://spiffe.wator.xyz/bucket/sync/workload \
     -parentID spiffe://spiffe.wator.xyz/spire/agent/x509pop/77e9a7a82046bfd11168abebf29afcfad82f30c9\
     -selector unix:uid:0
Entry ID         : 46fa22fe-ff23-4feb-8546-419d53f34137
SPIFFE ID        : spiffe://spiffe.wator.xyz/bucket/sync/workload
Parent ID        : spiffe://spiffe.wator.xyz/spire/agent/x509pop/77e9a7a82046bfd11168abebf29afcfad82f30c9
Revision         : 0
X509-SVID TTL    : default
JWT-SVID TTL     : default
Selector         : unix:uid:0
```
### 列出所有SVID
```bash
docker exec dts-cloudTwin-spire-server /opt/spire/bin/spire-server entry show
```
### 删除SVID
```bash
docker exec dts-cloudTwin-spire-server /opt/spire/bin/spire-server entry delete \
     -entryID e8d608e1-93dd-498e-bfad-dd0f49294ec0
```
