# otmc.dts spire server on cloud twin
## Description
Setup spire on cloud twin to enable secure communication between devices and cloud twin.

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
  -days 3650 -out /opt/otmc/secret/spire-server/ca/x509pop-root-ca.crt

# 生成中间 密钥
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -out /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.key
# 生成中间 证书
openssl req -new -nodes \
  -key /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.key \
  -subj "/C=CN/ST=Tokyo/L=Tokyo/O=Wator/CN=SPIRE X509POP Intermediate CA" \
  -out /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.csr
# 签名中间 证书
openssl x509 -req -in /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.csr \
  -CA /opt/otmc/secret/spire-server/ca/x509pop-root-ca.crt \
  -CAkey /opt/otmc/secret/spire-server/ca/x509pop-root-ca.key \
  -days 3650 -out /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.crt

cat /opt/otmc/secret/spire-server/ca/x509pop-root-ca.crt \
    /opt/otmc/secret/spire-server/ca/x509pop-intermediate-ca.crt \
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


