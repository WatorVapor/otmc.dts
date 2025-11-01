#!/bin/bash
# 使用 openssl 生成 ECDSA 客户端私钥 ssl/cluster.client.key.pem，并确保输出为 PEM 格式且包含私钥
openssl ecparam -genkey -name prime256v1 -noout -out ssl/cluster.client.key.pem
# 可选：确保私钥文件权限安全
chmod 600 ssl/cluster.client.key.pem
# 使用 openssl 生成 ECDSA 客户端 CSR ssl/cluster.client.csr
openssl req -new -key ssl/cluster.client.key.pem -out ssl/cluster.client.csr -subj "/CN=cluster.client"

# 发送 CSR 并获取证书
curl -X POST \
    -H "Content-Type: text/plain" \
    --data-binary @ssl/cluster.client.csr \
    --cert /opt/secure/dts/provision/factory/ssl/client.crt \
    --key /opt/secure/dts/provision/factory/keys/client.key.pem \
    --cacert /opt/secure/dts/provision/factory/ssl/rootca.crt \
    -o ssl/cluster.client.crt \
    https://127.0.0.1:9443/api/v1/cluster/add/client/cert

