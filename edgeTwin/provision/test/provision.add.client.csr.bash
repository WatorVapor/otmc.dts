#!/bin/bash
# 使用 openssl 生成 ECDSA 客户端私钥 ssl/provision.client.key.pem，并确保输出为 PEM 格式且包含私钥
openssl ecparam -genkey -name prime256v1 -noout -out ssl/provision.client.key.pem
# 可选：确保私钥文件权限安全
chmod 600 ssl/provision.client.key.pem
# 使用 openssl 生成 ECDSA 客户端 CSR ssl/provision.client.csr
openssl req -new -key ssl/provision.client.key.pem -out ssl/provision.client.csr -subj "/CN=provision.client"

# 发送 CSR 并获取证书
curl -X POST \
    -H "Content-Type: text/plain" \
    --data-binary @ssl/provision.client.csr \
    --cert /opt/secure/dts/provision/factory/ssl/client.crt \
    --key /opt/secure/dts/provision/factory/keys/client.key.pem \
    --cacert /opt/secure/dts/provision/factory/ssl/rootca.crt \
    -o ssl/provision.client.crt \
    https://127.0.0.1:9443/api/v1/provision/add/client/cert

# 检查健康状态
curl -X GET \
    --cert ssl/provision.client.crt \
    --key ssl/provision.client.key.pem \
    --cacert /opt/secure/dts/provision/factory/ssl/rootca.crt \
    https://127.0.0.1:9443/api/v1/health | jq .

# 测试无证书请求
curl -X POST \
    -H "Content-Type: text/plain" \
    --data-binary @ssl/provision.client.csr \
    --cacert /opt/secure/dts/provision/factory/ssl/rootca.crt \
    https://127.0.0.1:9443/api/v1/provision/add/client/cert