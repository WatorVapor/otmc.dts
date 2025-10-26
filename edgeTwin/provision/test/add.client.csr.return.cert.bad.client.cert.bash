curl -X POST \
    -H "Content-Type: text/plain" \
    --data-binary @ssl/client.csr \
    --cacert /opt/secure/dts/provision/factory/ssl/rootca.crt \
    https://127.0.0.1:9443/api/v1/provision/add/client/cert