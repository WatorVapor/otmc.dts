# otmc.dts edge twin rustfs object storage
## the default uses 
  ```bash
    docker exec -it dts-edge-rc rc alias set dts-edge-storage http://dts-rustfs:9000 ${RUSTFS_ACCESS_KEY} ${RUSTFS_SECRET_KEY}
    docker exec -it dts-edge-rc rc admin user add dts-edge-storage ${DTS_BUILTIN_APP_USER} ${DTS_BUILTIN_APP_SECRET_KEY}
    docker exec -it dts-edge-rc rc admin user enable dts-edge-storage ${DTS_BUILTIN_APP_USER}
    docker exec -it dts-edge-rc rc admin user list dts-edge-storage
  ```
