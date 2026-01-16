＃!/bin/bash
docker exec -it dts-mc /bin/bash -c "mc alias set dts-minio http://dts-minio:9000 dts-minioadmin MLmibutA6uBCAMxV"
docker exec -it dts-mc /bin/bash -c "mc admin user add dts-minio dts-rclone tGsxPAdOY0XnKM1x"
docker exec -it dts-mc /bin/bash -c "mc admin policy attach dts-minio readwrite --user=dts-rclone"
docker exec -it dts-mc /bin/bash -c "mc admin user info dts-minio dts-rclone"
docker exec -it dts-mc /bin/bash -c "mc admin accesskey create dts-minio dts-rclone" > dts-rclone.access.txt
