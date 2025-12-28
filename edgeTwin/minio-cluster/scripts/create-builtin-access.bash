＃!/bin/bash
docker exec -it dts-mc /bin/bash -c "mc alias set dts-minio http://dts-minio:9000 dts-minioadmin MLmibutA6uBCAMxV"
docker exec -it dts-mc /bin/bash -c "mc admin user add dts-minio dts-builtin tZpNRpGFCQygmbfe"
docker exec -it dts-mc /bin/bash -c "mc admin policy attach dts-minio readwrite --user=dts-builtin"
docker exec -it dts-mc /bin/bash -c "mc admin user info dts-minio dts-builtin"
docker exec -it dts-mc /bin/bash -c "mc admin accesskey create dts-minio dts-builtin" > dts-builtin.access.txt

docker exec -it dts-mc /bin/bash -c "mc admin user add dts-minio dts-builtin-sync tZpNRpGFCQygmbfe"
docker exec -it dts-mc /bin/bash -c "mc admin policy attach dts-minio readwrite --user=dts-builtin-sync"
docker exec -it dts-mc /bin/bash -c "mc admin user info dts-minio dts-builtin-sync"
docker exec -it dts-mc /bin/bash -c "mc admin accesskey create dts-minio dts-builtin-sync" > dts-builtin-sync.access.txt


