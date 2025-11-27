＃!/bin/bash
docker exec -it dts-minio /bin/bash -c "mc alias set dts-minio-admin http://dts-minio:9000 dts-minioadmin MLmibutA6uBCAMxV"
docker exec -it dts-minio /bin/bash -c "echo '{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action\": [\"s3:*\"],\"Resource\": [\"arn:aws:s3:::dts-system-setting\",\"arn:aws:s3:::dts-system-setting/*\"]}]}' > /tmp/dts-repo-rw.json && mc admin set dts-minio-admin dts-builtin-system-admin /tmp/dts-repo-rw.json"
docker exec -it dts-minio /bin/bash -c "echo '{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action\": [\"s3:*\"],\"Resource\": [\"arn:aws:s3:::dts-docker-repository\",\"arn:aws:s3:::dts-docker-repository/*\"]}]}' > /tmp/dts-repo-rw.json && mc admin set dts-minio-admin dts-builtin-mirror /tmp/dts-repo-rw.json"

