＃!/bin/bash
docker exec -it dts-minio /bin/bash -c "mc alias set dts-builtin http://dts-minio:9000 7NMF6I2FWHAA22AUAEC9 72ULbn40iz+yEFqXkQ3mHuW6LoP9CsxwZv+UzyJW"
docker exec -it dts-minio /bin/bash -c "mc ls dts-builtin/dts-system-setting || mc mb dts-builtin/dts-system-setting"
docker exec -it dts-minio /bin/bash -c "mc anonymous set private dts-builtin/dts-system-setting"
docker exec -it dts-minio /bin/bash -c "echo '{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action\": [\"s3:*\"],\"Resource\": [\"arn:aws:s3:::dts-system-setting\",\"arn:aws:s3:::dts-system-setting/*\"]}]}' > /tmp/dts-repo-rw.json && mc admin policy create dts-builtin dts-builtin-system-admin /tmp/dts-repo-rw.json"
docker exec -it dts-minio /bin/bash -c "mc ls dts-builtin/dts-docker-repository || mc mb dts-builtin/dts-docker-repository"
docker exec -it dts-minio /bin/bash -c "mc anonymous set private dts-builtin/dts-docker-repository"
docker exec -it dts-minio /bin/bash -c "echo '{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action\": [\"s3:*\"],\"Resource\": [\"arn:aws:s3:::dts-docker-repository\",\"arn:aws:s3:::dts-docker-repository/*\"]}]}' > /tmp/dts-repo-rw.json && mc admin policy create dts-builtin dts-builtin-mirror /tmp/dts-repo-rw.json"

