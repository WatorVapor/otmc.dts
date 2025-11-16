＃!/bin/bash
docker exec -it dts-minio /bin/bash -c "mc alias set dts-builtin http://dts-minio:9000 7NMF6I2FWHAA22AUAEC9 72ULbn40iz+yEFqXkQ3mHuW6LoP9CsxwZv+UzyJW"
# docker exec -it dts-minio /bin/bash -c "mc rb dts-builtin/my-bucket"
# docker exec -it dts-minio /bin/bash -c "mc rb dts-builtin/dts-system-bucket"
# docker exec -it dts-minio /bin/bash -c "mc rb dts-builtin/dts-system"


