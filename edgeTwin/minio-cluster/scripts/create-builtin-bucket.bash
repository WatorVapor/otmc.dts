＃!/bin/bash
docker exec -it dts-mc /bin/bash -c "mc alias set dts-builtin http://dts-minio:9000 7NMF6I2FWHAA22AUAEC9 72ULbn40iz+yEFqXkQ3mHuW6LoP9CsxwZv+UzyJW"
docker exec -it dts-mc /bin/bash -c "mc ls dts-builtin/dts-system-setting || mc mb dts-builtin/dts-system-setting"
docker exec -it dts-mc /bin/bash -c "mc anonymous set private dts-builtin/dts-system-setting"
docker exec -it dts-mc /bin/bash -c "mc ls dts-builtin/dts-docker-repository || mc mb dts-builtin/dts-docker-repository"
docker exec -it dts-mc /bin/bash -c "mc anonymous set private dts-builtin/dts-docker-repository"

