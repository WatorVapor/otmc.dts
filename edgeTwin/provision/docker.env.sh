#!/bin/bash
SCRIPT_DIR=$(cd $(dirname $0); pwd)
PARENT_DIR=$(dirname $SCRIPT_DIR)
GPARENT_DIR=$(dirname $PARENT_DIR)
BASE_NAME=$(basename $SCRIPT_DIR)
PARENT_NAME=$(basename $PARENT_DIR)
GPARENT_NAME=$(basename $GPARENT_DIR)
echo "SCRIPT_DIR:=${SCRIPT_DIR}"
echo "PARENT_DIR:=${PARENT_DIR}"
echo "GPARENT_DIR:=${GPARENT_DIR}"
DOCKER_MAME=${GPARENT_NAME}-${PARENT_NAME}-${BASE_NAME}
docker stop ${DOCKER_MAME}
docker rm ${DOCKER_MAME}
read -d ''  DOCKER_NODE << EOF
docker run -it
  -v /etc/group:/etc/group:ro 
  -v /etc/passwd:/etc/passwd:ro 
  -v /dev/shm/:/dev/shm/
  -v /var/run/:/var/run/
  -v /opt/otmc/:/opt/otmc/
  -v ${GPARENT_DIR}:${GPARENT_DIR} 
  -v ${HOME}:${HOME} 
  -u $(id -u $USER):$(id -g $USER) 
  -w ${SCRIPT_DIR} 
  --net host 
  --privileged
  --group-add dialout
  --memory=256M 
  --cpu-shares=128 
  --name ${DOCKER_MAME} 
  node:24
EOF

read -d ''  DOCKER_NODE_BG << EOF
docker run -d
  -v /etc/group:/etc/group:ro 
  -v /etc/passwd:/etc/passwd:ro 
  -v /dev/shm/:/dev/shm/ 
  -v /var/run/:/var/run/
  -v /opt/otmc/:/opt/otmc/
  -v ${GPARENT_DIR}:${GPARENT_DIR} 
  -v ${HOME}:${HOME} 
  -u $(id -u $USER):$(id -g $USER) 
  -w ${SCRIPT_DIR} 
  --restart always
  --net host 
  --privileged
  --group-add dialout
  --memory=256M 
  --cpu-shares=128 
  --name ${DOCKER_MAME} 
  node:24
EOF

