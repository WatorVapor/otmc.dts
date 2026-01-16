# otmc.dts
DigitalTwinStore (DTS) is an edge-to-cloud distributed object storage solution designed for robots, Iot Gateway, and other intelligent devices. It enables seamless synchronization between physical devices and their digital twins, providing secure, reliable, and high-performance storage for critical data.

## Default users on dts
- dts-config: The default user for configuration. It has readwrite access to dts-self-configure bucket.
- dts-rclone: The default user for rclone. It has readwrite access to all buckets.
- dts-docker-registry: The default user for docker registry. It has readwrite access to the `dts-docker-registry` bucket.
- dts-builtin: The default user for built-in applications. It has readwrite access to all buckets.
## Default bucket on dts
- dts-self-configure: The default bucket for self-configure. It is used to store the configuration files of the devices.
- dts-self-docker-registry: The default bucket for docker registry. It is used to store the docker images of the devices.
- dts-application-docker-registry: The default bucket for docker registry. It is used to store the docker images of the applications.
