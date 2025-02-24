# Nexa Bootstrap - Docker Usage

## Docker Run Command (general usage)

docker run -d -p <host_port>:443 \
  -e SSL_ENABLED=<true|false> \
  -e SSL_KEY_PATH=<path_to_private_key> \
  -e SSL_CRT_PATH=<path_to_certificate> \
  -v <host_ssl_folder>:<container_ssl_folder>:ro \
  -e DB_PATH="<database_file_path>" \
  -v <volume_name_or_host_path>:<data_path_in_container> \
  --name Nexa-bootstrap \
    nexa-bootstrap:latest

## Arguments Explanation

- `-p <host_port>:443`  
  Maps container port (443 by default for HTTPS) to a specified host port.

- `-e SSL_ENABLED=<true|false>`  
  Enables (`true`) or disables (`false`) SSL. Default is `false`.