#ifndef PHOENIX_CLOUD_RELAY_H
#define PHOENIX_CLOUD_RELAY_H

#include <stdint.h>
#include <stddef.h>

int32_t phoenix_cloud_relay_start(
    const char *upstream_host,
    uint16_t upstream_port,
    const char *upstream_username,
    const char *upstream_password,
    const char *local_username,
    const char *local_password,
    uint16_t local_port
);

void phoenix_cloud_relay_stop(void);
int32_t phoenix_cloud_relay_is_running(void);
size_t phoenix_cloud_relay_client_count(void);

#endif
