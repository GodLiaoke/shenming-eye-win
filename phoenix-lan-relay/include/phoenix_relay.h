#ifndef PHOENIX_RELAY_H
#define PHOENIX_RELAY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t phoenix_relay_start(
    const char *upstream_host,
    uint16_t upstream_port,
    const char *username,
    const char *password,
    const char *local_username,
    const char *local_password,
    uint16_t local_port
);
void phoenix_relay_set_force_all_upstream(int32_t enabled);
void phoenix_relay_stop(void);
int32_t phoenix_relay_is_running(void);
size_t phoenix_relay_client_count(void);

#ifdef __cplusplus
}
#endif

#endif
