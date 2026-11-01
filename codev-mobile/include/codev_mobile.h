#include <stddef.h>
#ifndef CODEV_MOBILE_H
#define CODEV_MOBILE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Start (or restart) the in-process CodeV live proxy engine.
 *
 * data_dir        writable directory for config + credential + capture files.
 * advertised_host LAN address the SOCKS5 proxy advertises (may be NULL).
 *
 * Returns a newly allocated NUL-terminated JSON string that the caller MUST
 * release with codev_engine_string_free(). On success:
 *   {"ok":true,"username":..,"password":..,"panelToken":..,"panelURL":..}
 * On failure:
 *   {"ok":false,"error":".."}
 */
char *codev_engine_start(const char *data_dir, const char *advertised_host);

/* Stop the engine and release its listeners. Safe to call repeatedly. */
void codev_engine_stop(void);

/* Run a redacted, layered proxy self-check. The returned JSON contains
 * listener/socks_handshake/dns/tcp/udp states and no credentials. */
char *codev_engine_diagnostics(const char *username, const char *password);

/* 直连卡密平台（T3）验证。返回 JSON: {"ok":true,...} 或 {"ok":false,"error":".."}；
 * 返回的字符串同样用 codev_engine_string_free() 释放。 */
char *codev_verify_card(const char *card, const char *device_id);

/* 验证进行到哪一段（中文短句，静态字符串，无需释放）。 */
const char *codev_verify_stage(void);

/* Release a string returned by codev_engine_start(). NULL is ignored. */
void codev_engine_string_free(char *value);

/* S3：用与引擎完全相同的解密管线解一份 pcap，产出坐标 JSONL + meta。
 * 成功返回 {"ok":true,"coordinate_records":..,"map_id":..,...}，
 * 失败返回 {"ok":false,"error":".."}。返回的字符串用 codev_engine_string_free 释放。 */
char *codev_decode_pcap(const char *pcap_path, const char *out_path);

/* S2：用云端下发的会话密钥解开字段字典（ChaCha20 + HMAC-SHA256）。
 * 成功返回字典明文 JSON；失败返回 {"ok":false,"error":".."}。
 * 返回的字符串用 codev_engine_string_free 释放。 */
char *codev_open_dictionary(const char *session_key_b64, const char *nonce_b64,
                            const char *blob_b64, const char *tag_b64);

/* S2：把解开的字段字典注入引擎。**可重复调用**（会话密钥每 35 分钟轮换，
 * 轮换后必须重新注入新会话加密的字典）。
 * 返回 1=写入成功，-1=参数非法。 */
int codev_set_dictionary(const char *json, size_t len);

/* S2：清除运行时字典，回退到编译期内嵌字典（会话到期续期失败时止损）。 */
void codev_clear_dictionary(void);

/* S2：1=已注入运行时字典，0=仍在使用内嵌字典。 */
int codev_dictionary_is_injected(void);

/* Start/stop the single-device iOS packet tunnel bridge.
 * tun_fd is one end of a Unix socketpair owned by the Packet Tunnel
 * extension. Packets are length-framed (u32 big-endian + raw IP packet).
 * The bridge sends those packets through the local CodevMobile SOCKS5 proxy.
 * Returns 0 when the bridge task was scheduled, -1 for invalid arguments. */
int codev_tunnel_start(int tun_fd, const char *username, const char *password);
void codev_tunnel_stop(void);



#ifdef __cplusplus
}
#endif

#endif /* CODEV_MOBILE_H */
