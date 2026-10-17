#ifndef AURA_SNI_FIREWALL_H
#define AURA_SNI_FIREWALL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum
{
    AURA_TLS_SNI_INCOMPLETE = 0,
    AURA_TLS_SNI_ALLOWED = 1,
    AURA_TLS_SNI_BLOCKED = 2,
    AURA_TLS_SNI_MALFORMED = 3
} AuraTlsSniResult;

/* Flags reported by aura_inspect_tls_client_hello(). */
#define AURA_TLS_FLAG_ECH 0x1u    /* encrypted_client_hello (0xfe0d) present */
#define AURA_TLS_FLAG_NO_SNI 0x2u /* ClientHello without server_name */

AuraTlsSniResult aura_inspect_tls_client_hello (const uint8_t *payload,
                                               uint32_t payload_len,
                                               char *sni, size_t sni_capacity,
                                               uint32_t *flags);

AuraTlsSniResult aura_inspect_tls_sni (const uint8_t *payload,
                                      uint32_t payload_len, char *sni,
                                      size_t sni_capacity);
bool aura_should_block_tls_sni (const uint8_t *payload, uint32_t payload_len);
int aura_add_dynamic_sni_rule (const char *domain);
int aura_set_dynamic_sni_allowlist (const char *const *domains, size_t count);

#endif
