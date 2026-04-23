/*
 * (c) 2026, Infineon Technologies AG, or an affiliate of Infineon
 * Technologies AG. All rights reserved.
 * This software, associated documentation and materials ("Software") is
 * owned by Infineon Technologies AG or one of its affiliates ("Infineon")
 * and is protected by and subject to worldwide patent protection, worldwide
 * copyright laws, and international treaty provisions. Therefore, you may use
 * this Software only as provided in the license agreement accompanying the
 * software package from which you obtained this Software. If no license
 * agreement applies, then any use, reproduction, modification, translation, or
 * compilation of this Software is prohibited without the express written
 * permission of Infineon.
 *
 * Disclaimer: UNLESS OTHERWISE EXPRESSLY AGREED WITH INFINEON, THIS SOFTWARE
 * IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING, BUT NOT LIMITED TO, ALL WARRANTIES OF NON-INFRINGEMENT OF
 * THIRD-PARTY RIGHTS AND IMPLIED WARRANTIES SUCH AS WARRANTIES OF FITNESS FOR A
 * SPECIFIC USE/PURPOSE OR MERCHANTABILITY.
 * Infineon reserves the right to make changes to the Software without notice.
 * You are responsible for properly designing, programming, and testing the
 * functionality and safety of your intended application of the Software, as
 * well as complying with any legal requirements related to its use. Infineon
 * does not guarantee that the Software will be free from intrusion, data theft
 * or loss, or other breaches ("Security Breaches"), and Infineon shall have
 * no liability arising out of any Security Breaches. Unless otherwise
 * explicitly approved by Infineon, the Software may not be used in any
 * application where a failure of the Product or any consequences of the use
 * thereof can reasonably be expected to result in personal injury.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "ssl.h"

#include "ctr_drbg.h"
#include "entropy.h"
#include "cipher.h"

#include "cy_md4.h"
#include "mbedtls/sha1.h"
#include "mbedtls/des.h"
#include "mbedtls/version.h"

/******************************************************
 *                      Macros
 ******************************************************/

#define TLS_RANDOM_BYTES                         (64)
#define TLS_SERVER_RANDOM_BYTES                  (32)
#define TLS_CLIENT_RANDOM_BYTES                  (32)
#define TLS_MASTER_SECRET_BYTES                  (48)
#define TLS_SERVER_VERSION_LEN                   (2)
#define BUFFER_SIZE                              (1600)
#define MBEDTLS_MAJOR_VERSION_3     (3)
#define MBEDTLS_MAJOR_VERSION_2     (2)

#define MBEDTLS_VERSION_WITH_PRF_SUPPORT         (0x02130000) /* mbedTLS version 2.19.0 where PRF support is added. */

#if ((MBEDTLS_VERSION_NUMBER >= 0x03000000) && (MBEDTLS_VERSION_MAJOR == 3))
#define MBEDTLS_MEMBER(state) MBEDTLS_PRIVATE(state)
#else
#define MBEDTLS_MEMBER(state) state
#endif
/******************************************************
 *                    Typedefs
 ******************************************************/

/* IMPLEMENTATION NOTE: Core supplicant implementation should not access any of the structure members defined in this file */
typedef struct mbedtls_ssl_context cy_tls_workspace_t;
typedef struct mbedtls_ssl_session cy_tls_session_t;
typedef struct mbedtls_x509_crt cy_x509_crt_t;
typedef struct mbedtls_pk_context cy_pk_context_t;
typedef struct mbedtls_entropy_context cy_entropy_context_t;
typedef struct mbedtls_ctr_drbg_context cy_ctr_drbg_context_t;
typedef struct mbedtls_ssl_config cy_ssl_config_t;

typedef struct
{
    cy_pk_context_t private_key;
    cy_x509_crt_t certificate;
    uint8_t is_client_auth;
} cy_tls_identity_t;

typedef struct eap_tls_keys
{
    uint8_t master_secret[TLS_MASTER_SECRET_BYTES];
    uint8_t randbytes[TLS_RANDOM_BYTES];
#if (MBEDTLS_VERSION_NUMBER > MBEDTLS_VERSION_WITH_PRF_SUPPORT)
    mbedtls_tls_prf_types tls_prf_type;
#else
    int32_t  (*supplicant_tls_prf)(const uint8_t *, size_t, const int8_t *,
                    const uint8_t *, size_t,
                    uint8_t *, size_t);
#endif
    int32_t resume;
} eap_tls_keys;


typedef struct
{
    void                    *usr_data;
    char                    *peer_cn;
    cy_tls_session_t        *session; /* This session pointer is only used to resume connection for client, If application/library wants to resume connection it needs to pass pointer of previous stored session */
    cy_tls_workspace_t      context;
    cy_tls_identity_t       *identity;
    cy_x509_crt_t           *root_ca_certificates; /* Context specific root-ca-chain */
    cy_entropy_context_t    entropy;
    cy_ctr_drbg_context_t   ctr_drbg;
    cy_ssl_config_t         conf;
    int                     resume;
    eap_tls_keys            eap_tls_keying;
    uint8_t                 tls_v13;

    /* Book-keeping information used for in-house use of TLS-security library */
    uint8_t                 buffered_data[BUFFER_SIZE];
    uint8_t                 *buffer_to_use;
    uint32_t                remaining_bytes;
    uint32_t                bytes_consumed;
    uint32_t                total_bytes;
} cy_tls_context_t;


#ifdef __cplusplus
} /*extern "C" */
#endif
