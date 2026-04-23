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

#include <nx_secure_tls_api.h>
#include <stdbool.h>
/******************************************************
 *                      Macros
 ******************************************************/

/******************************************************
 *                    Typedefs
 ******************************************************/

/* IMPLEMENTATION NOTE: Core supplicant implementation should not access any of the structure members defined in this file */

typedef NX_SECURE_TLS_SESSION cy_tls_session_t;
typedef NX_SECURE_X509_CERT   cy_x509_crt_t;
typedef NX_SECURE_TLS_SESSION cy_tls_workspace_t;

typedef struct
{
    NX_SECURE_X509_CERT     certificate;
    uint8_t                 *certificate_der;
    uint8_t                 *private_key_der;
    uint8_t                 is_client_auth;
} cy_tls_identity_t;

typedef struct
{
    void                    *usr_data;
    char                    *peer_cn;
    cy_tls_session_t        *session;
    cy_tls_workspace_t      context;
    cy_tls_identity_t       *identity;
    cy_x509_crt_t           *root_ca_certificates;
    uint8_t                 *root_ca_cert_der;
    int8_t                  *tls_metadata;
    uint8_t                 *tls_packet_buffer;
    uint8_t                 *certificate_buffer;
    int32_t                 resume;
    bool                    tls_handshake_successful;
    bool                    tls_v13;
    uint8_t                 expected_pkt_count;
} cy_tls_context_t;

#ifdef __cplusplus
} /*extern "C" */
#endif
