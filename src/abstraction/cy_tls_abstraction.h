/*
 * Copyright 2019, Cypress Semiconductor Corporation or a subsidiary of
 * Cypress Semiconductor Corporation. All Rights Reserved.
 *
 * This software, including source code, documentation and related
 * materials ("Software"), is owned by Cypress Semiconductor Corporation
 * or one of its subsidiaries ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products. Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "cy_tls_stack_specific.h"
#include "cy_supplicant_result.h"
#include "trng_api.h"

/******************************************************
 *                      Macros
 ******************************************************/
#define TLS_WRAPPER_DEBUG( x )  //printf x
#define TLS_WRAPPER_INFO( x )   //printf x

/******************************************************
 *                      Constants
 ******************************************************/
#define TLS_RANDOM_BYTES                         (64)
#define TLS_MASTER_SECRET_BYTES                  (48)
#define BUFFER_SIZE                              (1600)

/******************************************************
 *                      Enums
 ******************************************************/
typedef enum
{
    CY_TRUE = 0,
    CY_FALSE
} cy_bool_t;

typedef enum
{
    TLS_NO_VERIFICATION = 0,
    TLS_VERIFICATION_OPTIONAL = 1,
    TLS_VERIFICATION_REQUIRED = 2,
} cy_tls_certificate_verification_t;

/******************************************************
 *                      Typedefs
 ******************************************************/
typedef struct eap_tls_keys
{
    unsigned char master_secret[TLS_MASTER_SECRET_BYTES];
    unsigned char randbytes[TLS_RANDOM_BYTES];
    mbedtls_tls_prf_types tls_prf_type;
    int resume;
} eap_tls_keys;

typedef struct
{
    void *usr_data;
    char* peer_cn;
    cy_tls_session_t *session; /* This session pointer is only used to resume connection for client, If application/library wants to resume connection it needs to pass pointer of previous stored session */
    cy_tls_workspace_t context;
    cy_tls_identity_t *identity;
    cy_x509_crt_t *root_ca_certificates; /* Context specific root-ca-chain */
    cy_entropy_context_t entropy;
    cy_ctr_drbg_context_t ctr_drbg;
    cy_ssl_config_t conf;
    int resume;
    eap_tls_keys eap_tls_keying;

    /* Book-keeping information used for in-house use of TLS-security library */
    uint8_t buffered_data[BUFFER_SIZE];
    uint8_t* buffer_to_use;
    uint32_t remaining_bytes;
    uint32_t bytes_consumed;
    uint32_t total_bytes;
} cy_tls_context_t;

/******************************************************
 *                      Function Prototypes
 ******************************************************/
/** Initializes TLS context handle
 *
 * @param[in] context   : A pointer to a cy_tls_context_t context object that will be initialized.
 *                       The context object is analogous to a cookie which has all the information to process a TLS message.
 *                       This is the entity that has all the book-keeping information (TLS handshake state, TLS session etc.).
 * @param[in]  identity : A pointer to a cy_tls_identity_t object initialized with @ref cy_tls_init_identity.
 * @param[in]  peer_cn  : Expected peer CommonName (or NULL)
 *
 * @return cy_rslt_t    : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
cy_rslt_t cy_tls_init_context( cy_tls_context_t* context, cy_tls_identity_t* identity, char* peer_cn );

/** De-initialize a previously initialized TLS context
 *
 * @param[in] context : A pointer to a cy_tls_context_t context object
 *
 * @return cy_rslt_t  : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
cy_rslt_t cy_tls_deinit_context( cy_tls_context_t* context );

/** Initialize the trusted root CA certificates specific to the TLS context.
 *
 * @param[in] context                 : A pointer to a cy_tls_context_t context object
 * @param[in] trusted_ca_certificates : A chain of x509 certificates in PEM or DER format.
 *                                      This chain of certificates comprise the public keys of the signing authorities.
 *                                      During the handshake, these public keys are used to verify the authenticity of the peer
 * @param[in] length                  : Certificate length
 *
 * @return cy_rslt_t    : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
cy_rslt_t cy_tls_init_root_ca_certificates( cy_tls_context_t* context, const char* trusted_ca_certificates, const uint32_t length );

/** De-initialise the trusted root CA certificates of the context
 *
 * @param[in] context  : A pointer to a cy_tls_context_t context object
 *
 * @return cy_rslt_t   : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
cy_rslt_t cy_tls_deinit_root_ca_certificates( cy_tls_context_t* context );

/** Initializes a TLS identity using a supplied certificate and private key
 *
 * @param[in]  identity           : A pointer to a cy_tls_identity_t object that will be initialized
 *                                  The identity is a data structure that encompasses the device's own certificate/key.
 * @param[in]  private_key        : The server private key in binary format. This key is used to sign the handshake message
 * @param[in]  key_length         : Private key length
 * @param[in]  certificate_data   : The server x509 certificate in PEM or DER format
 * @param[in]  certificate_length : The length of the certificate
 *
 * @return cy_rslt_t              : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
cy_rslt_t cy_tls_init_identity( cy_tls_identity_t* identity, const char* private_key, const uint32_t key_length, const uint8_t* certificate_data, uint32_t certificate_length );

/** DeiInitializes a TLS identity
 *
 * @param[in] identity    : A pointer to a cy_tls_identity_t object that will be de-initialised
 *
 * @return cy_rslt_t      : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
cy_rslt_t cy_tls_deinit_identity( cy_tls_identity_t* tls_identity );

/** Start TLS on a TCP Connection with a particular set of cipher suites
 *
 * Start Transport Layer Security (successor to SSL) on a TCP Connection
 *
 * @param[in,out] tls_context  : The tls context to work with
 * @param[in,out] referee      : Transport reference - e.g. TCP socket or EAP context
 * @param[in]     verification : Indicates whether to verify the certificate chain against a root server.
 *
 * @return cy_rslt_t      : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 */
cy_rslt_t cy_tls_generic_start_tls_with_ciphers( cy_tls_context_t* tls_context, void* referee, cy_tls_certificate_verification_t verification );

/**
 * @brief   This function uses CTR_DRBG to generate random data.
 *
 * @note    The function automatically reseeds if the reseed counter is exceeded.
 *
 * @param[in] tls_context  :  The tls context to work with
 * @param output           :  The buffer to fill.
 * @param output_len       :  The length of the buffer.
 *
 * @return cy_rslt_t  : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
cy_rslt_t cy_crypto_get_random( cy_tls_context_t *context, void* buffer, uint16_t buffer_length );

/**
 * This function is used to generated mppe key using tls_prf (Pseudo-random)function.
 * For more information refer to TLS specification.
 *
 * @param[in] tls_context  :  The tls context to work with
 * @param[in] label        :  The label to use.
 * @param mppe_keys        :  Output buffer.
 * @param size             :  The length of the output buffer.
 *
 * @return cy_rslt_t  : CY_RESULT_SUCCESS on success, refer to cy_result_mw.h in connectivity-utilities for error
 *
 */
void get_mppe_key(cy_tls_context_t *tls_context, const char* label, uint8_t* mppe_keys, int size);

/** @} */

#ifdef __cplusplus
} /*extern "C" */
#endif
