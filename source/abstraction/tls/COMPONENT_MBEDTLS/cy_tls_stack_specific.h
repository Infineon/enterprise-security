/*
 * Copyright 2021, Cypress Semiconductor Corporation (an Infineon company) or
 * an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
 *
 * This software, including source code, documentation and related
 * materials ("Software") is owned by Cypress Semiconductor Corporation
 * or one of its affiliates ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products.  Any reproduction, modification, translation,
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

#include "ssl.h"
#include "ssl_internal.h"
#include "ctr_drbg.h"
#include "entropy.h"
#include "cipher.h"
#include "md4.h"
#include "sha1.h"
#include "des.h"

/******************************************************
 *                      Macros
 ******************************************************/

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

#ifdef __cplusplus
} /*extern "C" */
#endif
