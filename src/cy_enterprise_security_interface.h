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

/** @file
 *  Cypress Enterprise security library
 */

#ifndef ENTERPRISE_SECURITY_H
#define ENTERPRISE_SECURITY_H

#include "cy_type_defs.h"
#include "cy_supplicant_structures.h"
#include "cy_enterprise_security.h"
#include "WhdSTAInterface.h"

/**
********************************************************************************
* \mainpage Overview
********************************************************************************
* Cypress enterprise security library provides the capability for Cypress's best in class Wi-Fi enabled PSoC6 devices to connect to enterprise Wi-Fi networks.
* This library implements a collection of the most commonly used Extensible Authentication Protocol (EAP) that are commonly used in enterprise
* networks.
* This library is an embedded variant of the Wi-Fi supplicant (minimal features) that runs on an RTOS and provides the ability to securely join
* enterprise security networks (802.1x) using various EAP authentication protocols.
* Following are features supported by this library
*   - Supports following EAP security protocols:
*       - EAP-TLS
*       - PEAPv0 with MSCHAPv2
*       - EAP-TTLS with EAP-MSCHAPv2
*   - Supports TLS session (session ID based) resumption.
*   - Supports 'PEAP Fast reconnect' (this is applicable only for PEAP protocol).
*   - Supports roaming across APs in the enterprise network (vanilla roaming)
*   - Supports TLS versions 1.0, 1.1, and 1.2
* This library provides application developers an easy-to-use, unified interface for quickly enabling
* enterprise security in their applications. The library provides a single interface to join and leave 802.1x networks using different protocols.
*
* \defgroup enterprise_security Enterprise security library
* \defgroup enterprise_security_enums Enterprise security enumerated types
* @ingroup enterprise_security
* \defgroup enterprise_security_defines Enterprise security preprocessors definitions
* @ingroup enterprise_security
* \defgroup enterprise_security_struct Enterprise security data structures
* @ingroup enterprise_security
* \defgroup enterprise_security_classes Enterprise security base class and class methods
* @ingroup enterprise_security
*/

/**
 * @addtogroup enterprise_security_struct
 *
 * Enterprise security data structures and type definitions
 *
 * @{
 */

/** Enterprise security phase2 authenticaton parameters structure.
 *
 * */
typedef struct phase2_s
{
    cy_supplicant_tunnel_auth_type_t tunnel_auth_type;      /**<  Tunnel authentication type. */
    cy_supplicant_eap_type_t inner_eap_type;                /**<  Inner EAP type. */
    char inner_identity[CY_SUPPLICANT_MAX_IDENTITY_LENGTH]; /**<  Inner user identity. */
    char inner_password[CY_SUPPLICANT_MAX_PASSWORD_LENGTH]; /**<  Inner user password. */
} phase2_t;/**<  phase2 */

/** Enterprise security parameters structure
 *
 * */
typedef struct enterprise_security_parameters_s
{
    char                            ssid[64];                                              /**<  WIFI SSID. */
    cy_supplicant_eap_type_t        eap_type;                                              /**<  Authentication mechanism want to use. */
    char*                           ca_cert;                                               /**<  CA certificate in PEM format. */
    char*                           client_cert;                                           /**<  Client certificate in PEM format. */
    char*                           client_key;                                            /**<  Client private key in PEM format. */
    cy_supplicant_core_security_t   auth_type;                                             /**<  Security auth type used, as of now it should be always WHD_SECURITY_WPA2_MIXED_ENT for more information refer the file "mbed-os\targets\TARGET_Cypress\TARGET_PSOC6\TARGET_WHD\inc\whd_types.h". */
    char                            outer_eap_identity[CY_SUPPLICANT_MAX_IDENTITY_LENGTH]; /**<  Outer EAP identity. */
    uint8_t                         is_client_cert_required;                               /**<  (Used for EAP_TTLS) Specifies if client certificate is required. */
    phase2_t                        phase2;                                                /**<  Phase2 authentication members. */
}enterprise_security_parameters_t;

/**
 * @}
 */

/*****************************************************************************/
/**
 *
 * @addtogroup enterprise_security_classes
 *
 * Base class and communication functions for enterprise security
 *
 *  @{
 */
/*****************************************************************************/

/** Defines enterprise security object with various members */

class EnterpriseSecurity : public WhdSTAInterface
{
public:
    /**
     * EnterpriseSecurity constructor
     */
    EnterpriseSecurity();

    /**
     ******************************************************************************
     * Joins an enterprise security network (802.1x Access point)
     *
     * @param[in] ent_parameters : Pointer to enterprise_security_parameters_t
     *                             structure, parameters should be filled by user who calls this API.
     *
     * @return cy_supplicant_status_t  : CY_SUPPLICANT_STATUS_JOIN_SUCCESS - on success, error codes in @ref cy_supplicant_status_t otherwise
     *
     */
    cy_supplicant_status_t join(enterprise_security_parameters_t* ent_parameters);
    /**
     ******************************************************************************
     * Leaves an Enterprise security network (802.1x Access point)
     *
     * @return cy_supplicant_status_t  : CY_SUPPLICANT_STATUS_LEAVE_SUCCESS - on success, error codes in @ref cy_supplicant_status_t otherwise
     *
     */
    cy_supplicant_status_t leave();

private:
    cy_supplicant_instance_t supplicant_instance;  /**< For internal use. */
};

#endif

/**
 * @}
 */
