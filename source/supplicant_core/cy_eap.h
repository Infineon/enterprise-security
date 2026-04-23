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

#include "cy_type_defs.h"
#include "cy_supplicant_core_constants.h"
#include "cy_supplicant_structures.h"
#include "cy_supplicant_host.h"

/******************************************************
 *                      Macros
 ******************************************************/

/******************************************************
 *                   Typedef structures
 ******************************************************/
#pragma pack(1)

typedef struct
{
    uint8_t ether_dhost[ETHERNET_ADDRESS_LENGTH];
    uint8_t ether_shost[ETHERNET_ADDRESS_LENGTH];
    uint16_t ether_type;
} cy_ether_header_t;

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint16_t length;
} eapol_header_t;

typedef struct
{
    cy_ether_header_t ethernet;
    eapol_header_t eapol;
} eapol_packet_header_t;

typedef struct
{
    cy_ether_header_t ethernet;
    eapol_header_t eapol;
    uint8_t data[1];
} eapol_packet_t;

typedef struct
{
    uint8_t code;
    uint8_t id;
    uint16_t length;
    uint8_t type;
} eap_header_t;

typedef struct
{
    cy_ether_header_t ethernet;
    eapol_header_t eapol;
    eap_header_t eap;
    uint8_t data[1];
} eap_packet_t;

typedef struct
{
    uint8_t flags;
} eap_tls_header_t;

typedef struct
{
    cy_ether_header_t ethernet;
    eapol_header_t eapol;
    eap_header_t eap;
    eap_tls_header_t eap_tls;
    uint8_t data[1]; /* Data starts with a length of TLS data field or TLS data depending on the flags field */
} eap_tls_packet_t;

typedef struct
{
    uint16_t type;
    uint16_t length;
    uint8_t value[1];
} avp_request_t;

typedef struct
{
    uint16_t type;
    uint16_t length;
    uint16_t status;
} avp_result_t;

typedef struct
{
    uint8_t type;
    uint8_t major_version;
    uint8_t minor_version;
    uint16_t length;
    uint8_t message[1];
} tls_record_t;

/* Helper structure to create TLS record */
typedef struct
{
    uint8_t type;
    uint8_t major_version;
    uint8_t minor_version;
    uint16_t length;
} tls_record_header_t;

#pragma pack()

/******************************************************
 *               Function Prototypes
 ******************************************************/
cy_rslt_t supplicant_send_eapol_start               ( supplicant_workspace_t* workspace );
void      supplicant_send_eap_response_packet       ( supplicant_workspace_t* workspace, eap_type_t eap_type, uint8_t* data, uint16_t data_length );
cy_rslt_t supplicant_send_zero_length_eap_tls_packet( supplicant_workspace_t* workspace );
cy_rslt_t supplicant_send_eap_tls_fragment          ( supplicant_workspace_t* workspace, supplicant_packet_t packet );
void      supplicant_send_eapol_packet              ( supplicant_packet_t packet, supplicant_workspace_t* workspace, eapol_packet_type_t type, uint16_t content_size );

#ifdef __cplusplus
} /*extern "C" */
#endif
