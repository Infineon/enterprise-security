/*
 * (c) 2025, Infineon Technologies AG, or an affiliate of Infineon
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
#include "cy_tls_abstraction.h"
#include "cy_mschapv2.h"
#include "cy_supplicant_process_et.h"
#include "cy_supplicant_core_constants.h"
#include "cy_supplicant_structures.h"
#include "cy_supplicant_host.h"
#include "cy_eap.h"

/******************************************************
 *                 Typedef Structures
 ******************************************************/
typedef struct
{
    uint8_t  type;
} peap_header_t;

typedef struct
{
    uint8_t  type;
    uint8_t  data[1];
} peap_packet_t;

typedef struct
{
    eap_header_t    header;
    avp_request_t   avp[1];
}peap_extention_request_t;

typedef struct
{
    eap_header_t   header;
    avp_result_t   avp[1];
}peap_extention_response_t;


/******************************************************
 *               Function prototypes
 ******************************************************/
extern cy_rslt_t    supplicant_inner_packet_set_data        ( whd_driver_t whd_driver,supplicant_packet_t* packet, int32_t size );
supplicant_packet_t supplicant_create_peap_response_packet  ( supplicant_packet_t* packet, eap_type_t eap_type, uint16_t data_length, uint8_t length_field_overhead, supplicant_workspace_t* workspace );
void                supplicant_send_peap_response_packet    ( supplicant_packet_t* packet, supplicant_workspace_t* workspace );

#ifdef __cplusplus
} /*extern "C" */
#endif
