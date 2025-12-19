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
#include "cy_supplicant_core_constants.h"
#include "cy_supplicant_structures.h"
#include "cy_supplicant_host.h"
#include "cy_eap.h"
#include "cyabs_rtos.h"

/******************************************************
 *                  Constants
 ******************************************************/
#ifdef ENABLE_ENTERPRISE_SECURITY_LOGS
#define SUPPLICANT_THREAD_STACK_SIZE         ( 7*1024 + 3*1024 ) /* Extra 3k for debug logs */
#define TLS_AGENT_THREAD_STACK_SIZE          ( 7*1024 + 3*1024 ) /* Extra 3k for debug logs */
#else
#define SUPPLICANT_THREAD_STACK_SIZE         ( 7*1024 )
#define TLS_AGENT_THREAD_STACK_SIZE          ( 7*1024 )
#endif
#define SUPPLICANT_BUFFER_SIZE               ( 3500 )
#define SUPPLICANT_WORKSPACE_ARRAY_SIZE      ( 3 )
#define WLC_EVENT_MSG_LINK                   ( 0x01 )
#define EAPOL_PACKET_TIMEOUT                 ( 5000 )  /* Milliseconds */
#define SUPPLICANT_HANDSHAKE_ATTEMPT_TIMEOUT ( 30000 ) /* Milliseconds */
#define EAP_HANDSHAKE_TIMEOUT_IN_MSEC        ( 25000 ) /* Milliseconds */

/******************************************************
 *                 Macros
 ******************************************************/

/******************************************************
 *              Function Prototypes
 ******************************************************/

cy_rslt_t supplicant_start( supplicant_workspace_t* workspace );
cy_rslt_t supplicant_init_state(supplicant_workspace_t* workspace, eap_type_t eap_type );
void      supplicant_set_identity        ( supplicant_workspace_t* workspace, const uint8_t* eap_identity, uint32_t eap_identity_length );
void      supplicant_set_inner_identity  ( supplicant_workspace_t* workspace, eap_type_t eap_type, void* inner_identity );
cy_rslt_t supplicant_management_set_event_handler( supplicant_workspace_t* workspace, cy_bool_t enable );
cy_rslt_t supplicant_start( supplicant_workspace_t* workspace );
cy_rslt_t supplicant_stop( supplicant_workspace_t* workspace );
cy_rslt_t supplicant_init(supplicant_workspace_t* workspace, supplicant_connection_info_t *conn_info);
cy_rslt_t supplicant_deinit( supplicant_workspace_t* workspace );
cy_rslt_t supplicant_tls_calculate_overhead( supplicant_workspace_t* workspace, uint16_t available_space, uint16_t* header, uint16_t* footer );
cy_rslt_t supplicant_inner_packet_set_data( whd_driver_t whd_driver,supplicant_packet_t* packet, int32_t size );
cy_rslt_t supplicant_process_peap_event(supplicant_workspace_t* workspace, supplicant_packet_t packet);
cy_rslt_t supplicant_phase2_init( supplicant_workspace_t* workspace, eap_type_t type );
cy_rslt_t supplicant_phase2_start( supplicant_workspace_t* workspace );
cy_rslt_t supplicant_enable_tls( supplicant_workspace_t* supplicant, void* context );
void      supplicant_phase2_thread( cy_thread_arg_t arg );
void      supplicant_free_tls_session( cy_tls_session_t* session );
tls_agent_packet_t* supplicant_receive_eap_tls_packet( void* workspace_in, uint32_t* new_length, uint32_t timeout );
cy_rslt_t supplicant_host_get_tls_data(supplicant_workspace_t*, supplicant_packet_t, uint16_t, uint8_t**, uint16_t*, uint16_t*);
cy_rslt_t supplicant_fragment_and_queue_eap_response( supplicant_workspace_t *workspace );
cy_rslt_t supplicant_outgoing_push( void* workspace, supplicant_event_message_t* message );

#ifdef __cplusplus
} /*extern "C" */
#endif
