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

#include "cy_tls_abstraction.h"
#include "cy_supplicant_structures.h"
#include "cy_supplicant_process_et.h"
#include "cy_enterprise_security.h"
#include "whd_wifi_api.h"
#include "cybsp_wifi.h"

/******************************************************
 *              Macros
 ******************************************************/
#define CY_SUPPLICANT_PROCESS_ET_API_INFO( x )   //printf x

/******************************************************
 *              Function definations
 ******************************************************/
cy_supplicant_status_t cy_join_ent_deinit(cy_supplicant_instance_t *supplicant_instance )
{
    if(supplicant_instance->tls_identity != NULL)
    {
        free(supplicant_instance->tls_identity);
        supplicant_instance->tls_identity = NULL;
    }

    if(supplicant_instance->tls_context != NULL)
    {
        free(supplicant_instance->tls_context);
        supplicant_instance->tls_context = NULL;
    }
    if(supplicant_instance->supplicant_core.supplicant_workspace != NULL)
    {
        free(supplicant_instance->supplicant_core.supplicant_workspace);
        supplicant_instance->supplicant_core.supplicant_workspace = NULL;
    }
    return CY_SUPPLICANT_STATUS_PASS;
}

cy_supplicant_status_t cy_join_ent_init(cy_supplicant_instance_t *supplicant_instance )
{
    supplicant_instance->supplicant_core.supplicant_workspace = malloc(sizeof(supplicant_workspace_t));
    if(supplicant_instance->supplicant_core.supplicant_workspace == NULL)
    {
        goto INIT_FAILURE;
    }

    memset(supplicant_instance->supplicant_core.supplicant_workspace, 0, sizeof(supplicant_workspace_t));

    supplicant_instance->tls_context = malloc(sizeof(cy_tls_context_t));
    if(supplicant_instance->tls_context == NULL)
    {
        goto SUPPLICANT_WORKSPACE_CLEAN;
    }

    memset(supplicant_instance->tls_context, 0, sizeof(cy_tls_context_t));

    supplicant_instance->tls_context->session = &supplicant_instance->saved_session;

    supplicant_instance->tls_identity = malloc(sizeof(cy_tls_identity_t));

    if(supplicant_instance->tls_identity == NULL)
    {
        goto TLS_CONTEXT_CLEAN;
    }

    memset(supplicant_instance->tls_identity,0,sizeof(cy_tls_identity_t));

    return CY_SUPPLICANT_STATUS_PASS;

    TLS_CONTEXT_CLEAN:
    free(supplicant_instance->tls_context);
    supplicant_instance->tls_context = NULL;

    SUPPLICANT_WORKSPACE_CLEAN:
    free(supplicant_instance->supplicant_core.supplicant_workspace);
    supplicant_instance->supplicant_core.supplicant_workspace = NULL;

    INIT_FAILURE:
    return CY_SUPPLICANT_STATUS_FAIL;
}

cy_supplicant_status_t cy_leave_ent ( cy_supplicant_instance_t *supplicant_instance )
{
    cy_rslt_t res;
    supplicant_workspace_t *supplicant_workspace = supplicant_instance->supplicant_core.supplicant_workspace;

    CY_SUPPLICANT_PROCESS_ET_API_INFO( ("Stop supplicant\n" ) );
    res = supplicant_stop( supplicant_workspace );
    if (res != CY_RSLT_SUCCESS)
    {
        CY_SUPPLICANT_PROCESS_ET_API_INFO( ("supplicant Stop failed with error = [%d]\n", res) );
        return CY_SUPPLICANT_STATUS_FAIL;
    }

    CY_SUPPLICANT_PROCESS_ET_API_INFO( ("De-init supplicant\n" ) );
    res = supplicant_deinit( supplicant_workspace );
    if (res != CY_RSLT_SUCCESS)
    {
        CY_SUPPLICANT_PROCESS_ET_API_INFO( ("supplicant De-init failed with error = [%d]\n", res) );
        return CY_SUPPLICANT_STATUS_FAIL;
    }

    return CY_SUPPLICANT_STATUS_PASS;
}

cy_supplicant_status_t cy_join_ent  ( cy_supplicant_instance_t *supplicant_instance )
{

    whd_driver_t whd_driver = cybsp_get_wifi_driver();
    supplicant_workspace_t *supplicant_workspace = NULL;
    whd_ap_info_t details;
    cy_rslt_t res = CY_RSLT_SUCCESS;
    supplicant_connection_info_t conn_info;

    if(supplicant_instance == NULL)
    {
        return CY_SUPPLICANT_STATUS_FAIL;
    }

    supplicant_workspace = supplicant_instance->supplicant_core.supplicant_workspace;

    if(supplicant_instance == NULL || supplicant_workspace == NULL || whd_driver == NULL)
    {
        CY_SUPPLICANT_PROCESS_ET_API_INFO( ("\r\n Supplicant_instance or Supplicant workspace or whd_driver can't be NULL\r\n") );
        return CY_SUPPLICANT_STATUS_FAIL;
    }

    /* Modify config */
    details.SSID.length = strlen(supplicant_instance->ssid);
    memcpy( (char*)details.SSID.value, supplicant_instance->ssid, details.SSID.length );
    details.security = supplicant_instance->auth_type;

    conn_info.auth_type = supplicant_instance->auth_type;
    conn_info.eap_type = supplicant_instance->eap_type;
    conn_info.private_key = (uint8_t*)supplicant_instance->tls_security.key;
    conn_info.key_length = supplicant_instance->tls_security.key_len;
    conn_info.root_ca_cert_length = supplicant_instance->tls_security.ca_cert_len;
    conn_info.trusted_ca_certificates = (uint8_t*)supplicant_instance->tls_security.ca_cert;
    conn_info.user_cert = (uint8_t*)supplicant_instance->tls_security.cert;
    conn_info.user_cert_length = supplicant_instance->tls_security.cert_len;
    conn_info.eap_identity = (uint8_t*)supplicant_instance->outer_eap_identity;

    if (conn_info.eap_type == (eap_type_t) CY_SUPPLICANT_EAP_TYPE_PEAP)
    {
        conn_info.tunnel_auth_type = supplicant_instance->phase2_config.tunnel_auth_type;

        conn_info.user_name = (uint8_t*) supplicant_instance->phase2_config.tunnel_protocol.peap.inner_identity.identity;
        conn_info.password =   (uint8_t*) supplicant_instance->phase2_config.tunnel_protocol.peap.inner_identity.password;
    }
    else if (conn_info.eap_type == (eap_type_t) CY_SUPPLICANT_EAP_TYPE_TTLS)
    {
        conn_info.is_client_cert_required = supplicant_instance->phase2_config.tunnel_protocol.eap_ttls.is_client_cert_required;

        conn_info.tunnel_auth_type = supplicant_instance->phase2_config.tunnel_auth_type;

        conn_info.user_name = (uint8_t*) supplicant_instance->phase2_config.tunnel_protocol.eap_ttls.inner_identity.identity;
        conn_info.password =  (uint8_t*) supplicant_instance->phase2_config.tunnel_protocol.eap_ttls.inner_identity.password;

        conn_info.inner_eap_type = supplicant_instance->phase2_config.tunnel_protocol.eap_ttls.inner_eap_type;
    }
    else
    {
    }

    conn_info.interface = supplicant_instance->interface;

    conn_info.tls_session = supplicant_instance->tls_context->session;
    conn_info.tls_identity = supplicant_instance->tls_identity;
    conn_info.context = supplicant_instance->tls_context;
    conn_info.context->context.conf = NULL;
    conn_info.context->root_ca_certificates = NULL;

    conn_info.interface = whd_driver->iflist[0];
    res = supplicant_init( supplicant_workspace, &conn_info);
    if ( res != CY_RSLT_SUCCESS )
    {
        CY_SUPPLICANT_PROCESS_ET_API_INFO( ("Unable to initialize supplicant. Error = [%d]\n", res ) );
        return CY_SUPPLICANT_STATUS_FAIL;
    }

    if ( supplicant_start( supplicant_workspace ) != CY_RSLT_SUCCESS )
    {
        return CY_SUPPLICANT_STATUS_FAIL;

    }
    return CY_SUPPLICANT_STATUS_PASS;
}
