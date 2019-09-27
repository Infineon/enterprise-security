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

#include "cy_enterprise_security_interface.h"
#include "cy_supplicant_core_constants.h"
#include "cy_supplicant_process_et.h"

#define ENTERPRISE_SECUTIRY_DEBUG_INFO(x) //printf x

EnterpriseSecurity::EnterpriseSecurity()
{
    memset(&supplicant_instance, 0, sizeof(cy_supplicant_instance_t));
}

cy_supplicant_status_t EnterpriseSecurity::join(enterprise_security_parameters_t* ent_parameters)
{
    cy_supplicant_status_t result =     CY_SUPPLICANT_STATUS_JOIN_SUCCESS;
    nsapi_error_t res = 0;

    supplicant_instance.tls_security.ca_cert = ent_parameters->ca_cert;
    supplicant_instance.tls_security.ca_cert_len = strlen(ent_parameters->ca_cert);
    supplicant_instance.tls_security.cert = ent_parameters->client_cert;
    supplicant_instance.tls_security.cert_len = strlen(ent_parameters->client_cert);
    supplicant_instance.tls_security.key = ent_parameters->client_key;
    supplicant_instance.tls_security.key_len = strlen(ent_parameters->client_key);

    if (_interface != NULL)
    {
        if (is_interface_connected() == WHD_SUCCESS)
        {
            return CY_SUPPLICANT_STATUS_UP;
        }
    }

    result = cy_join_ent_init(&supplicant_instance);
    if (result != CY_SUPPLICANT_STATUS_PASS)
    {
        ENTERPRISE_SECUTIRY_DEBUG_INFO((" Unable to perform join ent init %d\n", result));
        return CY_SUPPLICANT_STATUS_FAIL;
    }

    memcpy(supplicant_instance.ssid, ent_parameters->ssid, strlen(ent_parameters->ssid) + 1);

    supplicant_instance.eap_type = ent_parameters->eap_type;

    memcpy(supplicant_instance.outer_eap_identity, (const char *)ent_parameters->outer_eap_identity ,strlen(ent_parameters->outer_eap_identity)+1);
    supplicant_instance.outer_eap_identity_length = strlen(ent_parameters->outer_eap_identity)+1;
    supplicant_instance.auth_type = ent_parameters->auth_type;

    if( ent_parameters->eap_type == CY_SUPPLICANT_EAP_TYPE_PEAP )
    {
        supplicant_instance.phase2_config.tunnel_auth_type = ent_parameters->phase2.tunnel_auth_type;
        memcpy( supplicant_instance.phase2_config.tunnel_protocol.peap.inner_identity.identity, ent_parameters->phase2.inner_identity, strlen(ent_parameters->phase2.inner_identity)+1);

        supplicant_instance.phase2_config.tunnel_protocol.peap.inner_identity.identity_length = strlen(ent_parameters->phase2.inner_identity)+1;

        memcpy( supplicant_instance.phase2_config.tunnel_protocol.peap.inner_identity.password, ent_parameters->phase2.inner_password, strlen(ent_parameters->phase2.inner_password)+1);

        supplicant_instance.phase2_config.tunnel_protocol.peap.inner_identity.password_length = strlen(ent_parameters->phase2.inner_password)+1;
    }
    else if ( ent_parameters->eap_type == CY_SUPPLICANT_EAP_TYPE_TTLS )
    {
        supplicant_instance.phase2_config.tunnel_auth_type = ent_parameters->phase2.tunnel_auth_type;
        supplicant_instance.phase2_config.tunnel_protocol.eap_ttls.inner_eap_type = ent_parameters->phase2.inner_eap_type;
        supplicant_instance.phase2_config.tunnel_protocol.eap_ttls.is_client_cert_required = ent_parameters->is_client_cert_required;
        memcpy( supplicant_instance.phase2_config.tunnel_protocol.eap_ttls.inner_identity.identity, ent_parameters->phase2.inner_identity, strlen(ent_parameters->phase2.inner_identity)+1);

        supplicant_instance.phase2_config.tunnel_protocol.eap_ttls.inner_identity.identity_length = strlen(ent_parameters->phase2.inner_identity)+1;

        memcpy( supplicant_instance.phase2_config.tunnel_protocol.eap_ttls.inner_identity.password, ent_parameters->phase2.inner_password, strlen(ent_parameters->phase2.inner_password)+1);

        supplicant_instance.phase2_config.tunnel_protocol.eap_ttls.inner_identity.password_length = strlen(ent_parameters->phase2.inner_password)+1;
    }

    wifi_on();

    result = cy_join_ent(&supplicant_instance);
    if( result != CY_SUPPLICANT_STATUS_PASS)
    {
        cy_join_ent_deinit(&supplicant_instance);
        ENTERPRISE_SECUTIRY_DEBUG_INFO(("ERROR: cy_join_ent failed with error %d\n", result));
        return CY_SUPPLICANT_STATUS_FAIL;
    }
    res = connect(ent_parameters->ssid, NULL, NSAPI_SECURITY_WPA2_ENT, 0);
    if( res != 0 )
    {
        cy_leave_ent(&supplicant_instance);
        cy_join_ent_deinit(&supplicant_instance);
        ENTERPRISE_SECUTIRY_DEBUG_INFO(("ERROR: connect failed with error %d\n", result));
        return CY_SUPPLICANT_STATUS_JOIN_FAILURE;
    }

    return CY_SUPPLICANT_STATUS_JOIN_SUCCESS;
}

cy_supplicant_status_t EnterpriseSecurity::leave()
{
    nsapi_error_t res;
    cy_supplicant_status_t result = CY_SUPPLICANT_STATUS_LEAVE_SUCCESS;
    if (_interface != NULL)
    {
        if ( is_interface_connected() == WHD_SUCCESS)
        {
            result = cy_leave_ent(&supplicant_instance);
            if(result !=  CY_SUPPLICANT_STATUS_PASS)
            {
                return CY_SUPPLICANT_STATUS_FAIL;
            }

            result = cy_join_ent_deinit(&supplicant_instance);
            if(result !=  CY_SUPPLICANT_STATUS_PASS)
            {
                return CY_SUPPLICANT_STATUS_FAIL;
            }

            res = disconnect();
            if( res != 0)
            {
                ENTERPRISE_SECUTIRY_DEBUG_INFO(("ERROR: disconnect failed with error %d\n", result));
                return CY_SUPPLICANT_STATUS_LEAVE_FAILURE;
            }
            ENTERPRISE_SECUTIRY_DEBUG_INFO( ("successfully left\r\n" ));

            return CY_SUPPLICANT_STATUS_LEAVE_SUCCESS;
        }
        return CY_SUPPLICANT_STATUS_DOWN;
    }
    else
    {
        return CY_SUPPLICANT_STATUS_DOWN;
    }

}
