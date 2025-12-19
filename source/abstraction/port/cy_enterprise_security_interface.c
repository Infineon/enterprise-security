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

/** @file
 *  Implements user functions for joining/leaving enterprise security network.
 *
 *  This file provides end-user functions which allow joining or leaving
 *  enterprise security network.
 *
 */

#include "cy_enterprise_security_log.h"
#include "cy_enterprise_security_internal.h"
#include "cy_wifi_abstraction.h"
#include "cy_supplicant_core_constants.h"
#include "cy_supplicant_process_et.h"
#include "cy_wcm.h"

extern cy_wcm_ip_setting_t* static_ip_settings;

/* This API is used for internal purpose to pass the static IP settings */
cy_rslt_t cy_enterprise_security_set_static_ip( cy_wcm_ip_setting_t* ip_settings )
{
    static_ip_settings = ip_settings;
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_enterprise_security_join( cy_enterprise_security_t handle )
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    cy_supplicant_instance_t *supplicant_instance;

    if( handle == NULL )
    {
        cy_enterprise_security_log_msg( CYLF_MIDDLEWARE, CY_LOG_ERR, "Enterprise Security handle is NULL.\n" );
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }

    supplicant_instance = (cy_supplicant_instance_t *)handle;

    if( is_wifi_connected() == WIFI_CONNECTED )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Already connected to Wi-Fi network.\n");
        return CY_RSLT_ENTERPRISE_SECURITY_ALREADY_CONNECTED;
    }

    result = cy_supplicant_alloc( supplicant_instance );
    if ( result != CY_RSLT_SUCCESS )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "ERROR: cy_supplicant_alloc failed with error = [%u]\n", (unsigned int)result);
        return result;
    }

    wifi_on_ent();

    result = cy_join_ent( supplicant_instance );
    if( result != CY_RSLT_SUCCESS )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "ERROR: cy_join_ent failed with error = [%u]\n", (unsigned int)result);
        cy_supplicant_free( supplicant_instance );
        return result;
    }

    result = connect_ent( supplicant_instance->ssid, strlen( supplicant_instance->ssid ) + 1, NULL, 0, supplicant_instance->auth_type );
    if( result != CY_RSLT_SUCCESS )
    {
        cy_leave_ent( supplicant_instance );
        cy_supplicant_free( supplicant_instance );
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "ERROR: connect failed with error = [%u]\n", (unsigned int)result);
        return result;
    }

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Successfully joined Enterprise Security network.\r\n");
    return CY_RSLT_SUCCESS;
}

cy_rslt_t cy_enterprise_security_leave(cy_enterprise_security_t handle)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    cy_supplicant_instance_t *supplicant_instance;

    if( handle == NULL )
    {
        cy_enterprise_security_log_msg( CYLF_MIDDLEWARE, CY_LOG_ERR, "Enterprise Security handle is NULL.\n" );
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }

    supplicant_instance = (cy_supplicant_instance_t *)handle;

    if( is_wifi_connected() != WIFI_CONNECTED )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Not connected to any Wi-Fi network.\n");
        return CY_RSLT_ENTERPRISE_SECURITY_NOT_CONNECTED;
    }

    result = cy_leave_ent( supplicant_instance );
    if( result !=  CY_RSLT_SUCCESS )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "ERROR: cy_leave_ent failed with error = [%u]\n", (unsigned int)result);
        cy_supplicant_free( supplicant_instance );
        return result;
    }

    result = disconnect_ent();
    if( result != CY_RSLT_SUCCESS )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "ERROR: disconnect failed with error = [%u]\n", (unsigned int)result);
        cy_supplicant_free( supplicant_instance );
        return result;
    }

    (void) cy_supplicant_free( supplicant_instance );
    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Successfully left Enterprise Security network.\r\n");

    static_ip_settings = NULL;

    return CY_RSLT_SUCCESS;
}
