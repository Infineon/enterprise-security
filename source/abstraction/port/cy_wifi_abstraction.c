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
 *  Implements functions for controlling the Wi-Fi system in AnyCloud using WCM
 *
 *  This file provides functions which allow actions such as turning on,
 *  joining Wi-Fi networks, getting the Wi-Fi connection status, etc
 *
 */
#include "cy_enterprise_security_log.h"
#include "cy_enterprise_security_error.h"
#include "cy_wifi_abstraction.h"
#include "cy_wcm.h"

#define ENTERPRISE_SECURITY_IPV4_ADDR_SIZE           4

cy_wcm_ip_setting_t* static_ip_settings = NULL;
static cy_wcm_config_t wcm_config;

#ifdef ENABLE_ENTERPRISE_SECURITY_LOGS
static void print_ip4(uint32_t ip);
#endif

void wifi_on_ent( void )
{
    cy_rslt_t res;

    wcm_config.interface = CY_WCM_INTERFACE_TYPE_STA;

    res = cy_wcm_init(&wcm_config);
    if( res != CY_RSLT_SUCCESS )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Wi-Fi module failed to initialize, err=%u\r\n", (unsigned int)res);
        return;
    }

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Wi-Fi module initialized.\r\n");
}

cy_rslt_t connect_ent( const char *ssid, uint8_t ssid_length,
                 const char *password, uint8_t password_length,
                 cy_enterprise_security_auth_t auth_type )
{
    cy_rslt_t res;
    cy_wcm_connect_params_t connect_params;
    cy_wcm_ip_address_t ip_addr;

    memset(&connect_params, 0, sizeof(cy_wcm_connect_params_t));

    /* validate input parameters */
    if( ssid == NULL || strlen(ssid) == 0 || strlen(ssid) > CY_ENTERPRISE_SECURITY_MAX_SSID_LENGTH )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid SSID!\n");
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }

    /* Setup parameters. */
    memcpy(connect_params.ap_credentials.SSID, ssid, strlen(ssid) + 1);

    if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA_AES )
    {
        connect_params.ap_credentials.security = CY_WCM_SECURITY_WPA_AES_ENT;
    }
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA_MIXED )
    {
        connect_params.ap_credentials.security = CY_WCM_SECURITY_WPA_MIXED_ENT;
    }
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA2_AES )
    {
        connect_params.ap_credentials.security = CY_WCM_SECURITY_WPA2_AES_ENT;
    }
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA2_MIXED )
    {
        connect_params.ap_credentials.security = CY_WCM_SECURITY_WPA2_MIXED_ENT;
    }
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA2_FBT )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "The auth type is not supported \r\n");
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }
#if defined(COMPONENT_55900) || defined(COMPONENT_PSE84)
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA3_AES )
    {
        connect_params.ap_credentials.security = CY_WCM_SECURITY_WPA3_ENT;
    }
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA3_AES_CCMP )
    {
        connect_params.ap_credentials.security = CY_WCM_SECURITY_WPA3_ENT_AES_CCMP;
    }
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA3_192BIT )
    {
        connect_params.ap_credentials.security = CY_WCM_SECURITY_WPA3_192BIT_ENT;
    }
#endif
    else
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "The auth type is invalid\r\n");
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }

    connect_params.band = CY_WCM_WIFI_BAND_ANY; // No band is set, so set it to auto.

    if(static_ip_settings != NULL)
    {
        connect_params.static_ip_settings = static_ip_settings;
    }

    res = cy_wcm_connect_ap(&connect_params, &ip_addr);
    if( res != CY_RSLT_SUCCESS )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Wi-Fi unable to connect, err=%u\r\n", (unsigned int)res);
        return CY_RSLT_ENTERPRISE_SECURITY_JOIN_ERROR;
    }

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Wi-Fi Connected to AP.\r\n");
#ifdef ENABLE_ENTERPRISE_SECURITY_LOGS
    print_ip4(ip_addr.ip.v4);
#endif
    return CY_RSLT_SUCCESS;
}

cy_rslt_t disconnect_ent( void )
{
    cy_rslt_t res = cy_wcm_disconnect_ap();
    if( res != CY_RSLT_SUCCESS )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Not Successfully Disconnected from AP, err=%u.\r\n", (unsigned int)res);
        return CY_RSLT_ENTERPRISE_SECURITY_LEAVE_ERROR;
    }

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Successfully Disconnected from AP.\r\n");
    return CY_RSLT_SUCCESS;
}

wifi_connection_status_t is_wifi_connected( void )
{
    if( cy_wcm_is_connected_to_ap() == 1 )
    {
        return WIFI_CONNECTED;
    }
    else
    {
        return WIFI_NOT_CONNECTED;
    }
}

#ifdef ENABLE_ENTERPRISE_SECURITY_LOGS
static void print_ip4(uint32_t ip)
{
    unsigned char bytes[ENTERPRISE_SECURITY_IPV4_ADDR_SIZE];

    (void)bytes;

    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "IP Address acquired: %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}
#endif // ENABLE_ENTERPRISE_SECURITY_LOGS
