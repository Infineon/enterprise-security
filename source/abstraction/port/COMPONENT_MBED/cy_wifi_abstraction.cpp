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

/** @file
 *  Implements functions for controlling the Wi-Fi system in Mbed using WiFiInterface
 *
 *  This file provides functions which allow actions such as turning on,
 *  joining Wi-Fi networks, getting the Wi-Fi connection status, etc
 *
 */

#include "mbed.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "cy_enterprise_security_log.h"
#include "cy_enterprise_security_error.h"
#include "cy_wifi_abstraction.h"

#define ENTERPRISE_SECURITY_IPV4_ADDR_SIZE           4

#ifdef ENABLE_ENTERPRISE_SECURITY_LOGS
static void print_ip4();
#endif

void wifi_on_ent( void )
{
    /* Do nothing. It's just a stub */
    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Wi-Fi module initialized.\r\n");
}

cy_rslt_t connect_ent( const char *ssid, uint8_t ssid_length,
                 const char *password, uint8_t password_length,
                 cy_enterprise_security_auth_t auth_type )
{
    nsapi_error_t err;
    nsapi_security sec;
    WiFiInterface *sta = NULL;
    int channel = 0;

    /* validate input parameters */
    if( ssid == NULL || strlen(ssid) == 0 || strlen(ssid) > CY_ENTERPRISE_SECURITY_MAX_SSID_LENGTH )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Invalid SSID!\n");
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }

    /* check if already connected */
    if( is_wifi_connected() == WIFI_CONNECTED )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Already connected to a network.\n");
        return CY_RSLT_ENTERPRISE_SECURITY_ALREADY_CONNECTED;
    }

    /* Setup parameters. */
    if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA2_MIXED ||
        auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA2_AES )
    {
        sec = NSAPI_SECURITY_WPA2_ENT;
    }
    else if( auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA_MIXED ||
             auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA_AES ||
             auth_type == CY_ENTERPRISE_SECURITY_AUTH_TYPE_WPA2_FBT )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "The auth type is not supported \r\n");
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }
    else
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "The auth type is invalid\r\n");
        return CY_RSLT_ENTERPRISE_SECURITY_BADARG;
    }

    sta = WiFiInterface::get_default_instance();
    if( sta == NULL )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to get STA interface!\n");
        return CY_RSLT_ENTERPRISE_SECURITY_ERROR;
    }

    err = sta->connect( ssid, NULL, sec, channel );
    if( err != NSAPI_ERROR_OK )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Wi-Fi unable to connect, err=%d\r\n", err);
        return CY_RSLT_ENTERPRISE_SECURITY_JOIN_ERROR;
    }

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Wi-Fi Connected to AP.\r\n");
#ifdef ENABLE_ENTERPRISE_SECURITY_LOGS
    print_ip4();
#endif
    return CY_RSLT_SUCCESS;
}

cy_rslt_t disconnect_ent( void )
{
    nsapi_error_t err;
    WiFiInterface *sta = NULL;

    sta = WiFiInterface::get_default_instance();
    if( sta == NULL )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to get STA interface!\n");
        return CY_RSLT_ENTERPRISE_SECURITY_ERROR;
    }

    err = sta->disconnect();
    if( err != NSAPI_ERROR_OK )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Not Successfully Disconnected from AP, err=%d.\r\n", err);
        return CY_RSLT_ENTERPRISE_SECURITY_LEAVE_ERROR;
    }

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Successfully Disconnected from AP.\r\n");
    return CY_RSLT_SUCCESS;
}

wifi_connection_status_t is_wifi_connected( void )
{
    nsapi_connection_status_t conn_status;
    WiFiInterface *sta = NULL;

    sta = WiFiInterface::get_default_instance();
    if( sta == NULL )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to get STA interface!\n");
        return WIFI_NOT_CONNECTED;
    }

    conn_status = sta->get_connection_status();
    if( conn_status == NSAPI_STATUS_LOCAL_UP || conn_status == NSAPI_STATUS_GLOBAL_UP )
    {
        return WIFI_CONNECTED;
    }
    else
    {
        return WIFI_NOT_CONNECTED;
    }
}

#ifdef ENABLE_ENTERPRISE_SECURITY_LOGS
static void print_ip4()
{
    nsapi_error_t err;
    SocketAddress address;
    WiFiInterface *sta = NULL;

    sta = WiFiInterface::get_default_instance();
    if( sta == NULL )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to get STA interface!\n");
        return;
    }

    err = sta->get_ip_address(&address);
    if( err != NSAPI_ERROR_OK )
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "Failed to fetch IP Address. Res:%d\n", err);
        return;
    }
    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_INFO, "IP Address acquired: %s\n", address.get_ip_address());
}
#endif // ENABLE_ENTERPRISE_SECURITY_LOGS

#ifdef __cplusplus
}
#endif
