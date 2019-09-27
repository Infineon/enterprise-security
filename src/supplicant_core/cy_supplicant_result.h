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

#include "cy_result_mw.h"

/******************************************************
 *                      Macros
 ******************************************************/
/*
 * Results returned by WIFI SUPPLICANT library
 */
#define CY_RSLT_MODULE_WIFI_SUPPLICANT_ERR_CODE_START          (0)
#define CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE                     CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_WIFI_SUPPLICANT_BASE, CY_RSLT_MODULE_WIFI_SUPPLICANT_ERR_CODE_START)

#define CY_RSLT_WIFI_SUPPLICANT_GENERIC_ERROR                  ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 1))
#define CY_RSLT_WIFI_SUPPLICANT_OUT_OF_HEAP_SPACE              ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 2))
#define CY_RSLT_WIFI_SUPPLICANT_TIMEOUT                        ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 4))
#define CY_RSLT_WIFI_SUPPLICANT_ERROR                          ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 5))
#define CY_RSLT_WIFI_SUPPLICANT_IN_PROGRESS                    ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 6))
#define CY_RSLT_WIFI_SUPPLICANT_ABORTED                        ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 7))
#define CY_RSLT_WIFI_SUPPLICANT_NOT_STARTED                    ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 8))
#define CY_RSLT_WIFI_SUPPLICANT_ERROR_STACK_MALLOC_FAIL        ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 9))
#define CY_RSLT_WIFI_SUPPLICANT_COMPLETE                       ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 10))
#define CY_RSLT_WIFI_SUPPLICANT_ERROR_AT_THREAD_START          ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 11))
#define CY_RSLT_WIFI_SUPPLICANT_UNPROCESSED                    ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 12))
#define CY_RSLT_WIFI_SUPPLICANT_ERROR_CREATING_EAPOL_PACKET    ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 13))
#define CY_RSLT_WIFI_SUPPLICANT_ERROR_READING_BSSID            ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 14))
#define CY_RSLT_WIFI_SUPPLICANT_RECEIVED_EAP_FAIL              ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 15))
#define CY_RSLT_WIFI_SUPPLICANT_TLS_HANDSHAKE_FAILURE          ((cy_rslt_t)(CY_RSLT_WIFI_SUPPLICANT_ERROR_BASE + 16))
