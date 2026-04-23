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

/** @file
 *  Implements functions for registering and unregistering for eapol packets with
 *  the underlying WHD layer.
 */
#include "cy_enterprise_security_log.h"
#include "cy_enterprise_security_error.h"
#include "cy_supplicant_host.h"
#include "cy_wifimwcore_eapol.h"

cy_rslt_t cy_ent_sec_register_eapol_packet_handler(cy_ent_sec_eapol_packet_handler_t eapol_packet_handler)
{
    if(cy_wifimwcore_eapol_register_receive_handler((cy_wifimwcore_eapol_packet_handler_t)eapol_packet_handler) != CY_RSLT_SUCCESS)
    {
        cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_ERR, "Failed to register eapol receive handler.\n");
        return CY_RSLT_ENTERPRISE_SECURITY_ERROR;
    }

    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Successfully registered eapol packet handler.\r\n");
    return CY_RSLT_SUCCESS;
}

void cy_ent_sec_unregister_eapol_packet_handler(void)
{
    cy_wifimwcore_eapol_register_receive_handler(NULL);
    cy_enterprise_security_log_msg(CYLF_MIDDLEWARE, CY_LOG_DEBUG, "Successfully unregistered eapol packet handler.\r\n");
}
