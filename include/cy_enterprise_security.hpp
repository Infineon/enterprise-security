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
 *  Prototypes of functions for controlling enterprise security network
 */

#pragma once

#include "WhdSTAInterface.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "cy_enterprise_security.h"

#ifdef __cplusplus
}
#endif


/**
 * \addtogroup enterprise_security_class
 * \{
 */

/**
 * EnterpriseSecurity class
 *
 * @brief
 * Defines Enterprise Security class with methods to join/leave an enterprise network.
 */
class EnterpriseSecurity : public WhdSTAInterface
{
public:
    /**
     * EnterpriseSecurity constructor
     *
     * @param[in]  ent_parameters : Pointer to \ref cy_enterprise_security_parameters_t structure,
     *                              initialized by the caller with the details required for establishing connection with the enterprise network.
     */
    EnterpriseSecurity(cy_enterprise_security_parameters_t *ent_parameters);

    /**
     * EnterpriseSecurity destructor
     */
    ~EnterpriseSecurity();

    /**
     * Joins an enterprise security network (802.1x Access point)
     *
     * @return cy_rslt_t  : CY_RSLT_SUCCESS - on success, an error code otherwise.
     *                      Error codes returned by this function are: \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_BADARG \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_ALREADY_CONNECTED \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_NOMEM \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_JOIN_ERROR \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_SUPPLICANT_ERROR
     */
    cy_rslt_t join( void );

    /**
     * Leaves an Enterprise security network (802.1x Access point)
     *
     * @return cy_rslt_t  : CY_RSLT_SUCCESS - on success, an error code otherwise.
     *                      Error codes returned by this function are: \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_BADARG \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_NOT_CONNECTED \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_LEAVE_ERROR \n
     *                     \ref CY_RSLT_ENTERPRISE_SECURITY_SUPPLICANT_ERROR
     */
    cy_rslt_t leave( void );

private:
    cy_enterprise_security_t handle; /**< Pointer to store the Enterprise Security instance handle for internal use. */
};

/** \} enterprise_security_class */
