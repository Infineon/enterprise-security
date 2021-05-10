# Cypress Enterprise Security Middleware Library

## Overview
This library provides the capability for Cypress' best in class Wi-Fi enabled 
PSoC® 6 devices to connect to enterprise Wi-Fi networks. This library implements 
a collection of the most commonly used Extensible Authentication Protocols (EAP) 
that are used in enterprise networks. 

## Features
This section provides details on the list of enterprise security Wi-Fi features 
supported by this library:
* Supports the following EAP security protocols: 
    * EAP-TLS
    * PEAPv0 with MSCHAPv2
    * EAP-TTLS with EAP-MSCHAPv2 (Phase 2 tunnel authentication supports only EAP methods)
* Supports TLS session (session ID based) resumption
* Supports 'PEAP Fast reconnect' (applicable only for PEAP protocol)
* Supports roaming across APs in the enterprise network (vanilla roaming)
* Supports TLS versions 1.0, 1.1, and 1.2

## Supported Frameworks

This library supports the following frameworks:

* AnyCloud Framework: AnyCloud is a FreeRTOS-based solution. Enterprise Security library uses the [abstraction-rtos](https://github.com/cypresssemiconductorco/abstraction-rtos) library that provides the RTOS abstraction API and the [wcm](https://github.com/cypresssemiconductorco/wifi-connection-manager) library for network functions.
* Mbed Framework: Mbed framework is an Mbed OS-based solution. Enterprise Security library uses the [abstraction-rtos](https://github.com/cypresssemiconductorco/abstraction-rtos) library that provides RTOS abstraction API, and uses the Mbed socket API for implementing network functions.

## Supported Platforms
### AnyCloud
* [PSoC® 6 WiFi-BT Prototyping Kit (CY8CPROTO-062-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w)
* [PSoC 62S2 Wi-Fi BT Pioneer Kit (CY8CKIT-062S2-43012)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-wi-fi-bt-pioneer-kit-cy8ckit-062s2-43012)

### Mbed OS
* [PSoC 6 WiFi-BT Prototyping Kit (CY8CPROTO-062-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w)
* [PSoC 62S2 Wi-Fi BT Pioneer Kit (CY8CKIT-062S2-43012)](https://www.cypress.com/documentation/development-kitsboards/psoc-62s2-wi-fi-bt-pioneer-kit-cy8ckit-062s2-43012)

## Dependencies
This section provides the list of dependent libraries required for this middleware library to work:

### AnyCloud
* [Wi-Fi Connection Manager](https://github.com/cypresssemiconductorco/wifi-connection-manager)

### Mbed OS
* [Arm Mbed OS 6.2.0](https://os.mbed.com/mbed-os/releases)
* [Connectivity Utilities Library](https://github.com/cypresssemiconductorco/connectivity-utilities/releases/tag/latest-v3.X)

## RADIUS Servers
This library has been verified with enterprise Wi-Fi networks configured using the following RADIUS server(s):
* FreeRadius 3.0.15

## Quick Start
This library is supported on both AnyCloud and Mbed OS frameworks. The section below provides information on how to build the library in those frameworks.

### AnyCloud
 A set of pre-defined configuration files have been bundled with the wifi-mw-core library for FreeRTOS, lwIP, and mbed TLS. Review the configuration and make the required adjustments. See the "Quick Start" section in [README.md](https://github.com/cypresssemiconductorco/wifi-mw-core/blob/master/README.md).
   
1. Make the following changes to the default mbed TLS configurations in mbedtls_user_config.h:
   - Enable the following flags:
     `MBEDTLS_DES_C`, `MBEDTLS_MD4_C`, `MBEDTLS_MD5_C`, `MBEDTLS_SHA1_C`, `MBEDTLS_SSL_PROTO_TLS1`, `MBEDTLS_SSL_PROTO_TLS1_1`, and `MBEDTLS_SSL_EXPORT_KEYS`
   - Disable the following flags:
     `MBEDTLS_POLY1305_C`, `MBEDTLS_CHACHAPOLY_C`, and `MBEDTLS_CHACHA20_C`

2. Define the following COMPONENTS in the application's Makefile for the Enterprise Security library.
  ```
    COMPONENTS=FREERTOS PSOC6HAL MBEDTLS LWIP WCM
  ```

3. Enterprise Security library disables all the debug log messages by default. To enable log messages, the application must perform the following:
  - Add `ENABLE_ENTERPRISE_SECURITY_LOGS` macro to the *DEFINES* in the application's Makefile. The Makefile entry would look as follows:
     ```
       DEFINES+=ENABLE_ENTERPRISE_SECURITY_LOGS
     ```
  - Call the `cy_log_init()` function provided by the *cy-log* module. cy-log is part of the *connectivity-utilities* library. See [connectivity-utilities library API documentation](https://cypresssemiconductorco.github.io/connectivity-utilities/api_reference_manual/html/group__logging__utils.html) for cy-log details.

4. By default, the macro `MBEDTLS_HAVE_TIME_DATE` is undefined in mbedtls_user_config.h. If the application wishes to perform time and date validation on the certificate, then enable the `MBEDTLS_HAVE_TIME_DATE` flag in mbedtls_user_config.h.

### Mbed OS

1. Add the .lib file(s) for dependent libraries.

   - Create a folder named `deps`.
   - Create a file with name mbed-os.lib and add the following line to this file:
     ```
     https://github.com/ARMmbed/mbed-os/#a2ada74770f043aff3e61e29d164a8e78274fcd4
     ```
   - Create a file with name connectivity-utilities.lib and add the following line to this file:
     ```
     https://github.com/cypresssemiconductorco/connectivity-utilities/#<commit-SHA-for-latest-release-v3.X>
     ```
   - Replace `<commit-SHA-for-latest-release-v3.X>` in the above line with commit SHA of the latest-v3.X tag available in the [GitHub repository](https://github.com/cypresssemiconductorco/connectivity-utilities/releases/tag/latest-v3.X).
      -  Example: For tag `release-v3.0.1`
         ```
         https://github.com/cypresssemiconductorco/connectivity-utilities/#68bd1bc9883a0ab424eb6daf1e726f0aba2c54a6
         ```

2. Add `MBED` and `MBEDTLS` to the *components_add* section in the application's JSON file. The JSON file entry would look as follows:

   ```
   "target.components_add": ["MBED", "MBEDTLS"]
   ```

3. Enterprise Security library disables all the debug log messages by default. To enable log messages, the application must perform the following:
  - Add `ENABLE_ENTERPRISE_SECURITY_LOGS` macro to the *macros* section in the code example's JSON file. The JSON file entry would look as follows:
     ```
       "macros": ["ENABLE_ENTERPRISE_SECURITY_LOGS"]
     ```
  - Call the `cy_log_init()` function provided by the *cy-log* module. cy-log is part of the *connectivity-utilities* library. See [connectivity-utilities library API documentation](https://cypresssemiconductorco.github.io/connectivity-utilities/api_reference_manual/html/group__logging__utils.html) for cy-log details.

4. Add an mbed TLS user config file (for e.g. mbedtls_user_config.h) with the following changes to the default mbed TLS configuration:
   - Enable the following flags:
     `MBEDTLS_DES_C`, `MBEDTLS_MD4_C`, `MBEDTLS_MD5_C`, `MBEDTLS_SHA1_C`, `MBEDTLS_SSL_PROTO_TLS1`, `MBEDTLS_SSL_PROTO_TLS1_1`, and `MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES`
   - Disable the following flags:
     `MBEDTLS_POLY1305_C`, `MBEDTLS_CHACHAPOLY_C`, and `MBEDTLS_CHACHA20_C`
     
5. If the application wishes to perform time and date validation on the certificate, enable the `MBEDTLS_HAVE_TIME_DATE` flag in the mbed TLS user config file created in the step above.

6. Provide the path to the mbed TLS user config file in the application's JSON file. The JSON file entry would look as follows:
   ```
   "macros": ["MBEDTLS_USER_CONFIG_FILE=\"mbedtls_user_config.h\""]
   ```

### Additional Information
* [Enterprise Security RELEASE.md](./RELEASE.md)
* [Enterprise Security API reference guide](https://cypresssemiconductorco.github.io/enterprise-security/api_reference_manual/html/index.html)
* [ModusToolbox® Software Environment, Quick Start Guide, Documentation, and Videos](https://www.cypress.com/products/modustoolbox-software-environment)
* [Enterprise Security library version](./version.txt)
