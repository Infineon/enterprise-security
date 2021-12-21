# Enterprise Security Middleware Library

## What's Included?
Refer to [README.md](./README.md) for a complete description of the enterprise security library.

## Changelog

### v2.1.0
* Added support for CY8CEVAL-062S2-MUR-43439M2 kit

### v2.0.1
* Fixed sending the TLS alert message when server passes certificate with Unknown CA.

### v2.0.0
* Updated interface definitions, API return type, and header file names.
* Added support for AnyCloud framework.
* Upgraded Mbed OS support to Mbed OS v6.2.0.

### v1.0.0
* Initial release for Arm Mbed OS
* Supports EAP protocols required to connect to enterprise Wi-Fi networks
    - Supports the following EAP security protocols:
        * EAP-TLS
        * PEAPv0 with MSCHAPv2
        * EAP-TTLS with EAP-MSCHAPv2 (Phase 2 tunnel authentication supports only EAP methods)
    - Supports TLS session (session ID based) resumption
    - Supports 'PEAP Fast reconnect' (applicable only for PEAP protocol)
    - Supports roaming across APs in the enterprise network (vanilla roaming)
    - Supports TLS versions 1.0, 1.1, and 1.2

## Supported Software and Tools
This version of the Middleware was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version |
| :---                                                    | :----:  |
| ModusToolbox® software environment                      | 2.4     |
| - ModusToolbox Device Configurator                      | 3.10    |
| - ModusToolbox CapSense Configurator / Tuner tools      | 4.0     |
| PSoC 6 Peripheral Driver Library (PDL)                  | 2.3.0   |
| GCC Compiler                                            | 10.3.1  |
| IAR Compiler                                            | 8.32    |
| Arm® Compiler 6                                         | 6.14    |
| Mbed OS                                                 | 6.2     |
