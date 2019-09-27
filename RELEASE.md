# Cypress Enterprise Security Middleware Library

## What's Included?
Refer to the [README.md](./README.md) for a complete description of the enterprise security library

## Changelog
### v1.0.0
* Initial release for ARMmbed mbed-os
* Supports EAP protocols required to connect to enterprise Wi-Fi networks
    - Supports following EAP security protocols:
        * EAP-TLS
        * PEAPv0 with MSCHAPv2
        * EAP-TTLS with EAP-MSCHAPv2
    - Supports TLS session (session ID based) resumption.
    - Supports 'PEAP Fast reconnect' (this is applicable only for PEAP protocol).
    - Supports roaming across APs in the enterprise network ( vanilla roaming)
    - Supports TLS versions 1.0, 1.1, and 1.2
### Supported Software and Tools
This version of the Middleware was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version |
| :---                                                    | :----:  |
| GCC Compiler                                            | 7.2.1   |
| IAR Compiler                                            | 8.32    |
| ARM Compiler 6                                          | 6.11    |
| MBED OS                                                 | 5.14    |
