# Cypress Enterprise Security Middleware Library

### Overview
This library provides the capability for Cypress's best in class Wi-Fi enabled 
PSoC6 devices to connect to enterprise Wi-Fi networks. This library implements 
a collection of the most commonly used Extensible Authentication Protocolx (EAP) 
that are used in enterprise networks. 

### Features
This section provides details on the list of enterprise security Wi-Fi features 
supported by this library:
* Supports following EAP security protocols: 
    * EAP-TLS
    * PEAPv0 with MSCHAPv2
    * EAP-TTLS with EAP-MSCHAPv2
* Supports TLS session (session ID based) resumption.
* Supports 'PEAP Fast reconnect' (this is applicable only for PEAP protocol).
* Supports roaming across APs in the enterprise network (vanilla roaming)
* Supports TLS versions 1.0, 1.1, and 1.2

### Supported Platforms
This middleware library and it's features are supported on following Cypress platforms:
* [PSoC6 WiFi-BT Prototyping Kit (CY8CPROTO-062-4343W)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wi-fi-bt-prototyping-kit-cy8cproto-062-4343w)
* [PSoC6 WiFi-BT Pioneer Kit (CY8CKIT-062-WiFi-BT)](https://www.cypress.com/documentation/development-kitsboards/psoc-6-wifi-bt-pioneer-kit-cy8ckit-062-wifi-bt)

### Dependencies
This section provides the list of dependency libraries required for this 
middleware library to work:
* [ARM mbed-os stack version 5.14 and above](https://os.mbed.com/mbed-os/releases)
* [Cypress Connectivity Utilities Library](https://github.com/cypresssemiconductorco/connectivity-utilities)

### Additional Information
* [Enterprise Security RELEASE.md](./RELEASE.md)
* [Enterprise Security API reference guide](https://cypresssemiconductorco.github.io/enterprise-security/api_reference_manual/html/index.html)
* [Enterprise Security library version](./version.txt)
