# ICSNPP-OPCUA_Binary

Industrial Control Systems Network Protocol Parsers (ICSNPP) - OPC Unified Architecture Binary (OPC UA Binary).

## Overview

ICSNPP-OPCUA_Binary is a Zeek plugin for parsing and logging fields within the OPC Unified Architecture Binary protocol.

The OPC Unified Architecture defines three data encodings: - OPC UA Binary, OPC UA XML, and OPC UA JSON. This plugin targets the OPC UA Binary encoding.

Specification details can be found on the OPC Foundation Org website located [here](https://opcfoundation.org/developer-tools/specifications-unified-architecture)

The initial implementation of the parser focuses on logging the message type, the service request and response headers along with any diagnostic and error information that may be present. The service numeric identifier and associated identifier string are also logged. However, the details of the service being called have been stubbed out for a majority of the services. Future development on the parser will focus on filling out this information.

This parser produces a variety of different log files. An overview of these log files can be found in the Logging Capabilities section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-opcua-binary
```

If this package is installed from ZKG it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly you will see `ICSNPP::OPCUA_Binary`.

If you have ZKG configured to load packages (see @load packages in quickstart guide), this plugin and scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/opcua-binary` to your command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-opcua-binary.git
zeek -Cr <sample packet capture> icsnpp/opcua-binary
```

### Manual Install

To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-opcua-binary.git
cd icsnpp-opcua-binary/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::OPCUA_Binary
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::OPCUA_Binary
```

To run this plugin in a site deployment you will need to add the line `@load icsnpp/opcua-binary` to your `site/local.zeek` file in order to load this plugin's scripts.

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/opcua-binary` to your command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr <sample packet capture> icsnpp/opcua-binary
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the ICSNPP_OPCUA_Binary.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/ICSNPP_OPCUA_Binary.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### Primary Log (opcua-binary.log)

This log captures the OPCUA message header, message type (HEL, ACK, MSG), service request/response headers along with the service identifier and logs it to **opcua-binary.log**. 

* See the ```OPCUA_Binary::Info: record``` in file [types.zeek](scripts/types.zeek) for a list of the fields logged.

### Status Code Detail (opcua-binary-status-code-detail.log)

This log captures the details of any status codes in the service response header and logs it to **opcua-binary-status-code-detail.log**. 

* See the ```OPCUA_Binary::StatusCodeDetail: record``` in file [statuscode-diagnostics-types.zeek](scripts/statuscode-diagnostic-types.zeek) for a list of the fields logged.
* See [status_codes.h](src/status_codes.h) for a list of status codes and their associated information. 
* See [opcua_binary-req_res_header_analyzer.pac](src/req-res-header/opcua_binary-req_res_header_analyzer.pac) for details on processing this information.

### Diagnostic Information Detail (opcua-binary-diag-info-detail.log)

This log captures the details of any diagnostic information present in the service response header and logs it to **opcua-binary-diag-info-detail.log**.

* See the ```OPCUA_Binary::DiagnosticInfoDetail: record``` in file [statuscode-diagnostic-types.zeek](scripts/statuscode-diagnostic-types.zeek) for a list of the fields logged.
* See the ```type OpcUA_DiagInfo = record``` in file [opcua_binary-types.pac](src/opcua_binary-types.pac) for details on the diagnostic information structure.
* See [opcua_binary-req_res_header_analyzer.pac](src/req-res-header/opcua_binary-req_res_header_analyzer.pac) for details on processing this information.

### Open Secure Channel Service (opcua-binary-opensecure-channel.log)

This log captures the details associated with calls to the Open Secure Channel Service.

* See the ```OPCUA_Binary::OpenSecureChannel: record``` in file [secure-channel-types.zeek](scripts/secure-channel-types.zeek) for a list of the fields logged.
* See [opcua_binary-secure_channel.pac](src/secure-channel/opcua_binary-secure_channel.pac), [opcua_binary-secure_channel_analyzer.pac](src/secure-channel/opcua_binary-secure_channel.pac), and [opcua_binary-secure_channel_debug.pac](src/secure-channel/opcua_binary-secure_channel_debug.pac) for details on parsing, processing, and logging this service.

### Get Endpoints Service (opcua-binary-get-endpoints.log, opcua-binary-get-endpoints-discovery.log, opcua-binary-get-endpoints-user_token.log, opcua-binary-get-endpoints-description.log, opcua-binary-get-endpoints-locale_id.log, opcua-binary-get-endpoints-profile_url.log)

This log captures the details associated with calls to the Get Endpoints Service.

* See [get-endpoints-types.zeek](scripts/get-endpoints-types.zeek) for a list of the fields logged.
* See [opcua_binary-get_endpoints.pac](src/get-endpoints/opcua_binary-get_endpoints.pac), [opcua_binary-get_endpoints_analyzer.pac](src/get-endpoints/opcua_binary-get_endpoints_analyzer.pac), and [opcua_binary-get_endpoints_debug.pac](src/get-endpoints/opcua_binary-get_endpoints_debug.pac) for details on parsing, processing, and logging this service.

### Create Session Service (opcua-binary-create-session.log, opcua-binary-create-session-user-token.log, opcua-binary-create-session-endpoints.log, opcua-binary-create-session-discovery.log)

This log captures the details associated with calls to the Create Session Service.

* See [create-session-types.zeek](scripts/create-session-types.zeek) for a list of the fields logged.
* See [opcua_binary-create_session.pac](src/create-session/opcua_binary-create_session.pac), [opcua_binary-create_session_analyzer.pac](src/create-session/opcua_binary-create_session_analyzer.pac), and [opcua_binary-create_session_debug.pac](src/create-session/opcua_binary-create_session_debug.pac) for details on parsing, processing, and logging this service.

### Activate Session Service (opcua-binary-activate-session.log, opcua-binary-activate-session-client-software-cert.log, opcua-binary-activate-session-locale-id.log, opcua-binary-activate-session-diagnostic-info.log)

This log captures the details associated with calls to the Activate Session Service.

* See [activate-session-types.zeek](scripts/activate-session-types.zeek) for a list of the fields logged.
* See [opcua_binary-activate_session.pac](src/activate-session/opcua_binary-activate_session.pac), [opcua_binary-activate_session_analyzer.pac](src/activate-session/opcua_binary-activate_session_analyzer.pac), and [opcua_binary-activate_session_debug.pac](src/activate-session/opcua_binary-activate_session_debug.pac) for details on parsing, processing, and logging this service.

### Browse Service (opcua-binary-browse.log, opcua-binary-browse-description.log, opcua-binary-browse-request-continuation-point.log, opcua-binary-browse-result.log, opcua-binary-browse-response-references.log, opcua-binary-browse-diagnostic-info.log)

This log captures the details associated with calls to the Browse Service.

* See [browse-types.zeek](scripts/browse-types.zeek) for a list of the fields logged.
* See [opcua_binary-browse.pac](src/browse/opcua_binary-browse.pac), [opcua_binary-browse_analyzer.pac](src/browse/opcua_binary-browse_analyzer.pac), and [opcua_binary-browse_debug.pac](src/browse/opcua_binary-browse_debug.pac) for details on parsing, processing, and logging this service

### Create Subscription Service (opcua-binary-create-subscription.log)

This log captures the details associated with calls to the Create Subscription Service.

* See [create_subscription-types.zeek](scripts/create-subscription-types.zeek) for a list of the fields logged.
* See [opcua_binary-create_subscription.pac](src/create-subscription/opcua_binary-create_subscription.pac), [opcua_binary-create_subscription_analyzer.pac](src/create-subscription/opcua_binary-create_subscription_analyzer.pac), and [opcua_binary-create_subscription_debug.pac](src/create-subscription/opcua_binary-create_subscription_debug.pac) for details on parsing, processing, and logging this service

## Developer's Guide

For development and implementation details, see the [developer_guide](developer_guide.md)

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2022 Battelle Energy Alliance, LLC

Licensed under the 3-Part BSD (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




Licensing
-----
This software is licensed under the terms you may find in the file named "LICENSE" in this directory.
