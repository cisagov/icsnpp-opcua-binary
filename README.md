# ICSNPP-OPCUA_Binary

Industrial Control Systems Network Protocol Parsers (ICSNPP) - OPC Unified Architecture Binary (OPC UA Binary).

## Overview

ICSNPP-OPCUA_Binary is a Zeek plugin for parsing and logging fields within the OPC Unified Architecture Binary protocol.

The OPC Unified Architecture defines three data encodings: - OPC UA Binary, OPC UA XML, and OPC UA JSON. This plugin targets the OPC UA Binary encoding.

Specification details can be found on the OPC Foundation Org website located [here](https://opcfoundation.org/developer-tools/specifications-unified-architecture)

The initial implementation of the parser focuses on logging the message type and the service request and response headers, along with any diagnostic and error information that may be present. The service numeric identifier and associated identifier string are also logged; however, the details of the service being called have been stubbed out for most of the services. Future development on the parser will focus on filling out this information.

This parser produces a variety of different log files. An overview of these log files can be found in the Logging Capabilities section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-opcua-binary
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly you will see `ICSNPP::OPCUA_Binary`.

If ZKG is configured to load packages (see @load packages in quickstart guide), this plugin and these scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp/opcua-binary` to the command to run this plugin's scripts on the packet capture:

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

If these commands succeed, users will end up with a newly created build directory that contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::OPCUA_Binary
```

Once users have tested the functionality locally and it appears to have compiled correctly, they can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::OPCUA_Binary
```

To run this plugin in a site deployment, users will need to add the line `@load icsnpp/opcua-binary` to the `site/local.zeek` file to load this plugin's scripts.

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp/opcua-binary` to the command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr <sample packet capture> icsnpp/opcua-binary
```

If users want to deploy this on an already existing Zeek implementation and don't want to build the plugin on the machine, they can extract the ICSNPP_OPCUA_Binary.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/ICSNPP_OPCUA_Binary.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

#### Primary Log (opcua_binary.log)

This log captures the OPCUA message header, message type (HEL, ACK, MSG), service request/response headers, along with the service identifier, and logs it to **opcua_binary.log**. 

* See the ```OPCUA_Binary::Info: record``` in file [types.zeek](scripts/types.zeek) for a list of the fields logged.

### OPCUA Type Logging

#### Diagnostic Information Detail (opcua_binary_diag_info_detail.log)

This log captures the details of any diagnostic information present in the service response header and logs it to **opcua_binary_diag_info_detail.log**.

* See the ```OPCUA_Binary::DiagnosticInfoDetail: record``` in file [statuscode-diagnostic-types.zeek](scripts/statuscode-diagnostic-types.zeek) for a list of the fields logged.
* See the ```type OpcUA_DiagInfo = record``` in file [opcua_binary-types.pac](src/types/opcua_binary-types.pac) for details on the diagnostic information structure.
* See [opcua_binary-req_res_header_analyzer.pac](src/req-res-header/opcua_binary-req_res_header_analyzer.pac) for details on processing this information.

#### Status Code Detail (opcua_binary_status_code_detail.log)

This log captures the details of any status codes in the service response header and logs it to **opcua_binary_status_code_detail.log**. 

* See the ```OPCUA_Binary::StatusCodeDetail: record``` in file [statuscode-diagnostics-types.zeek](scripts/statuscode-diagnostic-types.zeek) for a list of the fields logged.
* See [status_codes.h](src/headers/status_codes.h) for a list of status codes and their associated information. 
* See [opcua_binary-req_res_header_analyzer.pac](src/req-res-header/opcua_binary-req_res_header_analyzer.pac) for details on processing this information.

#### Filter Detail (opcua_binary_aggregate_filter.log, opcua_binary_data_change_filter.log, opcua_binary_event_filter.log, opcua_binary_event_filter_attribute_operand.log, opcua_binary_event_filter_attribute_operand_browse_paths.log, opcua_binary_event_filter_where_clause.log, opcua_binary_event_filter_where_clause_elements.log, opcua_binary_event_filter_element_operand.log, opcua_binary_event_filter_literal_operand.log, opcua_binary_event_filter_select_clause.log, opcua_binary_event_filter_simple_attribute_operand.log, opcua_binary_event_filter_simple_attribute_operand_browse_paths.log)

This log captures the details associated with filter objects.

* See [filter-types.zeek](scripts/filter-types.zeek) for a list of the fields logged.
* See [opcua_binary-filter_types.pac](src/types/filters/opcua_binary-filter_types.pac), [opcua_binary-filter_types_analyzer.pac](src/types/filters/opcua_binary-filter_types_analyzer.pac), and [opcua_binary-filter_types_debug.pac](src/types/filters/opcua_binary-filter_debug.pac) for details on parsing, processing, and logging this service.

#### Variant Detail (opcua_binary_variant_array_dims.log, opcua_binary_variant_data.log, opcua_binary_variant_data_value.log, opcua_binary_variant_extension_object.log, opcua_binary_variant_metadata.log)

This log captures the details associated with variant objects.

* See [variant-types.zeek](scripts/variant-types.zeek) for a list of the fields logged.
* See [opcua_binary-variant_types.pac](src/types/variants/opcua_binary-variant_types.pac), [opcua_binary-variant_types_analyzer.pac](src/types/variants/opcua_binary-variant_types_analyzer.pac), and [opcua_binary-variant_types_debug.pac](src/types/variants/opcua_binary-variant_types_debug.pac) for details on parsing, processing, and logging this service.

### OPCUA Services Logging

#### Activate Session Service (opcua_binary_activate_session.log, opcua_binary_activate_session_client_software_cert.log, opcua_binary_activate_session_locale_id.log)

This log captures the details associated with calls to the Activate Session Service.

* See [activate-session-types.zeek](scripts/activate-session-types.zeek) for a list of the fields logged.
* See [opcua_binary-activate_session.pac](src/services/activate-session/opcua_binary-activate_session.pac), [opcua_binary-activate_session_analyzer.pac](src/services/activate-session/opcua_binary-activate_session_analyzer.pac), and [opcua_binary-activate_session_debug.pac](src/services/activate-session/opcua_binary-activate_session_debug.pac) for details on parsing, processing, and logging this service.

#### Browse Service (opcua_binary_browse.log, opcua_binary_browse_description.log, opcua_binary_browse_request_continuation_point.log, opcua_binary_browse_result.log, opcua_binary_browse_response_references.log)

This log captures the details associated with calls to the Browse Service.

* See [browse-types.zeek](scripts/browse-types.zeek) for a list of the fields logged.
* See [opcua_binary-browse.pac](src/services/browse/opcua_binary-browse.pac), [opcua_binary-browse_analyzer.pac](src/services/browse/opcua_binary-browse_analyzer.pac), and [opcua_binary-browse_debug.pac](src/services/browse/opcua_binary-browse_debug.pac) for details on parsing, processing, and logging this service.

#### Close Session Service (opcua_binary_close_session.log)

This log captures the details associated with calls to the Close Session Service.

* See [close-session-types.zeek](scripts/create-session-types.zeek) for a list of the fields logged.
* See [opcua_binary-close-session.pac](src/services/close-session/opcua_binary-close-session.pac), [opcua_binary-close-session.pac](src/services/close-session/opcua_binary-close-session_analyzer.pac), and [opcua_binary-close-session_debug.pac](src/services/close-session/opcua_binary-close-session_debug.pac) for details on parsing, processing, and logging this service.
#### Create Monitored Items Service (opcua_binary_create_monitored_items.log, opcua_binary_create_monitored_items_create_item.log)

This log captures the details associated with calls to the Create Session Service.

* See [create-monitored-items-types.zeek](scripts/create_monitored_items-types.zeek) for a list of the fields logged.
* See [opcua_binary-create_monitored_items.pac](src/services/create_monitored_items/opcua_binary-create_monitored_items.pac), [opcua_binary-create_monitored_items_analyzer.pac](src/services/create_monitored_items/opcua_binary-create_monitored_items_analyzer.pac), and [opcua_binary-create_monitored_items_debug.pac](src/services/create_monitored_items/opcua_binary-create_monitored_items_debug.pac) for details on parsing, processing, and logging this service.

#### Create Session Service (opcua_binary_create_session.log, opcua_binary_create-session_discovery.log, opcua_binary_create_session_endpoints.log, opcua_binary_create_session_user_token.log)

This log captures the details associated with calls to the Create Session Service.

* See [create-session-types.zeek](scripts/create-session-types.zeek) for a list of the fields logged.
* See [opcua_binary-create_session.pac](src/services/create-session/opcua_binary-create_session.pac), [opcua_binary-create_session_analyzer.pac](src/services/create-session/opcua_binary-create_session_analyzer.pac), and [opcua_binary-create_session_debug.pac](src/services/create-session/opcua_binary-create_session_debug.pac) for details on parsing, processing, and logging this service.

#### Create Subscription Service (opcua_binary_create_subscription.log)

This log captures the details associated with calls to the Create Subscription Service.

* See [create_subscription-types.zeek](scripts/create-subscription-types.zeek) for a list of the fields logged.
* See [opcua_binary-create_subscription.pac](src/services/create-subscription/opcua_binary-create_subscription.pac), [opcua_binary-create_subscription_analyzer.pac](src/services/create-subscription/opcua_binary-create_subscription_analyzer.pac), and [opcua_binary-create_subscription_debug.pac](src/services/create-subscription/opcua_binary-create_subscription_debug.pac) for details on parsing, processing, and logging this service.

#### Get Endpoints Service (opcua_binary_get_endpoints.log, opcua_binary_get_endpoints_description.log, opcua_binary_get_endpoints_discovery.log, opcua_binary_get_endpoints_locale_id.log, opcua_binary_get_endpoints_profile_uri.log, opcua_binary_get_endpoints_user_token.log)

This log captures the details associated with calls to the Get Endpoints Service.

* See [get-endpoints-types.zeek](scripts/get-endpoints-types.zeek) for a list of the fields logged.
* See [opcua_binary-get_endpoints.pac](src/services/get-endpoints/opcua_binary-get_endpoints.pac), [opcua_binary-get_endpoints_analyzer.pac](src/services/get-endpoints/opcua_binary-get_endpoints_analyzer.pac), and [opcua_binary-get_endpoints_debug.pac](src/services/get-endpoints/opcua_binary-get_endpoints_debug.pac) for details on parsing, processing, and logging this service.

#### Read Subscription Service (opcua_binary_read.log, opcua_binary_read_nodes_to_read.log, opcua_binary_read-results.log)

This log captures the details associated with calls to the Read Subscription Service.

* See [read-types.zeek](scripts/read-types.zeek) for a list of the fields logged.
* See [opcua_binary-read.pac](src/services/read/opcua_binary-read.pac), [opcua_binary-read_analyzer.pac](src/services/read/opcua_binary-read_analyzer.pac), and [opcua_binary-read_debug.pac](src/services/read/opcua_binary-read_debug.pac) for details on parsing, processing, and logging this service.

#### Open Secure Channel Service (opcua_binary_opensecure_channel.log)

This log captures the details associated with calls to the Open Secure Channel Service.

* See the ```OPCUA_Binary::OpenSecureChannel: record``` in file [secure-channel-types.zeek](scripts/secure-channel-types.zeek) for a list of the fields logged.
* See [opcua_binary-secure_channel.pac](src/services/secure-channel/opcua_binary-secure_channel.pac), [opcua_binary-secure_channel_analyzer.pac](src/services/secure-channel/opcua_binary-secure_channel.pac), and [opcua_binary-secure_channel_debug.pac](src/services/secure-channel/opcua_binary-secure_channel_debug.pac) for details on parsing, processing, and logging this service.

#### Write Subscription Service (opcua_binary_write.log)

This log captures the details associated with calls to the Write Subscription Service.

* See [write-types.zeek](scripts/write-types.zeek) for a list of the fields logged.
* See [opcua_binary-write.pac](src/services/write/opcua_binary-write.pac), [opcua_binary-write_analyzer.pac](src/services/write/opcua_binary-write_analyzer.pac), and [opcua_binary-write_debug.pac](src/services/write/opcua_binary-write_debug.pac) for details on parsing, processing, and logging this service.

## Developer's Guide

For development and implementation details, see the [developer_guide](developer_guide.md)

## Coverage
Roughly 70% of the defined specification is covered by this parser implementation.  The implementation includes the top level message header information such as the Msg_HEL, Msg_ACK, Msg_ERR, Msg_OPN, Msg_MSG, and Msg_CLO.  The parser also captures the OpcUA StatusCode information along with the OpcUA Diagnostic information.  With regards to the services implemented, the parser covers ~26% of the services available as there are 42 services in total with 11 of those services implemented.  See the [Logging Capabilities](#logging-capabilities) section for detailed information of the parser coverage.

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
* [GE SRTP](https://github.com/cisagov/icsnpp-ge-srtp)
    * Full Zeek protocol parser for GE SRTP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)
* [Profinet IO CM](https://github.com/cisagov/icsnpp-profinet-io-cm)
    * Full Zeek protocol parser for Profinet I/O Context Manager

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### License

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE.txt`](./LICENSE.txt)).
