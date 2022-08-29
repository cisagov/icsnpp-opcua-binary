# Sample Packet Captures

## Overview

Sample packet captures used for testing were generated using the open2541 OPC-UA implementation and the Python OPC-UA implementation.  The sample packet captures have been named according to the implementation that generated them.  Additional information regarding these implementations can be found at:

* https://open62541.org/
* https://python-opcua.readthedocs.io/en/latest/

## Files

| Filename                                                          | Description                                                                                                                                         |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| open62541_client-server_encrypted.pcap                            | Example showing encrypted communications.                                                                                                           |
| open62541_client-server-getEndpoints.pcap                         | Example showing a simple getEndpoints service request/response                                                                                      |
| open62541_discover_getendpoints_discover_urls.pcap                | Example showing the getEndpoints service response with an array of DiscoveryUrls and an array of UserIdentityTokens in the response.                |
| open62541_client-server_mainloop-hasInnerStatusCode.pcap          | Example showing the OpenSecureChannel service response with an inner status code.                                                                   |
| open62541_client-server_mainloop-hasInnerDiagInfo.pcap            | Example showing the OpenSecureChannel service response with 1 inner diagnostic info along with an inner status code.                                |
| open62541_client-server_mainloop-4-InnerDiagInfo.pcap             | Example showing the OpenSecureChannel service response with 4 inner diagnostic info(s) each with an inner status code.                              |
| open62541_client-server_mainloop-hasInnerDiagInfohasAddlInfo.pcap | Example showing the OpenSecureChannel service response with 4 inner diagnostic info(s) each with an inner status code and one with additional info. |
| open62541_client-server_mainloop-withStringTable.pcap             | Example showing the OpenSecureChannel service response with a StringTable array along with inner diagnostic info(s)                                 |
| open62541_client-server_mainloop-not-localhost.pcap               | Generic OPCUA Binary communications with IPv4  addresses and NOT IPV6 localhost source/destination addresses.                                       |
| open62541_client-server_mainloop.pcap                             | Generic OPCUA Binary communications.                                                                                                                |
| open62541_client-server_minimal.pcap                              | Generic OPCUA Binary communications.                                                                                                                |
| python_opcua-client-server_encrypted.pcap                         | Example showing encrypted communications.                                                                                                           |
| python_opcua-client-server_minimal-2.pcap                         | Generic OPCUA Binary communications.                                                                                                                |
| python_opcua-client-server_minimal.pcap                           | Generic OPCUA Binary communications.                                                                                                                |
| open62541_browse_has_server_idx.pcap                              | Example showing the browse service with a server index.                                                                                             |
| open62541_browse_next.pcap                                        | Example showing the browse next service.                                                                                                            |
| open62541_browse_request_with_results.pcap                        | Example showing the browse service with cooresponding results.                                                                                      |
| open62541_browse_with_diagnostic_info.pcap                        | Example showing the browse service with diagnostic information in the response.                                                                     |
| open62541_client-server_mainloop-ActivateSession-diagInfo.pcap    | Example showing the activate session service with diagnotic information in the response.                                                            |