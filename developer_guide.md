# Implementation and Architecture Details

## Processing
Generally speaking, the architecture can be divided into three layers - zeek scripts, analyzers, and binpac processing.  Ultimately, these three layers get boiled down to C++ code.  The parser leverages this fact extensively when parsing and logging the protocol.

The analyzer layer is the glue between the other two layers and maps the results from the binpac parsing into zeek scripting objects that can then be logged.  The following code snippets will help clarify the architecture with a concrete example.

At the binpac layer we declare the following structures and delivery function.

```bash
type Msg_Header = record {
    msg_type   : bytestring &length = 3;
    is_final   : bytestring &length = 1;
    msg_size   : uint32;
    type       : case($context.flow.bytestring_to_uint32(msg_type)) of {
        HEL  -> hel: Msg_HEL(this);
    };
} &byteorder=littleendian;

type Msg_HEL(header: Msg_Header) = record {
    version       : uint32;
    rcv_buf_size  : uint32;
    snd_buf_size  : uint32;
    max_msg_size  : uint32;
    max_chunk_cnt : uint32;
} &let {
    deliver: bool = $context.flow.deliver_Msg_HEL(this);
} &byteorder=littleendian;
```

At the scripting layer we declare the following logging record.  Take note of the similarities between the fields declared in the logging record and the fields declared at the binpac layer above.

```bash
module OPCUA_Binary;
export {
    type OPCUA_Binary::Info: record {
        ts                            : time    &log;
        uid                           : string  &log;
        id                            : conn_id &log;

        msg_type                      : string  &log;
        is_final                      : string  &log;
        msg_size                      : count   &log;

        # Msg_HEL
        version                       : count   &log &optional;
        rcv_buf_size                  : count   &log &optional;
        snd_buf_size                  : count   &log &optional;
        max_msg_size                  : count   &log &optional;
        max_chunk_cnt                 : count   &log &optional;
    };
}
```

At the analyser level, we declare the delivery function `deliver_Msg_HEL`.

Note the argument to this function is of type `Msg_HEL` which was declared earlier at the binpac layer.  Also note the `zeek::RecordValPtr` declaration inside the function and the `zeek::BifType::Record::OPCUA_Binary::Info` used as an argument.  This argument is the resulting C++ object from the `type OPCUA_Binary::Info: record` declaration at the scripting layer.

The `zeek::RecordValPtr` is used to assign the values from the `Msg_HEL` object the binpac parser provided.  The indexes into the `zeek::RecordValPtr` start at 0 and map to the field positions of the `OPCUA_Binary::Info: record` - e.g. field ts = index 0, field uid = index 1, etc.

Finally, the function processing enqueues a BifEvent which triggers the logging process on the scripting side.

```bash
#
# Message Hello
#
function deliver_Msg_HEL(msg_hel: Msg_HEL): bool
    %{
    // Get a RecordValPtr to the scripting side OPCUA_Binary::Info object
    zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

    //
    // Map the Msg header details.  Note: Start at index 3 to take into account the ts, uid, and id fields
    // will be mapped on the scripting side just before the information is written to the log file.
    //
    info->Assign(3, zeek::make_intrusive<zeek::StringVal>(std_str(msg_hel->header()->msg_type())));
    info->Assign(4, zeek::make_intrusive<zeek::StringVal>(std_str(msg_hel->header()->is_final())));
    info->Assign(5, zeek::val_mgr->Count(msg_hel->header()->msg_size()));

    // Map the Msg HEL details
    info->Assign(6,  zeek::val_mgr->Count(msg_hel->version()));
    info->Assign(7,  zeek::val_mgr->Count(msg_hel->rcv_buf_size()));
    info->Assign(8,  zeek::val_mgr->Count(msg_hel->snd_buf_size()));
    info->Assign(9,  zeek::val_mgr->Count(msg_hel->max_msg_size()));
    info->Assign(10, zeek::val_mgr->Count(msg_hel->max_chunk_cnt()));

    // Fire the event to log the info.
    zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                               connection()->bro_analyzer()->Conn(),
                                               info);

    return true;
    %}
```

Back at the scripting layer, a logging stream is created with the defined columns based off the `OPCUA_Binary::Info` object declared earlier.  The event is processed in the opcua_binary_event function by mapping the ts, uid, and id fields in the `OPCUA_Binary::Info` structure.  Finally, the information is written to the log file.

```bash
event zeek_init() &priority=5
   {
   Log::create_stream(OPCUA_Binary::LOG, [$columns=OPCUA_Binary::Info, $path="opcua-binary"]);
   }

event opcua_binary_event(c: connection, info: OPCUA_Binary::Info)
   {
       info$ts  = network_time();
       info$uid = c$uid;
       info$id  = c$id;
       Log::write(OPCUA_Binary::LOG, info);
    }
```

The above example provides a simplified implementation for processing the protocols "Hello" message.  The example can be extended to process more complex types and structures defined by the protocol.

## Directory Structure

The directory structure primarily consists of a `scripts` directory which contains the Zeek scripts that make up the scripting layer and the `src` directory which contains a combination of C/C++ source files and binpac files. These files make up the analyzer and binpac layers. Due to the quantity of files, the `src` directory is divided into subdirectories. Genereic files and processing folders used to perform basic processing are stored in the `src` parent directory. Maps for enumerations are in the `headers` folder. Index-consts.h files do not belong in the `headers` directory. The `services` folder contains parsing for individual OPCUA services grouped by service. Finally, the `types` folder contains OPCUA structures that are used across multiple services but are not services in and of themselves. In an effort to provide some additional organization to the file structure, a file naming convention has been (loosely) adopted for processing the protocol services along with the service request/response headers.  The following table describes the naming convention.

Please note that when including files, it is necessary to import the files in the `headers` directory and the `types` directory first. By convention, the imports are alphabatized. 

### Naming Convention

| Filename                                   | Description                                                                                                   |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| `opcua_binary-<service_name>.pac`          | `Binpac code describing the protocol structure.`                                                              |
| `opcua_binary-<service_name>_analyzer.pac` | `C/C++ code used to process the parsed information and map to the corresponding scripting object for logging` |
| `opcua_binary-<service_name>_debug.pac `   | `C/C++ code used to verify the parsed information is as expected.`                                            |

### Files of interest

| Filename                                                           | Description                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`scripts/OPCUA/Binary/main.zeek`](scripts/OPCUA/Binary/main.zeek) | `Log stream definitions and log event processing`                                                                                                                                                                                             |
| [`scripts/types.zeek`](scripts/types.zeek)                         | `Zeek script type/record definitions describing the information that will be written to the log files.  Each service implemented has type/record definations declared in a file with the naming convention scripts/<service-name>-types.zeek` |
| [`src/index-consts.h`](src/index-consts.h)                         | `Constants used for assignment indexes when mapping in the analyzers.  Each service implemented has index constants declared in a directory with the naming convention src/<service-name>/index-consts.h`                                     |
| [`src/events.bif`](src/events.bif)                                 | `Event definitions used by the analyzers.`                                                                                                                                                                                                    |
| [`src/opcua_binary-analyzer.pac`](src/opcua_binary-analyzer.pac)   | `Message type processing and analyzer utility functions.`                                                                                                                                                                                     |
| [`src/opcua_binary-services.pac`](src/opcua_binary-services.pac)   | `Binpac processing that identifies which service was called.`                                                                                                                                                                                 |
| [`src/opcua_binary-types.pac`](src/opcua_binary-types.pac)         | `Binpac type definitions that correspond to the types defined in the OPCUA documentation.`                                                                                                                                                    |
| [`src/opcua_binary.pac`](src/opcua_binary.pac)                     | `Primary binpac file.  This is where the other *.pac files get %included.`                                                                                                                                                                    |
| [`src/types.bif`](src/types.bif)                                   | `Type/record definitions that correspond to the definitions in scripts/types.zeek.  This enables the types to be visible in the analyzers.`                                                                                                   |

## Data Verification

Using the resulting log files to verify the data is being parsed and processed correctly can be difficult as the missing and/or empty fields cause the file format to shift drastically.  For this reason, debug code was developed and placed in the *_debug.pac files.  The format of the debug output corresponding with the format of Wireshark and makes data verification easier.  See [opcua_binary-get_endpoints_debug.pac](src/opcua_binary-get_endpoints_debug.pac) for an example implementations.

Note: Some of the *_debug.pac code has been stubbed out.


## Future Development

### Services
The following table shows the services that have been stubbed out and currently log just the service request/response header information.  Future development will focus on processing and logging this information.

| Service                                 | Service                                 | Service
| --------------------------------------- | --------------------------------------- | --------------------------------------- |
| `CancelRequest`                         | `FindServersRequest`                    | `FindServersResponse`                   |
| `FindServersOnNetworkRequest`           | `FindServersOnNetworkResponse`          | `RegisterServerRequest`                 |
| `RegisterServerResponse`                | `RegisterServer2Request`                | `RegisterServer2Response`               |
| `CancelResponse`                        | `AddNodesRequest`                       | `AddNodesResponse`                      |
| `AddReferencesRequest`                  | `AddReferencesResponse`                 | `DeleteNodesRequest`                    |
| `DeleteNodesResponse`                   | `DeleteReferencesRequest`               | `DeleteReferencesResponse`              |
| `TranslateBrowsePathsToNodeIdsRequest`  | `TranslateBrowsePathsToNodeIdsResponse` | `RegisterNodesRequest`                  |
| `RegisterNodesResponse`                 | `UnregisterNodesRequest`                | `UnregisterNodesResponse`               | 
| `QueryFirstRequest`                     | `QueryFirstResponse`                    | `QueryNextRequest`                      |
| `QueryNextResponse`                     | `HistoryReadRequest`                    | `HistoryReadResponse`                   |
| `HistoryUpdateRequest`                  |                                         |                                         |
| `HistoryUpdateResponse`                 | `CallRequest`                           | `CallResponse`                          | 
| `ModifyMonitoredItemsRequest`           | `ModifyMonitoredItemsResponse`          | `SetMonitoringModeRequest`              | 
| `SetMonitoringModeResponse`             | `SetTriggeringRequest`                  | `SetTriggeringResponse`                 | 
| `DeleteMonitoredItemsRequest`           | `DeleteMonitoredItemsResponse`          | `ModifySubscriptionRequest`             | 
| `ModifySubscriptionResponse`            | `SetPublishingModeRequest`              | `SetPublishingModeResponse`             | 
| `PublishRequest`                        | `PublishResponse`                       | `RepublishRequest`                      | 
| `RepublishResponse`                     | `TransferSubscriptionsRequest`          | `TransferSubscriptionsResponse`         | 
| `DeleteSubscriptionsRequest`            | `DeleteSubscriptionsResponse`           | `TestStackRequest`                      | 
| `TestStackResponse`                     | `TestStackExRequest`                    | `TestStackExResponse`                   | 

#### Files of interest when implementing a service

| Filename                                                           | Description                                                                                                                                                                                                                       |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`scripts/OPCUA/Binary/main.zeek`](scripts/OPCUA/Binary/main.zeek) | `Add a log stream definition and log event processing`                                                                                                                                                                            |
| [`scripts/types.zeek`](scripts/types.zeek)                         | `Add a type/record definitions describing the information that will be written to the log files.  Alternately, create a <service-name>-types.zeek file containing the type/record definations for the service being implemented.` |
| [`scripts/__preload__.zeek`](scripts/__preload__.zeek)             | `Add a @load reference to the appropriate types.zeek file.`                                                                                                                                                                       |
| [`src/types.bif`](src/types.bif)                                   | `Add a type/record definitions that corresponds to the definitions in scripts/types.zeek.  This enables the types to be visible in the analyzer.`                                                                                 |
| `<service-name>/opcua_binary-<service_name>.pac`                   | `Create a directory associated with the service and implement binpac code describing the protocol structure for the service.`                                                                                                     |
| `<service-name>/opcua_binary-<service_name>_analyzer.pac`          | `Implement the code used to process the parsed information and map to the corresponding scripting object for logging`                                                                                                             |
| `<service-name>/opcua_binary-<service_name>_debug.pac `            | `Implement the code used to verify the parsed information is as expected.`                                                                                                                                                        |
| `<service-name>/index-consts.h `                                   | `Implement the constants used for assignment indexes when mapping in the analyzers.`                                                                                                                                              |
| [`src/events.bif`](src/events.bif)                                 | `Define the event definitions used by the analyzer.  These correspond to the log event processing functions defined in main.zeek`                                                                                                 |
| [`src/opcua_binary.pac`](src/opcua_binary.pac)                     | `Add the corresponding %include for the analyzer .`                                                                                                                                                                               |
| [`src/opcua_binary-protocol.pac`](src/opcua_binary-protocol.pac)   | `Add the corresponding %includes for the binpac parser and debug code.`                                                                                                                                                           |
| [`src/opcua_binary-services.pac`](src/opcua_binary-services.pac)   | `Update the processing to parse the new service.`                                                                                                                                                                                 |
| [`src/opcua_binary-analyzer.pac`](src/opcua_binary-analyzer.pac)   | `Add the corresponding #include for the <service-name>/index-conts.h`                                                                                                                                                             |