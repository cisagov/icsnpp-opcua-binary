signature dpd_opcua {
  ip-proto == tcp
  src-port >= 1024
  dst-port >= 1024
  payload /^\x48\x45\x4c/
  enable "ICSNPP_OPCUA_BINARY"
}
