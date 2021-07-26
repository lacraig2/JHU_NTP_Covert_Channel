# JHU_NTP_Covert_Channel
Covert Channels


Our NTP Covert Channel works by using NTP Extensions to communicate data.

We make use of the SIGN_MESSAGE_REQUEST and SIGN_MESSAGE_RESPONSE messages to send and receive data. This particular message type takes a RSA public key in X.509 format with ASN.1 symtax format as a payload. We encode our data into the public key n value.

We use the maximum RSA key size of 4096 bits for our request and achieve a throughput of 509 bytes per packet. The overall packets are 662 bytes long.

## Sources

https://datatracker.ietf.org/doc/html/rfc5906.html#appendix-H
https://datatracker.ietf.org/doc/html/rfc5905