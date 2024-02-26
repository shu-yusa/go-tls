# TLS 1.3 Server Implementation in Go

## Purpose

This project aims to deepen the understanding of TLS 1.3 by implementing a full handshake mechanism of TLS 1.3 on a Go-based TCP server. It involves developing a custom TLS 1.3 handshake on top of a Go TCP server, showcasing the capabilities and flexibility of Go in handling network protocols and encryption.

## Prerequisites

- Recommended to use **Go 1.22**. The implementation may work on lower versions, but no verification has been done.

## Installation and Running

1. **Generate a Self-Signed Certificate**

    Create a local self-signed certificate by running:
    ```
    make server-cert
    ```
    This will generate `server.crt` and `server.key` files.

2. **Start the TCP Server**

    Launch the TCP server using:
    ```
    make start
    ```

## Client Requests

You can test the server using one of the following methods:

1. **Using OpenSSL s_client**

    ```
    openssl s_client -noservername -crlf -connect localhost:443
    ```
    and enter
    ```
    GET / HTTP/1.1
    Host: localhost

    ```

2. **Using curl**

    ```
    curl -k https://localhost:443
    ```

3. **Using a Web Browser**

    Open `https://localhost` in your browser. Note: You may need to accept the self-signed certificate warning.

## TLS 1.3 Full Handshake Overview

The implementation covers the following messages in the TLS 1.3 full handshake process:

- ClientHello
- ServerHello
- EncryptedExtensions
- Certificate
- CertificateVerify
- Finished (from both client and server)

Below is a sequence diagram illustrating the handshake process:

```
(Client)              (Server)
   |                      |
   |-----ClientHello----->|
   |                      |
   |<---ServerHello-------|
   |<--EncryptedExtensions|
   |<-------Certificate---|
   |<--CertificateVerify--|
   |<-------Finished------|
   |                      |
   |-------Finished------>|
   |                      |
```

## References

For more detailed information about TLS 1.3, refer to [RFC 8446](https://tools.ietf.org/html/rfc8446).
