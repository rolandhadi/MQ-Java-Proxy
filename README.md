# Java TLS Forward Proxy

Minimal, dependency-free Java proxy that listens locally and forwards to a remote upstream using **plain TCP** or **TLS 1.2** with a fixed cipher.  
Supports optional **SNI**, **hostname verification**, and **mutual TLS (mTLS)** using a client certificate.

This tool is especially useful when working with **Service Virtualization (SV) using OpenText SV Designer**,  
because SV Designer does not provide a way to explicitly select a TLS cipher suite when connecting to IBM MQ.  
By running this proxy, you can enforce a specific cipher (e.g., `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`)  
so SV Designer can connect successfully to MQ channels that require strict CipherSpec matching.

---

## ✨ Features

- Strict TLS 1.2 enforcement
- Fixed cipher: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- Trust via truststore (JKS/PKCS12) or single `.cer`/`.pem`
- Optional client identity for mTLS
- Zero third-party dependencies

---

## 🖼 Diagram

    [ SV Designer MQ Agent ] --tcp--> [ Proxy (listen HOST:PORT) ] ==TLS1.2:AES_256_GCM==> [ MQ Channel ]

---

## 📋 Requirements

- Java 11+ (tested with Java 11 & 17)

---

## 🔨 Build

    javac Proxy.java

---

## 🚀 Usage

### TLS (server trust with single `.cer`)

    java Proxy ^
      --mode tls ^
      --listen 127.0.0.1:9444 ^
      --target mq.example.com:1414 ^
      --trustcert /path/to/root.cer ^
      --sni mq.example.com ^
      --hostname-verification true

### TLS + mTLS (keystore + truststore)

    java Proxy ^
      --mode tls ^
      --listen 127.0.0.1:9444 ^
      --target mq.example.com:1414 ^
      --truststore /path/to/truststore.p12 --truststore-pass changeit --truststore-type PKCS12 ^
      --keystore   /path/to/client.p12     --keystore-pass secret    --keystore-type PKCS12 ^
      --sni mq.example.com ^
      --hostname-verification true

(Use `\` line continuations on macOS/Linux instead of `^`.)

### Plain TCP (no TLS)

    java Proxy --mode plain --listen 127.0.0.1:9444 --target 10.0.0.5:1414

---

## ⚙️ Arguments

| Flag | Description |
|------|-------------|
| `--mode tls or plain` | Upstream mode (default `tls`) |
| `--listen HOST:PORT` | Local bind (default `127.0.0.1:9444`) |
| `--target HOST:PORT` | **Required.** Upstream host:port |
| `--sni HOST` | SNI value to advertise |
| `--hostname-verification true or false` | Verify CN/SAN against host (default `false`) |
| `--trustcert PATH` | Trust server using a single `.cer` or `.pem` |
| `--truststore PATH` | Trust server with JKS/PKCS12 truststore |
| `--truststore-type JKS or PKCS12` | Truststore type (auto-guessed if omitted) |
| `--truststore-pass PASS` | Truststore password |
| `--keystore PATH` | Client identity for mTLS (JKS/PKCS12) |
| `--keystore-type JKS or PKCS12` | Keystore type (auto-guessed if omitted) |
| `--keystore-pass PASS` | Keystore password |

> If both `--trustcert` and `--truststore` are provided, `--trustcert` takes precedence.

---

## 🛠 Troubleshooting

- **Timeout:** Check upstream reachability, firewall, or service/channel status.
- **Handshake failure:** Ensure upstream allows TLS 1.2 and selected cipher.
- **`PKIX path building failed`:** Add correct CA chain (Root + Intermediate) to trust.
- **`Unrecognized keystore format`:** Use `--keystore-type PKCS12` for `.p12` files or `--truststore-type JKS`.

---

## 🔒 Security Notes

- Prefer `--hostname-verification true` in production and ensure server certificate SAN matches target host.
- Change `TLS_CIPHERS` in `Proxy.java` only if your upstream mandates a different suite.

---

## 📄 License

MIT (or your organization’s standard).
