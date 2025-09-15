import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;

/**
 * Proxy
 *
 * Minimal TCP/TLS forward proxy:
 * - Listens on a local host:port.
 * - Dials the target using either plain TCP or TLS 1.2.
 * - Copies bytes in both directions until either side closes.
 *
 * Use case: let a non-TLS client talk to a TLS upstream (e.g., MQ channel)
 * with strict protocol/cipher, optional SNI/hostname verification, and optional mTLS.
 *
 * No third-party deps. Java 11+ recommended.
 */
public final class MQProxy {
    // Enforce TLS 1.2 and a single cipher by default (adjust if required).
    private static final String[] TLS_PROTOCOLS = new String[]{"TLSv1.2"};
    private static final String[] TLS_CIPHERS   = new String[]{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"};

    public static void main(String[] args) throws Exception {
        Config c = Config.parse(args);
        c.validate(); // ensure required fields present (e.g., --target)

        System.out.printf(
            "Starting Proxy%n" +
            "  Mode        : %s%n" +
            "  Listen      : %s:%d%n" +
            "  Target      : %s:%d%n" +
            "  TLS Prot    : %s%n" +
            "  TLS Cipher  : %s%n" +
            "  HostnameChk : %s%n",
            c.mode, c.listenHost, c.listenPort, c.targetHost, c.targetPort,
            Arrays.toString(TLS_PROTOCOLS), Arrays.toString(TLS_CIPHERS),
            c.hostnameVerification ? "ENABLED" : "DISABLED"
        );

        // TLS machinery only in TLS mode.
        SSLConnectionFactory sslFactory = null;
        if (c.isTls()) {
            SSLContext sslCtx = buildSSLContext(c);
            SSLParameters params = new SSLParameters();
            params.setProtocols(TLS_PROTOCOLS);
            params.setCipherSuites(TLS_CIPHERS);
            if (c.hostnameVerification) {
                // Enables HTTPS-style host verification against CN/SAN.
                params.setEndpointIdentificationAlgorithm("HTTPS");
            }
            sslFactory = new SSLConnectionFactory(sslCtx, params, c.sniHost);
        }

        // Bind listener.
        ServerSocket server = ServerSocketFactory.getDefault().createServerSocket();
        server.bind(new InetSocketAddress(c.listenHost, c.listenPort));
        System.out.println("Listening on " + c.listenHost + ":" + c.listenPort + " (" + c.mode + ")");

        // Thread pool per connection.
        ExecutorService pool = Executors.newCachedThreadPool();

        // Graceful shutdown.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { server.close(); } catch (IOException ignored) {}
            pool.shutdownNow();
        }));

        // Accept loop.
        while (true) {
            Socket client = server.accept();
            client.setTcpNoDelay(true);
            client.setKeepAlive(true);
            final SSLConnectionFactory f = sslFactory; // capture for lambda
            pool.submit(() -> handleClient(client, c, f, pool));
        }
    }

    /** Handle one client: connect upstream, run bidirectional pumps. */
    private static void handleClient(Socket client, Config c, SSLConnectionFactory sslFactory, ExecutorService pool) {
        String id = client.getRemoteSocketAddress().toString();
        System.out.println("[+] Accepted " + id);

        try (Socket clientSock = client;
             Socket upstream = c.isTls()
                 ? sslFactory.connect(c.targetHost, c.targetPort)
                 : connectPlain(c.targetHost, c.targetPort)) {

            Future<?> a = pumpAsync(clientSock.getInputStream(), upstream.getOutputStream(), pool, id + " c->s");
            Future<?> b = pumpAsync(upstream.getInputStream(), clientSock.getOutputStream(), pool, id + " s->c");

            a.get();           // wait until one direction finishes
            b.cancel(true);    // stop the peer direction
        } catch (Exception e) {
            System.err.println("[-] " + id + " error: " + e.getMessage());
        } finally {
            System.out.println("[-] Closed " + id);
        }
    }

    /** Plain TCP connect with sensible options. */
    private static Socket connectPlain(String host, int port) throws IOException {
        Socket s = new Socket();
        s.setTcpNoDelay(true);
        s.setKeepAlive(true);
        s.connect(new InetSocketAddress(host, port), 15_000);
        System.out.println("  -> Plain TCP connected to " + host + ":" + port);
        return s;
    }

    /** Copy bytes from in→out until EOF/error. */
    private static Future<?> pumpAsync(InputStream in, OutputStream out, ExecutorService pool, String tag) {
        return pool.submit(() -> {
            try (in; out) {
                byte[] buf = new byte[16 * 1024];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    out.write(buf, 0, n);
                    out.flush();
                }
            } catch (IOException ignored) {
                // normal on half-close/drop
            }
        });
    }

    // ------------------- TLS helpers -------------------

    /**
     * Build an SSLContext:
     * - Optional client identity (keystore) for mTLS.
     * - Trust via truststore or single cert (.cer/.pem/PEM string).
     */
    private static SSLContext buildSSLContext(Config c) throws Exception {
        KeyManager[] kms = null;
        TrustManager[] tms = null;

        // Client identity (mTLS) – optional.
        if (c.keystorePath != null) {
            KeyStore ks = loadKeyStore(c.keystorePath, c.keystorePassword, c.keystoreType);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, c.keystorePassword != null ? c.keystorePassword.toCharArray() : new char[0]);
            kms = kmf.getKeyManagers();
        }

        // Server trust (TLS only) – truststore or single certificate.
        if (c.trustCertPath != null || c.truststorePath != null) {
            KeyStore ts;
            if (c.trustCertPath != null) {
                ts = KeyStore.getInstance(KeyStore.getDefaultType());
                ts.load(null, null);
                X509Certificate cert = loadX509(c.trustCertPath);
                ts.setCertificateEntry("server-root", cert);
            } else {
                ts = loadKeyStore(c.truststorePath, c.truststorePassword, c.truststoreType);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            tms = tmf.getTrustManagers();
        }

        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(kms, tms, new SecureRandom());
        return ctx;
    }

    /** Load JKS/PKCS12 keystore/truststore. */
    private static KeyStore loadKeyStore(String path, String password, String type) throws Exception {
        String guessType = (type != null) ? type
                : (path.toLowerCase().endsWith(".p12") || path.toLowerCase().endsWith(".pkcs12")) ? "PKCS12" : "JKS";
        KeyStore ks = KeyStore.getInstance(guessType);
        try (InputStream in = new FileInputStream(path)) {
            ks.load(in, password != null ? password.toCharArray() : null);
        }
        return ks;
    }

    /**
     * Load a single X.509 certificate from:
     * - File path (.cer/.pem) OR
     * - PEM string OR
     * - base64 DER (auto-wrapped to PEM).
     */
    private static X509Certificate loadX509(String pathOrPem) throws Exception {
        InputStream in;
        File f = new File(pathOrPem);
        if (f.exists()) {
            in = new FileInputStream(f);
        } else {
            String pem = pathOrPem.trim();
            if (!pem.startsWith("-----BEGIN")) {
                pem = "-----BEGIN CERTIFICATE-----\n" +
                        wrap64(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                                .encodeToString(Base64.getDecoder().decode(pathOrPem))) +
                        "\n-----END CERTIFICATE-----\n";
            }
            in = new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII));
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }

    /** Wrap long base64 lines for PEM readability. */
    private static String wrap64(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i += 64) b.append(s, i, Math.min(i + 64, s.length())).append('\n');
        return b.toString();
    }

    /** TLS connector: builds SSLSocket, applies strict params/SNI, handshakes. */
    private static final class SSLConnectionFactory {
        private final SSLSocketFactory factory;
        private final SSLParameters params;
        private final String sniHost;

        SSLConnectionFactory(SSLContext ctx, SSLParameters params, String sniHost) {
            this.factory = ctx.getSocketFactory();
            this.params = params;
            this.sniHost = sniHost;
        }

        Socket connect(String host, int port) throws IOException {
            SSLSocket s = (SSLSocket) factory.createSocket();
            s.setUseClientMode(true);
            s.setTcpNoDelay(true);
            s.setKeepAlive(true);
            s.connect(new InetSocketAddress(host, port), 15_000);

            // Copy configured params into a fresh instance (avoid sharing mutable state).
            SSLParameters p = new SSLParameters();
            p.setProtocols(params.getProtocols());
            p.setCipherSuites(params.getCipherSuites());
            p.setAlgorithmConstraints(params.getAlgorithmConstraints());
            p.setWantClientAuth(params.getWantClientAuth());
            p.setNeedClientAuth(params.getNeedClientAuth());
            if (params.getEndpointIdentificationAlgorithm() != null) {
                p.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
            }
            if (sniHost != null && !sniHost.isEmpty()) {
                p.setServerNames(Collections.singletonList(new SNIHostName(sniHost)));
            }
            s.setSSLParameters(p);

            s.startHandshake();
            System.out.println("  -> TLS connected. Session=" + s.getSession().getProtocol()
                    + " " + s.getSession().getCipherSuite());
            return s;
        }
    }

    // ------------------- CLI config -------------------

    private static final class Config {
        String mode = "tls";                         // "tls" or "plain"
        String listenHost = "127.0.0.1";
        int listenPort = 9444;

        // target is REQUIRED (no defaults to avoid leaking anything)
        String targetHost = null;
        int targetPort = -1;

        String sniHost = null;
        boolean hostnameVerification = false;

        // Trust via truststore...
        String truststorePath, truststorePassword, truststoreType;
        // ...or a single cert (.cer/.pem/PEM string).
        String trustCertPath;
        // Optional client identity for mTLS.
        String keystorePath, keystorePassword, keystoreType;

        boolean isTls() { return "tls".equalsIgnoreCase(mode); }

        void validate() {
            if (targetHost == null || targetPort <= 0) {
                System.err.println("Error: --target HOST:PORT is required.");
                usage();
                System.exit(2);
            }
        }

        static Config parse(String[] args) {
            Config c = new Config();
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "--mode": c.mode = next(args, ++i); break;

                    case "--listen": {
                        String[] lh = next(args, ++i).split(":", 2);
                        c.listenHost = lh[0]; c.listenPort = Integer.parseInt(lh[1]);
                        break;
                    }
                    case "--target": {
                        String[] th = next(args, ++i).split(":", 2);
                        c.targetHost = th[0]; c.targetPort = Integer.parseInt(th[1]);
                        break;
                    }
                    case "--sni": c.sniHost = next(args, ++i); break;
                    case "--hostname-verification": c.hostnameVerification = Boolean.parseBoolean(next(args, ++i)); break;

                    case "--truststore": c.truststorePath = next(args, ++i); break;
                    case "--truststore-pass": c.truststorePassword = next(args, ++i); break;
                    case "--truststore-type": c.truststoreType = next(args, ++i); break;

                    case "--trustcert": c.trustCertPath = next(args, ++i); break;

                    case "--keystore": c.keystorePath = next(args, ++i); break;
                    case "--keystore-pass": c.keystorePassword = next(args, ++i); break;
                    case "--keystore-type": c.keystoreType = next(args, ++i); break;

                    case "-h": case "--help": usage(); System.exit(0); break;
                    default:
                        System.err.println("Unknown arg: " + a);
                        usage();
                        System.exit(1);
                }
            }
            return c;
        }
        private static String next(String[] a, int i){ if(i>=a.length) usage(); return a[i]; }
        private static void usage() {
            System.out.println(
              "Usage:\n" +
              "  java Proxy [--mode tls|plain] --listen HOST:PORT --target HOST:PORT [options]\n\n" +
              "Options:\n" +
              "  --mode tls|plain                    Upstream mode (default tls)\n" +
              "  --listen HOST:PORT                  Local bind (default 127.0.0.1:9444)\n" +
              "  --target HOST:PORT                  REQUIRED. Remote host:port\n" +
              "  --sni HOST                          Optional SNI (TLS only)\n" +
              "  --hostname-verification true|false  HTTPS-style hostname check (TLS only; default false)\n" +
              "  --truststore PATH | --trustcert PATH  Trust server (TLS only). Use truststore (JKS/PKCS12) or single .cer/.pem\n" +
              "  --truststore-pass PASS              Truststore password\n" +
              "  --truststore-type JKS|PKCS12        Truststore type\n" +
              "  --keystore PATH                     Client identity (TLS only; JKS/PKCS12)\n" +
              "  --keystore-pass PASS                Keystore password\n" +
              "  --keystore-type JKS|PKCS12          Keystore type\n"
            );
        }
    }
}
