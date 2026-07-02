/**
 * SiDIVA / SiDOMPUL - SSL Pinning Bypass + Traffic Capture
 *
 * Usage (MUST use spawn mode):
 *   frida -U -f com.toko.xl -l ssl_intercept.js --no-pause
 *
 * Captures all HTTPS requests/responses. Output goes to stdout.
 * HPACK-encoded H2 frames → decode with hpack_decode.py
 */

'use strict';

// ─── TrustManager bypass ──────────────────────────────────────────────────────

Java.perform(function () {
  // 1. OkHttp CertificatePinner bypass
  try {
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function (h, l) {
      console.log('[SSL] CertificatePinner.check bypassed: ' + h);
    };
    CertPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (h, c) {
      console.log('[SSL] CertificatePinner.check(cert[]) bypassed: ' + h);
    };
  } catch (e) { console.log('[SSL] OkHttp3 CertPinner: ' + e); }

  // 2. TrustManager bypass
  try {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function (u, r, h, a, o, s) {
      return u;
    };
  } catch (e) { console.log('[SSL] TrustManagerImpl: ' + e); }

  // 3. X509TrustManager
  try {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManagerImpl2 = Java.registerClass({
      name: 'com.sidiva.FakeTrustManager',
      implements: [TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () { return []; },
      },
    });
    SSLContext.init.implementation = function (km, tm, sr) {
      SSLContext.init.call(this, km, [TrustManagerImpl2.$new()], sr);
    };
  } catch (e) { console.log('[SSL] X509TrustManager: ' + e); }

  // 4. Conscrypt setHostname
  try {
    var ConscryptSocket = Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket');
    ConscryptSocket.setHostname.implementation = function (h) {};
  } catch (e) {}

  // 5. WebViewClient (for WebView pinning)
  try {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
      handler.proceed();
    };
  } catch (e) {}

  console.log('[SSL] Pinning bypass active.');
});

// ─── SSL KeyLog (SSLKEYLOGFILE equivalent via OpenSSL hook) ───────────────────

var ssl_read = Module.findExportByName('libssl.so', 'SSL_read');
var ssl_write = Module.findExportByName('libssl.so', 'SSL_write');

var write_counter = 0;

if (ssl_read) {
  Interceptor.attach(ssl_read, {
    onLeave: function (retval) {
      var len = retval.toInt32();
      if (len <= 0) return;
      var ssl = this.context.x0 || this.context.r0;
      var buf = this.context.x1 || this.context.r1;
      if (buf.isNull()) return;
      try {
        var data = buf.readByteArray(Math.min(len, 4096));
        var hex = Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('');
        send({ type: 'ssl_read', len: len, hex: hex });
      } catch (e) {}
    },
  });
}

if (ssl_write) {
  Interceptor.attach(ssl_write, {
    onEnter: function (args) {
      var len = args[2].toInt32();
      if (len <= 0) return;
      var buf = args[1];
      if (buf.isNull()) return;
      try {
        var data = buf.readByteArray(Math.min(len, 4096));
        var hex = Array.from(new Uint8Array(data)).map(b => b.toString(16).padStart(2, '0')).join('');
        var w = write_counter++;
        console.log('W' + w + ':' + hex);
        send({ type: 'ssl_write', w: w, len: len, hex: hex });
      } catch (e) {}
    },
  });
}

console.log('[SSL] Intercept hooks installed. ssl_read=' + ssl_read + ' ssl_write=' + ssl_write);
