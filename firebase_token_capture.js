/**
 * SiDIVA / SiDOMPUL - Bearer Token Auto-Capture
 *
 * Hooks OkHttp3 to intercept all HTTP requests and extract:
 *   - Authorization: Bearer <token>
 *   - x-signature (HMAC from V-OS JNI)
 *   - x-timestamp
 *   - All request/response bodies
 *
 * Usage (spawn mode):
 *   frida -U -f com.toko.xl -l token_capture.js --no-pause
 *
 * Output token will be printed as:
 *   [TOKEN] Bearer: <token>
 */

'use strict';

Java.perform(function () {

  // ─── OkHttp3 Request interceptor ─────────────────────────────────────────

  var capturedTokens = new Set();

  function interceptOkHttp() {
    try {
      var OkHttpClient = Java.use('okhttp3.OkHttpClient');
      var Request = Java.use('okhttp3.Request');
      var RequestBody = Java.use('okhttp3.RequestBody');
      var MediaType = Java.use('okhttp3.MediaType');
      var Buffer = Java.use('okio.Buffer');

      // Hook OkHttpClient.newCall to intercept requests
      var RealCall = Java.use('okhttp3.internal.connection.RealCall');

      RealCall.execute.implementation = function () {
        var request = this.request();
        interceptRequest(request);
        var response = this.execute();
        interceptResponse(response, request.url().toString());
        return response;
      };

      console.log('[TOKEN] OkHttp3 RealCall.execute hooked.');
    } catch (e) {
      console.log('[TOKEN] RealCall hook failed: ' + e);
    }

    // Also hook at the chain level (works for interceptors)
    try {
      var Interceptor = Java.use('okhttp3.Interceptor');
      var Chain = Java.use('okhttp3.Interceptor$Chain');
    } catch (e) {}

    // Hook OkHttp Response reading
    try {
      var RealResponseBody = Java.use('okhttp3.internal.http.RealResponseBody');
    } catch (e) {}
  }

  function interceptRequest(request) {
    try {
      var url = request.url().toString();
      var method = request.method();

      // Extract headers
      var headers = request.headers();
      var headerCount = headers.size();
      var auth = null;
      var xsig = null;
      var xts = null;
      var hdrs = {};

      for (var i = 0; i < headerCount; i++) {
        var name = headers.name(i);
        var value = headers.value(i);
        hdrs[name] = value;
        if (name.toLowerCase() === 'authorization') {
          auth = value;
          var token = value.replace(/^Bearer\s+/i, '');
          if (!capturedTokens.has(token)) {
            capturedTokens.add(token);
            console.log('\n[TOKEN] ========================================');
            console.log('[TOKEN] Bearer: ' + token);
            console.log('[TOKEN] URL: ' + url);
            console.log('[TOKEN] ========================================\n');
            send({ type: 'bearer_token', token: token, url: url });
          }
        }
        if (name.toLowerCase() === 'x-signature') xsig = value;
        if (name.toLowerCase() === 'x-timestamp') xts = value;
      }

      if (xsig) {
        console.log('[TOKEN] x-signature: ' + xsig.substring(0, 40) + '...');
        send({ type: 'x_signature', signature: xsig, timestamp: xts, url: url });
      }

      // Extract request body
      var body = request.body();
      if (body !== null) {
        try {
          var Buffer = Java.use('okio.Buffer');
          var buf = Buffer.$new();
          body.writeTo(buf);
          var bodyStr = buf.readUtf8();
          if (bodyStr.length > 0) {
            console.log('[TOKEN] ' + method + ' ' + url);
            console.log('[TOKEN] Body: ' + bodyStr.substring(0, 500));
            send({ type: 'request_body', method: method, url: url, body: bodyStr });
          }
        } catch (e) {}
      }
    } catch (e) {
      console.log('[TOKEN] interceptRequest error: ' + e);
    }
  }

  function interceptResponse(response, url) {
    try {
      var code = response.code();
      var bodyStr = null;
      try {
        var body = response.peekBody(65536);
        if (body) bodyStr = body.string();
      } catch (e) {}

      if (bodyStr && bodyStr.length > 0) {
        // Look for access_token in response
        if (bodyStr.indexOf('access_token') >= 0) {
          console.log('[TOKEN] RESPONSE with access_token from: ' + url);
          console.log('[TOKEN] ' + bodyStr.substring(0, 800));
          send({ type: 'login_response', url: url, body: bodyStr, status: code });
        }
      }
    } catch (e) {}
  }

  // ─── Firebase ID token capture ───────────────────────────────────────────

  try {
    var FirebaseUser = Java.use('com.google.firebase.auth.FirebaseUser');
    FirebaseUser.getIdToken.overload('boolean').implementation = function (forceRefresh) {
      var task = this.getIdToken(forceRefresh);
      console.log('[TOKEN] Firebase getIdToken called (forceRefresh=' + forceRefresh + ')');
      // Hook TaskCompletionSource to get the result
      return task;
    };
  } catch (e) {}

  // Hook Firebase token result
  try {
    var GetTokenResult = Java.use('com.google.firebase.auth.GetTokenResult');
    GetTokenResult.getToken.implementation = function () {
      var token = this.getToken();
      console.log('\n[FIREBASE] ==========================================');
      console.log('[FIREBASE] ID Token: ' + token.substring(0, 100) + '...');
      console.log('[FIREBASE] ==========================================\n');
      send({ type: 'firebase_token', token: token });
      return token;
    };
  } catch (e) {
    console.log('[TOKEN] Firebase GetTokenResult hook: ' + e);
  }

  // ─── Keycloak token from SharedPreferences / DataStore ───────────────────

  try {
    var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferences.getString.implementation = function (key, def) {
      var val = this.getString(key, def);
      if (val && (key.toLowerCase().indexOf('token') >= 0 || key.toLowerCase().indexOf('bearer') >= 0)) {
        if (val.length > 20 && !capturedTokens.has(val)) {
          capturedTokens.add(val);
          console.log('[TOKEN] SharedPref token found: ' + key + ' = ' + val.substring(0, 50) + '...');
          send({ type: 'pref_token', key: key, value: val });
        }
      }
      return val;
    };
  } catch (e) {}

  interceptOkHttp();

  console.log('[TOKEN] Token capture script loaded.');
  console.log('[TOKEN] Waiting for login... Bearer token will appear above.');
});
