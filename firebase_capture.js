/**
 * SiDIVA / SiDOMPUL - Firebase ID Token Capture
 *
 * Captures Firebase Authentication ID token for use with SiDivaAuth.loginWithFirebaseToken().
 *
 * Usage (spawn mode):
 *   frida -U -f com.toko.xl -l firebase_capture.js --no-pause
 *
 * After login OTP is entered, the Firebase ID token will print to console.
 * Copy it and use with: auth.loginWithFirebaseToken('<token>')
 */

'use strict';

Java.perform(function () {

  // Method 1: Hook GetTokenResult (Firebase Auth result object)
  try {
    var GetTokenResult = Java.use('com.google.firebase.auth.GetTokenResult');
    GetTokenResult.getToken.implementation = function () {
      var token = this.getToken();
      console.log('\n╔═══════════════════════════════════════════╗');
      console.log('║        FIREBASE ID TOKEN CAPTURED         ║');
      console.log('╚═══════════════════════════════════════════╝');
      console.log(token);
      console.log('═══════════════════════════════════════════\n');
      send({ type: 'firebase_id_token', token: token });
      return token;
    };
    console.log('[FB] GetTokenResult.getToken hooked.');
  } catch (e) {
    console.log('[FB] GetTokenResult: ' + e);
  }

  // Method 2: Hook FirebaseUser.getIdToken
  try {
    var FirebaseUser = Java.use('com.google.firebase.auth.FirebaseUser');
    FirebaseUser.getIdToken.overload('boolean').implementation = function (force) {
      console.log('[FB] getIdToken called, force=' + force);
      return this.getIdToken(force);
    };
  } catch (e) {}

  // Method 3: Hook PhoneAuthCredential (OTP verification)
  try {
    var PhoneAuthCredential = Java.use('com.google.firebase.auth.PhoneAuthCredential');
    var fields = PhoneAuthCredential.class.getDeclaredFields();
    fields.forEach(function (f) {
      f.setAccessible(true);
      console.log('[FB] PhoneAuthCredential field: ' + f.getName());
    });
  } catch (e) {}

  // Method 4: Hook signInWithCredential result callback
  try {
    var AuthResult = Java.use('com.google.firebase.auth.AuthResult');
  } catch (e) {}

  // Method 5: Scan heap for Firebase user object after login
  // Call this 5 seconds after completing OTP
  setTimeout(function () {
    try {
      Java.choose('com.google.firebase.auth.internal.zzn', {
        onMatch: function (instance) {
          try {
            var token = instance.getIdToken(false);
            console.log('[FB] Heap scan found FirebaseUser, token task created.');
          } catch (e) {}
        },
        onComplete: function () {},
      });
    } catch (e) {}

    // Also try to find token in FirebaseAuth instance
    try {
      Java.choose('com.google.firebase.auth.FirebaseAuth', {
        onMatch: function (auth) {
          try {
            var user = auth.getCurrentUser();
            if (user) {
              console.log('[FB] CurrentUser found: ' + user.getUid());
              user.getIdToken(true).addOnSuccessListener(
                Java.use('com.google.android.gms.tasks.OnSuccessListener').$implement({
                  onSuccess: function (result) {
                    var token = result.getToken();
                    console.log('\n╔═══════════════════════════════════════╗');
                    console.log('║    FIREBASE TOKEN (forced refresh)    ║');
                    console.log('╚═══════════════════════════════════════╝');
                    console.log(token);
                    send({ type: 'firebase_id_token_refreshed', token: token });
                  },
                })
              );
            }
          } catch (e) {
            console.log('[FB] getCurrentUser error: ' + e);
          }
        },
        onComplete: function () {},
      });
    } catch (e) {
      console.log('[FB] Heap FirebaseAuth scan: ' + e);
    }
  }, 5000);

  console.log('[FB] Firebase capture script loaded.');
  console.log('[FB] Complete OTP login in the app → token will appear above.');
});
