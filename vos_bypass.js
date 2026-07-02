/**
 * SiDIVA / SiDOMPUL - V-OS / VGuard Anti-Tamper Bypass
 *
 * Bypasses V-Key V-OS (libvosWrapperEx.so) integrity checks.
 *
 * CRITICAL: MUST use spawn mode only.
 *   frida -U -f com.toko.xl -l vos_bypass.js --no-pause
 *
 * Attaching to running process WILL FAIL due to V-OS detecting frida.
 */

'use strict';

// ─── V-OS / VGuard native hooks ───────────────────────────────────────────────

var vosLib = null;
var vosNames = ['libvosWrapperEx.so', 'libnative-lib.so', 'libchecks.so'];

function findVosModule() {
  for (var i = 0; i < vosNames.length; i++) {
    var m = Process.findModuleByName(vosNames[i]);
    if (m) {
      console.log('[VOS] Found module: ' + vosNames[i] + ' @ ' + m.base);
      return m;
    }
  }
  return null;
}

// Hook integrity check returns
function patchVosChecks() {
  vosLib = findVosModule();
  if (!vosLib) {
    console.log('[VOS] V-OS modules not loaded yet, scheduling retry...');
    setTimeout(patchVosChecks, 1000);
    return;
  }

  // Export-based patches
  var checkExports = [
    'VOS_CheckIntegrity',
    'VOS_VerifyApp',
    'VOS_IsRooted',
    'VOS_IsEmulator',
    'VOS_IsDebugger',
    'vosCheckRootStatus',
    'vosCheckIntegrity',
  ];

  checkExports.forEach(function (name) {
    try {
      var exp = Module.findExportByName(vosLib.name, name);
      if (exp) {
        Interceptor.attach(exp, {
          onLeave: function (retval) {
            console.log('[VOS] ' + name + ' → patched to 0');
            retval.replace(ptr(0));
          },
        });
      }
    } catch (e) {}
  });

  // Hook JNI_OnLoad to patch after V-OS initializes
  try {
    var onLoad = Module.findExportByName(vosLib.name, 'JNI_OnLoad');
    if (onLoad) {
      Interceptor.attach(onLoad, {
        onLeave: function (retval) {
          console.log('[VOS] JNI_OnLoad returned, applying post-init patches...');
          applyPostInitPatches();
        },
      });
    }
  } catch (e) {}

  console.log('[VOS] V-OS bypass hooks installed.');
}

function applyPostInitPatches() {
  // Pattern-scan for common integrity check return sequences
  // Returns 0 (pass) for any check that returns non-zero (fail)
  var ranges = Process.enumerateRangesSync({ protection: 'r-x', coalesce: true });
  ranges.forEach(function (range) {
    if (range.size < 0x1000 || range.size > 0x10000000) return;
    // Only scan VOS-related modules
    var module = Process.findModuleByAddress(range.base);
    if (!module) return;
    if (!vosNames.some(function (n) { return module.name === n; })) return;

    try {
      // Thumb2: MOV R0, #0 + BX LR (return 0)
      Memory.scan(range.base, range.size, '00 00 A0 E3 1E FF 2F E1', {
        onMatch: function (addr) {
          // Don't blindly patch - log candidates
          console.log('[VOS] Potential check at: ' + addr);
        },
      });
    } catch (e) {}
  });
}

// ─── Java-layer V-OS JNI checks ───────────────────────────────────────────────

Java.perform(function () {
  // Patch VGuard Java wrappers
  var vguardClasses = [
    'com.vkey.android.vguard.VGuard',
    'com.vkey.android.vos.VOS',
    'com.vkey.vos.VOS',
  ];

  vguardClasses.forEach(function (cls) {
    try {
      var C = Java.use(cls);
      var methods = C.class.getDeclaredMethods();
      methods.forEach(function (m) {
        var name = m.getName();
        // Patch check/verify/isRooted/isEmulator methods
        if (/check|verify|root|emulat|debug|tamper|integrit/i.test(name)) {
          try {
            C[name].implementation = function () {
              console.log('[VOS] Bypassed: ' + cls + '.' + name);
              return false;
            };
          } catch (e) {
            try {
              C[name].overload().implementation = function () {
                console.log('[VOS] Bypassed: ' + cls + '.' + name);
                return false;
              };
            } catch (e2) {}
          }
        }
      });
      console.log('[VOS] Patched Java class: ' + cls);
    } catch (e) {}
  });
});

// ─── Start ───────────────────────────────────────────────────────────────────

patchVosChecks();
console.log('[VOS] V-OS bypass script loaded (spawn mode).');
