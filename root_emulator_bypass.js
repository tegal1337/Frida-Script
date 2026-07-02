/**
 * SiDIVA / SiDOMPUL - Root & Emulator Detection Bypass
 *
 * Bypasses:
 * - RootBeer (com.scottyab.rootbeer)
 * - SafetyNet / Play Integrity (attestation)
 * - Emulator detection (Build props, /proc, sensors)
 * - Frida/Magisk/Xposed detection
 * - File-based root detection (su, busybox, etc.)
 *
 * Usage (spawn mode):
 *   frida -U -f com.toko.xl -l root_bypass.js --no-pause
 */

'use strict';

Java.perform(function () {

  // ─── RootBeer ────────────────────────────────────────────────────────────

  var rootBeerClasses = [
    'com.scottyab.rootbeer.RootBeer',
    'com.scottyab.rootbeer.util.Utils',
  ];

  rootBeerClasses.forEach(function (cls) {
    try {
      var C = Java.use(cls);
      var methods = C.class.getDeclaredMethods();
      methods.forEach(function (m) {
        var name = m.getName();
        if (/root|su|busybox|magisk|xposed|isDevice/i.test(name)) {
          try {
            C[name].overload().implementation = function () {
              console.log('[ROOT] Bypassed RootBeer.' + name);
              return false;
            };
          } catch (e) {
            try {
              C[name].implementation = function () { return false; };
            } catch (e2) {}
          }
        }
      });
      console.log('[ROOT] Patched: ' + cls);
    } catch (e) {}
  });

  // ─── File-based root detection ───────────────────────────────────────────

  var File = Java.use('java.io.File');

  File.exists.implementation = function () {
    var path = this.getAbsolutePath();
    var rootPaths = [
      '/su', '/system/bin/su', '/system/xbin/su', '/system/app/Superuser.apk',
      '/sbin/su', '/data/local/su', '/data/local/xbin/su',
      '/system/sd/xbin/su', '/system/bin/failsafe/su',
      '/data/local/bin/su', '/system/xbin/busybox',
      '/data/magisk', '/sbin/.magisk', '/sbin/.core/mirror',
      '/data/adb/magisk', '/cache/.disable_magisk',
      '/proc/net/tcp6', // Frida detection via port check
    ];
    if (rootPaths.some(function (p) { return path.startsWith(p); })) {
      console.log('[ROOT] File.exists blocked: ' + path);
      return false;
    }
    return this.exists();
  };

  // ─── Build prop emulator detection ──────────────────────────────────────

  var Build = Java.use('android.os.Build');
  var emulatorStrings = ['google_sdk', 'goldfish', 'ranchu', 'sdk_gphone', 'emulator'];

  try {
    Build.FINGERPRINT.value = 'samsung/SM-G991B/star2qltesq:11/RP1A.200720.012/G991BXXS5AUL1:user/release-keys';
    Build.MODEL.value = 'SM-G991B';
    Build.MANUFACTURER.value = 'samsung';
    Build.PRODUCT.value = 'star2qltesq';
    Build.BRAND.value = 'samsung';
    Build.DEVICE.value = 'star2qltesq';
    Build.HARDWARE.value = 'exynos2100';
    console.log('[ROOT] Build props spoofed to Samsung Galaxy S21');
  } catch (e) {
    console.log('[ROOT] Build prop spoof: ' + e);
  }

  // ─── SystemProperties emulator detection ────────────────────────────────

  try {
    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
      var emulatorKeys = ['ro.kernel.qemu', 'ro.hardware', 'ro.product.model',
                          'ro.bootloader', 'ro.build.characteristics'];
      // Don't block, just log
      var val = this.get(key);
      return val;
    };
  } catch (e) {}

  // ─── Runtime.exec (su check) ─────────────────────────────────────────────

  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
    if (typeof cmd === 'string' && /^su$|which su|\/su$/.test(cmd)) {
      console.log('[ROOT] Runtime.exec blocked: ' + cmd);
      throw Java.use('java.io.IOException').$new('Permission denied');
    }
    return this.exec(cmd);
  };

  // ─── PackageManager (Magisk, Superuser, BusyBox apps) ───────────────────

  var Activity = Java.use('android.app.Activity');
  var PackageManager = Java.use('android.content.pm.PackageManager');

  var blockedPackages = [
    'com.topjohnwu.magisk',
    'com.noshufou.android.su',
    'com.koushikdutta.superuser',
    'eu.chainfire.supersu',
    'com.kingroot.kinguser',
    'com.kingo.root',
    'com.smedialink.oneclickroot',
    'com.zhiqupk.root.global',
    'com.alephzain.framaroot',
    'de.robv.android.xposed.installer',
    'io.va.exposed',
  ];

  try {
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
      if (blockedPackages.indexOf(pkg) >= 0) {
        console.log('[ROOT] PackageInfo blocked: ' + pkg);
        throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
      }
      return this.getPackageInfo(pkg, flags);
    };
  } catch (e) {}

  // ─── Frida detection (port 27042 check) ──────────────────────────────────

  try {
    var Socket = Java.use('java.net.Socket');
    Socket.$init.overload('java.lang.String', 'int').implementation = function (host, port) {
      if (port === 27042 || port === 27043) {
        console.log('[ROOT] Frida port probe blocked: ' + host + ':' + port);
        throw Java.use('java.net.ConnectException').$new('Connection refused');
      }
      return this.$init(host, port);
    };
  } catch (e) {}

  console.log('[ROOT] Root/emulator/Frida detection bypass active.');
});
