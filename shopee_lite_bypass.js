'use strict';

// Shopee Lite bypass — Frida 17+ compatible

function log(tag, msg) {
    console.log('[' + tag + '] ' + msg);
}

function addr(p) {
    try { return '0x' + p.toString(16).toUpperCase().padStart(12, '0'); } catch (_e) { return '0x?'; }
}

function hexpreview(str, maxBytes) {
    if (!str) return '<null>';
    var n = Math.min(str.length, maxBytes || 32);
    var hex = '';
    for (var i = 0; i < n; i++) {
        hex += ('0' + str.charCodeAt(i).toString(16)).slice(-2) + ' ';
    }
    return hex.trim() + (str.length > n ? ' ...' : '');
}

function dumpModules() {
    var targets = ['libc.so', 'libshpssdk.so', 'libandroid.so', 'libssl.so', 'libart.so'];
    var found = {};
    Process.enumerateModules().forEach(function (m) {
        for (var i = 0; i < targets.length; i++) {
            if (m.name === targets[i] && !found[m.name]) {
                found[m.name] = true;
                log('MOD', m.name + '\t base=' + addr(m.base) + '  size=0x' + m.size.toString(16));
            }
        }
    });
}

// ─── 1. RootBeer native ───────────────────────────────────────────────────────

function bypassRootBeer() {
    try {
        const RootBeerNative = Java.use('com.scottyab.rootbeer.RootBeerNative');
        RootBeerNative.checkForRoot.implementation = function (_paths) {
            log('ROOT', 'RootBeerNative.checkForRoot() -> 0');
            return 0;
        };
    } catch (e) {
        log('WARN', 'RootBeerNative: ' + e.message);
    }
}

// ─── 1b. androidx.core.b.q() — THE root check ────────────────────────────────
// x.f() and y.f() both call: is_rooted(Boolean.valueOf(androidx.core.b.q()))
// Killing q() here stops is_rooted=true from reaching DeviceExt.Builder in both
// TCP login request paths.

function bypassCoreRootCheck() {
    // Main root check: Build.TAGS test-keys + su file check + which su exec
    try {
        const CoreUtils = Java.use('androidx.core.b');
        log('ROOT', 'androidx.core.b class resolved OK');
        try {
            CoreUtils.q.implementation = function () {
                log('ROOT', 'androidx.core.b.q() -> false');
                return false;
            };
            log('ROOT', 'CoreUtils.q hook installed');
        } catch (e) { log('WARN', 'CoreUtils.q hook: ' + e.message); }
        try {
            CoreUtils.b.implementation = function () {
                log('ROOT', 'androidx.core.b.b() -> false');
                return false;
            };
            log('ROOT', 'CoreUtils.b hook installed');
        } catch (e) { log('WARN', 'CoreUtils.b hook: ' + e.message); }
    } catch (e) { log('WARN', 'CoreRootCheck: ' + e.message); }

    // File existence helper called by b() for su binary paths
    try {
        const MediaSessionA = Java.use('android.support.v4.media.session.a');
        MediaSessionA.b.overload('java.lang.String').implementation = function (path) {
            if (path && (path.indexOf('/su') !== -1 || path.indexOf('uperuser') !== -1 || path.indexOf('rootbeer') !== -1)) {
                log('ROOT', 'session.a.b(' + path + ') -> false');
                return false;
            }
            return this.b(path);
        };
    } catch (_e) {}

    // Block Runtime.exec(["which", "su"]) — q() exec-checks su after file checks
    // If which su succeeds on emulator, q() returns true regardless of file hooks
    try {
        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdarray) {
            if (cmdarray && cmdarray.length >= 2) {
                const last = String(cmdarray[cmdarray.length - 1]);
                if (last === 'su' || last === 'su\n') {
                    log('ROOT', 'Runtime.exec(which su) -> /system/bin/true (empty output)');
                    return this.exec(['/system/bin/true']);
                }
            }
            return this.exec(cmdarray);
        };
        log('ROOT', 'Runtime.exec hook installed');
    } catch (e) { log('WARN', 'Runtime.exec hook: ' + e.message); }

    // Belt+suspenders: intercept at DeviceExt.Builder.is_rooted() protobuf builder
    try {
        const DeviceExtBuilder = Java.use('com.shopee.protocol.action.DeviceExt$Builder');
        DeviceExtBuilder.is_rooted.overload('java.lang.Boolean').implementation = function (_val) {
            log('ROOT', 'DeviceExt.Builder.is_rooted() -> false');
            return this.is_rooted(Java.use('java.lang.Boolean').valueOf(false));
        };
        log('ROOT', 'DeviceExt.Builder.is_rooted hook installed');
    } catch (e) { log('WARN', 'DeviceExtBuilder.is_rooted: ' + e.message); }

    // ClientStats.toProtobuf() sends is_rooted / tongdunBlackboxData / szDeviceFingerPrint
    // All are final Kotlin fields — patch via reflection before serialization
    try {
        const ClientStats = Java.use('com.shopee.app.network.request.extended.clientstats.ClientStats');

        function patchClientStatsFields(instance) {
            const clazz = instance.getClass();
            const fields = {
                'isRooted': { bool: false },
                'isFingerprintTempered': { bool: false },
                'tongdunBlackboxData': { str: '' }
            };
            for (const name in fields) {
                try {
                    const f = clazz.getDeclaredField(name);
                    f.setAccessible(true);
                    if (fields[name].bool !== undefined) {
                        f.setBoolean(instance, fields[name].bool);
                    } else {
                        f.set(instance, fields[name].str);
                    }
                } catch (_e) {}
            }
            log('ROOT', 'ClientStats patched: isRooted=false tongdun=""');
        }

        ClientStats.toProtobuf.overload().implementation = function () {
            try { patchClientStatsFields(this); } catch (e) { log('WARN', 'ClientStats reflect: ' + e.message); }
            return this.toProtobuf();
        };
        ClientStats.toProtobuf.overload('com.shopee.app.network.request.extended.clientstats.ClientStats').implementation = function (oldStats) {
            try { patchClientStatsFields(this); } catch (e) { log('WARN', 'ClientStats(oldStats) reflect: ' + e.message); }
            return this.toProtobuf(oldStats);
        };
    } catch (e) { log('WARN', 'ClientStats.toProtobuf: ' + e.message); }
}

// ─── 8. SHPSSDK / TongDun bypass ────────────────────────────────────────────
// SHPSSDK.getRiskToken() generates an encrypted device-fingerprint token from
// libshpssdk.so. Returning "" breaks the server-side validation differently from
// F13 ("Halaman Tidak Tersedia"). Instead, let libshpssdk.so generate a real
// token but with root/Frida/emulator signals scrubbed via native hooks (see
// bypassNativeSecurity below). Only TongDun blackbox is zeroed (separate SDK).

function bypassSPSSdk() {
    // TongDun blackbox only — cleared at ClientIdentifier proto builder level
    try {
        const CIBuilder = Java.use('com.shopee.protocol.action.ClientIdentifier$Builder');
        CIBuilder.tongdun_blackbox.overload('java.lang.String').implementation = function (_str) {
            log('SPS', 'ClientIdentifier.Builder.tongdun_blackbox() -> ""');
            try {
                const f = this.getClass().getDeclaredField('tongdun_blackbox');
                f.setAccessible(true);
                f.set(this, '');
            } catch (_e) {}
            return this;
        };
        log('SPS', 'ClientIdentifier.Builder.tongdun_blackbox hook installed');
    } catch (e) { log('WARN', 'ClientIdentifier.tongdun_blackbox: ' + e.message); }

    // SHPSSDK.Builder.toggle(boolean) controls sensor-data collection.
    // toggle() is sometimes NOT called by the app (remote config feature flag OFF) → default=false.
    // Hook build() to force toggle(true) before building so sensor collection always happens.
    // Native ASensor_getVendor is hooked separately to spoof "Goldfish" → "STMicroelectronics".
    // NOTE: build()→toggle(true) was tried but causes sensor-wait delay that breaks
    // login form timing. Toggle() is not called by the app (server feature flag=OFF),
    // so default=false (no sensor collection) → 155-byte short token generated quickly.
    try {
        const SHPSSBuilder = Java.use('com.shopee.shpssdk.SHPSSDK$Builder');
        SHPSSBuilder.toggle.overload('boolean').implementation = function (_z) {
            log('SPS', 'SHPSSDK.Builder.toggle(' + _z + ') called');
            return this.toggle.call(this, _z);
        };
        log('SPS', 'SHPSSDK.Builder.toggle hook installed (pass-through, logging)');
    } catch (e) { log('WARN', 'SHPSSDK.Builder.toggle: ' + e.message); }

    // getRiskToken: pass-through + log (needed for startup; don't return "" here).
    try {
        const SHPSSDK_cls = Java.use('com.shopee.shpssdk.SHPSSDK');
        SHPSSDK_cls.getRiskToken.overload('android.content.Context').implementation = function (ctx) {
            const token = this.getRiskToken.call(this, ctx);
            const preview = token ? token.substring(0, 60) : '<null>';
            log('SPS', 'getRiskToken() len=' + (token ? token.length : 0) + ' preview=' + preview);
            return token;
        };
        log('SPS', 'SHPSSDK.getRiskToken hook installed (logging)');
    } catch (e) { log('WARN', 'SHPSSDK.getRiskToken: ' + e.message); }

    // getRiskSync / getRiskAsync — local device integrity checks returning SPSType enum list.
    // EMULATOR/ROOT/HOOK in the list causes HaTe locally. Force SAFETY.
    try {
        const SHPSSDK_cls2 = Java.use('com.shopee.shpssdk.SHPSSDK');
        const ArrayList = Java.use('java.util.ArrayList');
        try {
            SHPSSDK_cls2.getRiskSync.overload('android.content.Context').implementation = function (_ctx) {
                const lst = ArrayList.$new();
                log('SPS', 'getRiskSync() -> [] (forced SAFETY)');
                return lst;
            };
        } catch (_e) {}
        try {
            // getRiskAsync with callback — find overloads by trying common signatures
            const overloads = SHPSSDK_cls2.getRiskAsync.overloads;
            overloads.forEach(function (ov) {
                ov.implementation = function () {
                    log('SPS', 'getRiskAsync() intercepted — invoking with forced SAFETY callback');
                    // Call original but we'll hook the callback result
                    return ov.apply(this, arguments);
                };
            });
        } catch (_e) {}
        log('SPS', 'getRiskSync/Async hooks installed');
    } catch (e) { log('WARN', 'getRiskSync/Async: ' + e.message); }

    // Log the risk_token returned by df.infra.sz.shopee.co.id.
    // Called with (false, riskToken) when a fresh server token is stored.
    // Logging helps understand what Part2 the server sends — useful for crafting bypass.
    try {
        const RiskStore = Java.use('com.shopee.shpssdk.uuuvuvvww.vwwwuwwvv.vwwuvwwvv');
        RiskStore.uwwuwuwuv.overload('boolean', 'java.lang.String').implementation = function (fresh, token) {
            var tlen = token ? token.length : 0;
            log('SPS', 'RISK_TOKEN_STORED: fresh=' + fresh + ' len=' + tlen);
            if (token && tlen > 0) {
                log('SPS', 'TOKEN_TXT: ' + token.substring(0, 80) + (tlen > 80 ? '...' : ''));
                log('SPS', 'TOKEN_HEX: ' + hexpreview(token, 24));
            }
            return this.uwwuwuwuv(fresh, token);
        };
        log('SPS', 'risk_token storage hook installed');
    } catch (e) { log('WARN', 'risk_token storage hook: ' + e.message); }

    // F13 bypass: SPSSDKDelegate.getDeviceFingerPrint is called ONLY from Login.Builder
    // to set security_device_fingerprint in the login protobuf.
    // Returning "" sends no SPS token with the login request → server cannot do risk-based F13 block.
    try {
        const SPSDelegate = Java.use('com.shopee.app.util.tongdun.SPSSDKDelegate');
        SPSDelegate.getDeviceFingerPrint.implementation = function (_ctx) {
            log('SPS', 'getDeviceFingerPrint -> "" (F13 bypass)');
            return '';
        };
        log('SPS', 'getDeviceFingerPrint hook installed (F13 bypass)');
    } catch (e) { log('WARN', 'getDeviceFingerPrint hook: ' + e.message); }

}

// ─── 2. Emulator detection ────────────────────────────────────────────────────

function bypassEmulator() {
    try {
        const EmulatorA = Java.use('com.shopee.libdeviceinfo.emulator.a');
        EmulatorA.a.overload('[Ljava.lang.String;').implementation = function (_paths) {
            log('EMULATOR', 'emulator.a.a() -> false');
            return false;
        };
        EmulatorA.b.overload('android.content.Context').implementation = function (_ctx) {
            log('EMULATOR', 'emulator.a.b() -> false');
            return false;
        };
    } catch (e) {
        log('WARN', 'emulator.a: ' + e.message);
    }

    try {
        const RNInfo = Java.use('com.facebook.react.modules.systeminfo.AndroidInfoHelpers');
        try { RNInfo.isRunningOnGenymotion.implementation = function () { return false; }; } catch (_e) {}
        try { RNInfo.isRunningOnStockEmulator.implementation = function () { return false; }; } catch (_e) {}
    } catch (_e) {}
}

// ─── 3. CommonInfo telemetry ──────────────────────────────────────────────────

function bypassTelemetry() {
    try {
        const CommonInfo = Java.use('com.shopee.luban.common.model.common.CommonInfo');

        try {
            CommonInfo.isRoot.overload().implementation = function () {
                log('TELEMETRY', 'CommonInfo.isRoot() -> false');
                return false;
            };
        } catch (_e) {}

        try {
            CommonInfo.isEmulator.overload().implementation = function () {
                log('TELEMETRY', 'CommonInfo.isEmulator() -> false');
                return false;
            };
        } catch (_e) {}

        try {
            CommonInfo.toPBCommonInfo.implementation = function () {
                try {
                    const clazz = this.getClass();

                    const setBool = function(name, val) {
                        try {
                            const f = clazz.getDeclaredField(name);
                            f.setAccessible(true);
                            try { f.setBoolean(this, val); }
                            catch (_e) { f.set(this, Java.use('java.lang.Boolean').valueOf(val)); }
                        } catch (e) { log('WARN', 'setBool ' + name + ': ' + e.message); }
                    }.bind(this);

                    const setStr = function(name, val) {
                        try {
                            const f = clazz.getDeclaredField(name);
                            f.setAccessible(true);
                            f.set(this, val);
                        } catch (e) { log('WARN', 'setStr ' + name + ': ' + e.message); }
                    }.bind(this);

                    setBool('isRoot', false);
                    setBool('isEmulator', false);
                    setStr('deviceFingerPrint', 'ed083ba0ae636b33_SM-G9750');
                    setStr('region', 'ID');

                    log('TELEMETRY', 'toPBCommonInfo() patched: isRoot=false isEmulator=false region=ID');
                } catch (e) { log('WARN', 'toPBCommonInfo reflect: ' + e.message); }
                return this.toPBCommonInfo();
            };
        } catch (_e) {}

    } catch (e) {
        log('WARN', 'CommonInfo: ' + e.message);
    }
}

// ─── 4. SSL pinning (OkHttp3) ────────────────────────────────────────────────

function bypassSSL() {
    try {
        const CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner['check'].overload('java.lang.String', 'java.util.List').implementation =
            function (host, _certs) {
                log('SSL', 'CertificatePinner.check(' + host + ') bypassed');
            };
        try {
            CertPinner['check'].overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation =
                function (host, _fn) {
                    log('SSL', 'CertificatePinner.check(kotlin)(' + host + ') bypassed');
                };
        } catch (_e) {}
    } catch (e) {
        log('WARN', 'OkHttp3 CertPinner: ' + e.message);
    }

    try {
        const TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.verifyChain.implementation = function (chain, _anchors, host, _clientAuth, _ocsp, _sct) {
            log('SSL', 'TrustManagerImpl.verifyChain(' + host + ') bypassed');
            return chain;
        };
    } catch (e) {
        log('WARN', 'TrustManagerImpl: ' + e.message);
    }
}

// ─── 5. Build props spoof ────────────────────────────────────────────────────
// Build.TAGS must be "release-keys" — androidx.core.b.q() checks TAGS.contains("test-keys")
// Emulators default to "test-keys" which triggers isRooted=true before any file check.

function spoofBuild() {
    try {
        const Build = Java.use('android.os.Build');
        Build.FINGERPRINT.value  = 'samsung/beyond1qltezxm/beyond1q:12/SP1A.210812.016/G9750ZHU7GVI5:user/release-keys';
        Build.HARDWARE.value     = 'kona';
        Build.PRODUCT.value      = 'beyond1q';
        Build.BOARD.value        = 'msmnile';
        Build.MANUFACTURER.value = 'samsung';
        Build.MODEL.value        = 'SM-G9750';
        Build.BRAND.value        = 'samsung';
        Build.TAGS.value         = 'release-keys';
        Build.TYPE.value         = 'user';
        log('SPOOF', 'Build props -> Samsung SM-G9750 (release-keys)');
    } catch (e) {
        log('WARN', 'Build spoof: ' + e.message);
    }

    // IMEI spoofing — emulator returns "000000000000000" which is a well-known emulator ID.
    // TelephonyManager.getDeviceId() (deprecated API 26) and getImei() (API 26+) both leak it.
    try {
        const TelephonyManager = Java.use('android.telephony.TelephonyManager');
        const FAKE_IMEI = '358423097812345'; // fresh IMEI — rotated to change SPS token
        try {
            TelephonyManager.getDeviceId.overload().implementation = function () {
                log('SPOOF', 'TelephonyManager.getDeviceId() -> ' + FAKE_IMEI);
                return FAKE_IMEI;
            };
        } catch (_e) {}
        try {
            TelephonyManager.getImei.overload().implementation = function () {
                log('SPOOF', 'TelephonyManager.getImei() -> ' + FAKE_IMEI);
                return FAKE_IMEI;
            };
        } catch (_e) {}
        try {
            TelephonyManager.getImei.overload('int').implementation = function (_slot) {
                return FAKE_IMEI;
            };
        } catch (_e) {}
        log('SPOOF', 'IMEI hooks installed (' + FAKE_IMEI + ')');
    } catch (e) { log('WARN', 'IMEI spoof: ' + e.message); }

    // NOTE: Settings.Secure.android_id hook removed — Settings.Secure.getString is called too
    // frequently during app init, causing V8 overhead that delays login form rendering.
    // If android_id proves to be an F13 signal, address via lower-level ContentProvider hook.
}

// ─── 6 & 7. Native hooks ─────────────────────────────────────────────────────

function resolveExport(exportName, optModuleName) {
    if (optModuleName) {
        try {
            const m = Process.getModuleByName(optModuleName);
            const a = m.findExportByName(exportName);
            if (a && !a.isNull()) return a;
        } catch (_e) {}
    }
    try {
        const a = Module.findExportByName(optModuleName || null, exportName);
        if (a && !a.isNull()) return a;
    } catch (_e) {}
    try {
        const a = Module.findExportByName(exportName);
        if (a && !a.isNull()) return a;
    } catch (_e) {}
    try {
        for (const m of Process.enumerateModules()) {
            try {
                const a = m.findExportByName(exportName);
                if (a && !a.isNull()) return a;
            } catch (_e) {}
        }
    } catch (_e) {}
    return null;
}

function safeAttach(sym, callbacks, label) {
    if (!sym || sym.isNull()) return false;
    try {
        Interceptor.attach(sym, callbacks);
        if (label) log('HOOK', label + ' @ ' + addr(sym));
        return true;
    } catch (_e) { return false; }
}

function bypassNativeExists() {
    try {
        const sym = resolveExport('_Z6existsPKc', 'libtoolChecker.so');
        if (sym) {
            safeAttach(sym, {
                onEnter: function (args) { try { this.path = args[0].readUtf8String(); } catch (_e) { this.path = '?'; } },
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) {
                        log('NATIVE', 'exists(' + this.path + ') -> 0');
                        retval.replace(ptr(0));
                    }
                }
            });
            log('NATIVE', 'libtoolChecker.exists() hooked (early)');
            return;
        }

        const dlopenSym = resolveExport('android_dlopen_ext') || resolveExport('dlopen');
        if (!dlopenSym) { log('WARN', 'dlopen not found — skip exists() watch'); return; }

        let hooked = false;
        safeAttach(dlopenSym, {
            onEnter: function (args) { try { this.lib = args[0].readUtf8String(); } catch (_e) { this.lib = ''; } },
            onLeave: function (_ret) {
                if (hooked || !this.lib || this.lib.indexOf('libtoolChecker.so') === -1) return;
                const s = resolveExport('_Z6existsPKc', 'libtoolChecker.so');
                if (s && safeAttach(s, {
                    onEnter: function (a) { try { this.path = a[0].readUtf8String(); } catch (_e) { this.path = '?'; } },
                    onLeave: function (r) { if (r.toInt32() !== 0) { log('NATIVE', 'exists(' + this.path + ') -> 0'); r.replace(ptr(0)); } }
                })) { hooked = true; log('NATIVE', 'libtoolChecker.exists() hooked (late)'); }
            }
        });
        log('NATIVE', 'dlopen watcher set for libtoolChecker.so');
    } catch (e) {
        log('WARN', 'bypassNativeExists: ' + e.message);
    }
}

// Filtered /proc/self/maps — real maps with Frida entries removed.
// /dev/null was previously used but an EMPTY maps file is a strong anomaly signal.
// Generated once in Java.perform using Java IO (bypasses our libc hooks) at startup.
var _fakeMapsPath = '/data/local/tmp/fake_maps_sps';
var _fakeMapsReady = false;
var _trafficIntercepted = false;  // guard against CLEAR_TASK infinite loop

function generateFilteredMaps() {
    // Use shell cat on /proc/<pid>/maps so our own fopen/open hooks don't intercept it.
    // The child sh process reads from /proc/<shopee-pid>/maps directly (no hook).
    try {
        var pid = Java.use('android.os.Process').myPid();
        var rt = Java.use('java.lang.Runtime').getRuntime();
        var proc = rt.exec([
            '/system/bin/sh', '-c',
            "cat /proc/" + pid + "/maps | grep -v frida | grep -v gadget | grep -v xposed > " + _fakeMapsPath
        ]);
        proc.waitFor();
        _fakeMapsReady = true;
        log('MAPS', 'Filtered maps written via shell for PID ' + pid + ' -> ' + _fakeMapsPath);
    } catch (e) { log('WARN', 'generateFilteredMaps (shell): ' + e.message); }
}

// Module-range cache for caller-attribution in I/O hooks.
// Populated lazily after libshpssdk.so loads. Only used for diagnostic logging.
var _spsMod = null;
function _spsFromHere(ra) {
    try {
        if (!_spsMod) _spsMod = Process.findModuleByName('libshpssdk.so');
        if (!_spsMod || !ra) return false;
        return ra.compare(_spsMod.base) >= 0 &&
               ra.compare(_spsMod.base.add(_spsMod.size)) < 0;
    } catch (_e) { return false; }
}

function hideFrida() {
    try {
        const fopen = resolveExport('fopen', 'libc.so');
        if (!fopen) { log('WARN', 'fopen not found'); return; }
        const ok = safeAttach(fopen, {  /* label logged separately via ok path below */
            onEnter: function (args) {
                try {
                    const path = args[0].readUtf8String();
                    // Log every fopen from libshpssdk.so so we can see ALL paths it reads
                    if (path && _spsFromHere(this.returnAddress)) {
                        log('SPS_IO', 'libshpssdk.fopen("' + path + '")');
                    }
                    // /proc/self/maps → filtered maps (real entries minus frida).
                    // Redirecting to /dev/null creates an empty file which is a strong
                    // anomaly signal (real apps always have many mappings).
                    if (path && path.indexOf('/proc/self/maps') !== -1) {
                        var mapsTarget = _fakeMapsReady ? _fakeMapsPath : '/dev/null';
                        args[0] = Memory.allocUtf8String(mapsTarget);
                        log('NATIVE', 'fopen(' + path + ') -> ' + (_fakeMapsReady ? 'fake_maps_sps' : '/dev/null'));
                    }
                    // /proc/self/smaps — extended maps with memory details; redirect to /dev/null
                    if (path && path.indexOf('/proc/self/smaps') !== -1) {
                        args[0] = Memory.allocUtf8String('/dev/null');
                        log('NATIVE', 'fopen(' + path + ') -> /dev/null (smaps)');
                    }
                    // Network/version paths that could reveal QEMU topology or kernel version:
                    if (path && (path.indexOf('/proc/net/tcp') !== -1 ||
                                 path.indexOf('/proc/net/unix') !== -1)) {
                        args[0] = Memory.allocUtf8String('/dev/null');
                        log('NATIVE', 'fopen(' + path + ') -> /dev/null');
                    }
                    // cpuinfo → fake ARM64 Exynos 9820 (SPS-only, not global).
                    // Global redirect caused non-SPS libs (OpenSSL etc.) to see ARM64 → SIGILL.
                    // Previous: global /dev/null = empty suspicious. Now: SPS-only fake ARM64.
                    if (path && path.indexOf('/proc/cpuinfo') !== -1 && _spsFromHere(this.returnAddress)) {
                        args[0] = Memory.allocUtf8String('/data/local/tmp/fake_cpuinfo');
                        log('NATIVE', 'fopen(' + path + ') [SPS] -> fake_cpuinfo (ARM64)');
                    } else if (path && path.indexOf('/proc/cpuinfo') !== -1) {
                        // Non-SPS callers still need empty (not real x86 content for anti-cheat tools)
                        args[0] = Memory.allocUtf8String('/dev/null');
                        log('NATIVE', 'fopen(' + path + ') -> /dev/null');
                    }
                    // Redirect /proc/net/arp for SPS only: real QEMU ARP (52:54:00:..., 10.0.2.x)
                    // is a definitive emulator signal. Fake WiFi ARP consistent with ARM64 HWCAP
                    // + aarch64 uname. SPS-only (not global) to avoid HaTe.
                    if (path && path.indexOf('/proc/net/arp') !== -1 && _spsFromHere(this.returnAddress)) {
                        args[0] = Memory.allocUtf8String('/data/local/tmp/fake_arp');
                        log('NATIVE', 'fopen(/proc/net/arp) [SPS] -> fake_arp (WiFi)');
                    }
                    // Battery cycle: emulator has no battery files → ENOENT → suspicious.
                    // Real device (SM-G9750, ~1yr): battery_cycle ≈ 280.
                    if (path && _spsFromHere(this.returnAddress) &&
                        (path.indexOf('/sys/class/power_supply/battery/battery_cycle') !== -1 ||
                         path.indexOf('/sys/class/power_supply/battery/cycle_count') !== -1)) {
                        args[0] = Memory.allocUtf8String('/data/local/tmp/fake_battery_cycle');
                        log('NATIVE', 'fopen(' + path + ') [SPS] -> fake_battery_cycle (280)');
                    }
                } catch (_e) {}
            }
        });
        if (ok) log('HOOK', 'fopen @ ' + addr(fopen));
        log('NATIVE', ok ? 'fopen hook active' : 'fopen attach failed');
    } catch (e) {
        log('WARN', 'hideFrida: ' + e.message);
    }
}

// ─── 9. Broad native security hook ───────────────────────────────────────────
// Hook open/access/stat/__system_property_get so libshpssdk.so (and any other
// native detector) sees no su binaries, no Frida maps, and real-device props.
// This lets libshpssdk.so generate a structurally-valid SPS token without
// root/Frida/emulator signals — server accepts the token and doesn't send F13.

function bypassNativeSecurity() {
    const SU_PATHS = [
        '/system/bin/su', '/system/xbin/su', '/sbin/su',
        '/data/local/xbin/su', '/data/local/su', '/su/bin/su',
        '/system/sd/xbin/su', '/system/bin/failsafe/su',
        '/system/app/Superuser.apk', '/system/app/SuperSU.apk',
        '/data/local/bin/su',
        // Magisk-specific paths
        '/data/adb/magisk', '/sbin/.magisk', '/dev/.magisk',
        '/data/adb/ksu', '/data/adb/apatch'
    ];

    function isSuPath(p) {
        if (!p) return false;
        for (var i = 0; i < SU_PATHS.length; i++) {
            if (p === SU_PATHS[i] || p.indexOf(SU_PATHS[i]) === 0) return true;
        }
        return false;
    }

    // Paths redirected via open/openat/__open_2 (NOT fopen — see hideFrida).
    // /proc/self/maps: use filtered maps (real entries minus frida), not /dev/null.
    // /proc/net/tcp, /proc/net/unix: /dev/null (QEMU network topology detection).
    function isMapsPath(p) {
        return p && (p.indexOf('/proc/net/tcp')  !== -1 ||
                     p.indexOf('/proc/net/unix') !== -1);
    }
    function isSelfMapsPath(p) {
        return p && p.indexOf('/proc/self/maps') !== -1;
    }

    // QEMU-specific device/pseudo-paths → redirect to non-existent path
    var QEMU_PATHS = [
        '/dev/goldfish_pipe', '/dev/qemu_pipe', '/dev/goldfish_sync_fence',
        '/dev/goldfish_audio', '/dev/goldfish_fb'
    ];
    function isQemuPath(p) {
        if (!p) return false;
        for (var i = 0; i < QEMU_PATHS.length; i++) {
            if (p === QEMU_PATHS[i] || p.indexOf(QEMU_PATHS[i]) === 0) return true;
        }
        return false;
    }

    // open() / open64() — redirect su/qemu/tcp paths; maps → filtered fake
    var open_sym = resolveExport('open', 'libc.so') || resolveExport('open64', 'libc.so');
    if (open_sym) {
        safeAttach(open_sym, {
            onEnter: function (args) {
                try {
                    var p = args[0].readUtf8String();
                    if (isSelfMapsPath(p)) {
                        args[0] = Memory.allocUtf8String(_fakeMapsReady ? _fakeMapsPath : '/dev/null');
                        log('NATIVE', 'open(' + p + ') -> ' + (_fakeMapsReady ? 'fake_maps_sps' : '/dev/null'));
                    } else if (isMapsPath(p)) {
                        args[0] = Memory.allocUtf8String('/dev/null');
                        log('NATIVE', 'open(' + p + ') -> /dev/null');
                    } else if (isSuPath(p) || isQemuPath(p)) {
                        args[0] = Memory.allocUtf8String('/proc/_no_su_');
                        log('NATIVE', 'open(' + p + ') -> blocked');
                    }
                } catch (_e) {}
            }
        }, 'open');
        log('NATIVE', 'open() hook active');
    } else { log('WARN', 'open() not found in libc.so'); }

    // openat() — same filters, path is args[1]
    var openat_sym = resolveExport('openat', 'libc.so') || resolveExport('openat64', 'libc.so');
    if (openat_sym) {
        safeAttach(openat_sym, {
            onEnter: function (args) {
                try {
                    var p = args[1].readUtf8String();
                    if (isSelfMapsPath(p)) {
                        args[1] = Memory.allocUtf8String(_fakeMapsReady ? _fakeMapsPath : '/dev/null');
                        log('NATIVE', 'openat(' + p + ') -> ' + (_fakeMapsReady ? 'fake_maps_sps' : '/dev/null'));
                    } else if (isMapsPath(p)) {
                        args[1] = Memory.allocUtf8String('/dev/null');
                        log('NATIVE', 'openat(' + p + ') -> /dev/null');
                    } else if (isSuPath(p) || isQemuPath(p)) {
                        args[1] = Memory.allocUtf8String('/proc/_no_su_');
                        log('NATIVE', 'openat(' + p + ') -> blocked');
                    }
                } catch (_e) {}
            }
        }, 'openat');
        log('NATIVE', 'openat() hook active');
    }

    // access() — return -1 for su paths
    var access_sym = resolveExport('access', 'libc.so');
    if (access_sym) {
        safeAttach(access_sym, {
            onEnter: function (args) { try { this.p = args[0].readUtf8String(); } catch (_e) {} },
            onLeave: function (retval) {
                if (isSuPath(this.p) && retval.toInt32() === 0) {
                    retval.replace(ptr(-1));
                    log('NATIVE', 'access(' + this.p + ') -> -1');
                }
            }
        }, 'access');
        log('NATIVE', 'access() hook active');
    }

    // stat() / lstat() — return -1 for su paths
    var stat_sym = resolveExport('stat', 'libc.so') || resolveExport('stat64', 'libc.so') || resolveExport('__stat64', 'libc.so');
    if (stat_sym) {
        safeAttach(stat_sym, {
            onEnter: function (args) { try { this.p = args[0].readUtf8String(); } catch (_e) {} },
            onLeave: function (retval) {
                if (isSuPath(this.p) && retval.toInt32() === 0) {
                    retval.replace(ptr(-1));
                    log('NATIVE', 'stat(' + this.p + ') -> -1');
                }
            }
        }, 'stat');
        log('NATIVE', 'stat() hook active');
    }

    var lstat_sym = resolveExport('lstat', 'libc.so') || resolveExport('lstat64', 'libc.so');
    if (lstat_sym) {
        safeAttach(lstat_sym, {
            onEnter: function (args) { try { this.p = args[0].readUtf8String(); } catch (_e) {} },
            onLeave: function (retval) {
                if (isSuPath(this.p) && retval.toInt32() === 0) {
                    retval.replace(ptr(-1));
                    log('NATIVE', 'lstat(' + this.p + ') -> -1');
                }
            }
        }, 'lstat');
        log('NATIVE', 'lstat() hook active');
    }

    // __open_2 — Android's 2-arg open() variant that libc.so compiles to
    var open2_sym = resolveExport('__open_2', 'libc.so');
    if (open2_sym) {
        safeAttach(open2_sym, {
            onEnter: function (args) {
                try {
                    var p = args[0].readUtf8String();
                    if (isSelfMapsPath(p)) {
                        args[0] = Memory.allocUtf8String(_fakeMapsReady ? _fakeMapsPath : '/dev/null');
                        log('NATIVE', '__open_2(' + p + ') -> ' + (_fakeMapsReady ? 'fake_maps_sps' : '/dev/null'));
                    } else if (isMapsPath(p)) {
                        args[0] = Memory.allocUtf8String('/dev/null');
                        log('NATIVE', '__open_2(' + p + ') -> /dev/null');
                    } else if (isSuPath(p) || isQemuPath(p)) {
                        args[0] = Memory.allocUtf8String('/proc/_no_su_');
                        log('NATIVE', '__open_2(' + p + ') -> blocked');
                    }
                } catch (_e) {}
            }
        }, '__open_2');
        log('NATIVE', '__open_2() hook active');
    } else { log('WARN', '__open_2 not found'); }

    // fstatat — stat with dirfd, used instead of stat() on Android
    var fstatat_sym = resolveExport('fstatat', 'libc.so') || resolveExport('fstatat64', 'libc.so');
    if (fstatat_sym) {
        safeAttach(fstatat_sym, {
            onEnter: function (args) { try { this.p = args[1].readUtf8String(); } catch (_e) {} },
            onLeave: function (retval) {
                if (isSuPath(this.p) && retval.toInt32() === 0) {
                    retval.replace(ptr(-1));
                    log('NATIVE', 'fstatat(' + this.p + ') -> -1');
                }
            }
        }, 'fstatat');
        log('NATIVE', 'fstatat() hook active');
    }

    // popen — shell command execution e.g. "which su"
    var popen_sym = resolveExport('popen', 'libc.so');
    if (popen_sym) {
        safeAttach(popen_sym, {
            onEnter: function (args) {
                try {
                    var cmd = args[0].readUtf8String();
                    if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('busybox') !== -1 || cmd.indexOf('magisk') !== -1)) {
                        args[0] = Memory.allocUtf8String('echo ""');
                        log('NATIVE', 'popen("' + cmd + '") -> "echo """');
                    }
                } catch (_e) {}
            }
        }, 'popen');
        log('NATIVE', 'popen() hook active');
    }

    // dl_iterate_phdr — dynamic linker scans its own linked list (NOT /proc/self/maps)
    // so frida-agent-64.so appears even if we redirect maps to /dev/null.
    // IMPORTANT: create NativeCallback ONCE (not per-library entry) to avoid V8 alloc
    // overhead on every iteration (dl_iterate_phdr may be called 100s of times at startup).
    var dl_iter_sym = resolveExport('dl_iterate_phdr', 'libc.so');
    if (dl_iter_sym) {
        try {
            var _dlOrigFn = null; // cached NativeFunction for current invocation's callback
            var _dlWrapper = new NativeCallback(function (info, sz, ud) {
                try {
                    var np = info.add(8).readPointer();
                    if (!np.isNull()) {
                        var nm = np.readCString();
                        if (nm && (nm.indexOf('frida') !== -1 ||
                                   nm.indexOf('gadget') !== -1 ||
                                   nm.indexOf('xposed') !== -1)) {
                            log('NATIVE', 'dl_iterate_phdr: hiding "' + nm + '"');
                            return 0;
                        }
                    }
                } catch (_e) {}
                return _dlOrigFn ? _dlOrigFn(info, sz, ud) : 0;
            }, 'int', ['pointer', 'uint64', 'pointer']);
            safeAttach(dl_iter_sym, {
                onEnter: function (args) {
                    _dlOrigFn = new NativeFunction(args[0], 'int', ['pointer', 'uint64', 'pointer']);
                    args[0] = _dlWrapper;
                },
                onLeave: function (_retval) {
                    _dlOrigFn = null;
                }
            }, 'dl_iterate_phdr');
            log('NATIVE', 'dl_iterate_phdr() hooked (Frida filter, single-alloc)');
        } catch (e) { log('WARN', 'dl_iterate_phdr: ' + e.message); }
    } else { log('WARN', 'dl_iterate_phdr not found'); }

    // syscall() wrapper — raw syscall interception for openat/access/faccessat
    // libshpssdk.so imports syscall() directly; libc open/access hooks can be bypassed
    // x86-64 syscall numbers: openat=257, open=2, access=21, faccessat=269
    var syscall_sym = resolveExport('syscall', 'libc.so');
    if (syscall_sym) {
        safeAttach(syscall_sym, {
            onEnter: function (args) {
                try {
                    var nr = args[0].toInt32();
                    var pathArgIdx;
                    if (nr === 2) { pathArgIdx = 1; }        // SYS_open
                    else if (nr === 257) { pathArgIdx = 2; } // SYS_openat
                    else if (nr === 21) { pathArgIdx = 1; }  // SYS_access
                    else if (nr === 269) { pathArgIdx = 2; } // SYS_faccessat
                    else { return; }
                    var p = args[pathArgIdx].readUtf8String();
                    // Use arg pointer replacement (not in-place write) to avoid buffer overflow
                    // when new path is longer than original. Store ref on this to prevent GC.
                    if (p && p.indexOf('/proc/cpuinfo') !== -1) {
                        this._ref = Memory.allocUtf8String('/data/local/tmp/fake_cpuinfo');
                        args[pathArgIdx] = this._ref;
                        log('NATIVE', 'syscall(' + nr + ',' + p + ') -> fake_cpuinfo (ARM64)');
                    } else if (isSelfMapsPath(p)) {
                        this._ref = Memory.allocUtf8String(_fakeMapsReady ? _fakeMapsPath : '/dev/null');
                        args[pathArgIdx] = this._ref;
                        log('NATIVE', 'syscall(' + nr + ',' + p + ') -> ' + (_fakeMapsReady ? 'fake_maps_sps' : '/dev/null'));
                    } else if (isMapsPath(p)) {
                        this._ref = Memory.allocUtf8String('/dev/null');
                        args[pathArgIdx] = this._ref;
                        log('NATIVE', 'syscall(' + nr + ',' + p + ') -> /dev/null');
                    } else if (isSuPath(p)) {
                        this.blockSyscall = true;
                        this.nr = nr;
                        this._ref = Memory.allocUtf8String('/proc/_no_su_');
                        args[pathArgIdx] = this._ref;
                        log('NATIVE', 'syscall(' + nr + ',' + p + ') -> blocked');
                    }
                } catch (_e) {}
            },
            onLeave: function (retval) {
                // For access()/faccessat() raw syscall, also force -1 return
                if (this.blockSyscall && (this.nr === 21 || this.nr === 269)) {
                    if (retval.toInt32() === 0) { retval.replace(ptr(-1)); }
                }
            }
        }, 'syscall');
        log('NATIVE', 'syscall() hook active');
    }

    // __system_property_get — spoof emulator-revealing props
    var SPOOF_PROPS = {
        'ro.hardware':              'kona',
        'ro.kernel.qemu':           '0',
        'ro.kernel.android.qemud':  '0',
        'ro.build.tags':            'release-keys',
        'ro.build.type':            'user',
        'ro.product.model':         'SM-G9750',
        'ro.product.manufacturer':  'samsung',
        'ro.product.brand':         'samsung',
        'ro.build.fingerprint':     'samsung/beyond1qltezxm/beyond1q:12/SP1A.210812.016/G9750ZHU7GVI5:user/release-keys',
        'qemu.sf.fake_camera':      '',
        'init.svc.qemu-props':      '',
        'ro.product.board':         'msmnile',
        'ro.product.cpu.abi':       'arm64-v8a',
        'ro.product.cpu.abilist':   'arm64-v8a,armeabi-v7a,armeabi'
    };
    var propget_sym = resolveExport('__system_property_get', 'libc.so');
    if (propget_sym) {
        safeAttach(propget_sym, {
            onEnter: function (args) {
                try { this.name = args[0].readUtf8String(); } catch (_e) {}
                this.valPtr = args[1];
            },
            onLeave: function (retval) {
                if (this.name && SPOOF_PROPS.hasOwnProperty(this.name)) {
                    try {
                        var spoofed = SPOOF_PROPS[this.name];
                        Memory.writeUtf8String(this.valPtr, spoofed);
                        retval.replace(ptr(spoofed.length));
                        log('NATIVE', '__system_property_get(' + this.name + ') -> "' + spoofed + '"');
                    } catch (_e) {}
                }
            }
        }, '__system_property_get');
        log('NATIVE', '__system_property_get() hook active');
    }

    // __system_property_find — returns prop_info* (modern property API)
    // Return null for emulator-specific properties so find+read path is also blocked.
    // Block find() for emulator-revealing props so the find+read path is covered too.
    // __system_property_get is still hooked to spoof values for callers using get() directly.
    var BLOCK_PROP_FIND = {
        'ro.hardware': true,
        'ro.kernel.qemu': true, 'ro.kernel.android.qemud': true,
        'qemu.sf.fake_camera': true, 'init.svc.qemu-props': true,
        'ro.product.board': true
    };
    var propfind_sym = resolveExport('__system_property_find', 'libc.so');
    if (propfind_sym) {
        safeAttach(propfind_sym, {
            onEnter: function (args) { try { this.name = args[0].readUtf8String(); } catch (_e) {} },
            onLeave: function (retval) {
                if (this.name && BLOCK_PROP_FIND[this.name] && !retval.isNull()) {
                    retval.replace(ptr(0)); // null = property not found
                    log('NATIVE', '__system_property_find(' + this.name + ') -> null');
                }
            }
        }, '__system_property_find');
        log('NATIVE', '__system_property_find() hook active');
    }

    // uname() — returns kernel/machine info; x86_64 reveals emulator on ARM device
    // struct utsname offsets (Linux x86-64): sysname[65], nodename[65], release[65],
    // version[65], machine[65], domainname[65] — machine at offset 65*4=260
    var uname_sym = resolveExport('uname', 'libc.so');
    if (uname_sym) {
        safeAttach(uname_sym, {
            onEnter: function (args) { this.utsPtr = args[0]; },
            onLeave: function (retval) {
                if (retval.toInt32() === 0 && this.utsPtr && !this.utsPtr.isNull()) {
                    try {
                        var mach = this.utsPtr.add(65 * 4).readUtf8String();
                        if (mach && mach.indexOf('x86') !== -1) {
                            this.utsPtr.add(65 * 4).writeUtf8String('aarch64');
                            log('NATIVE', 'uname: machine x86_64 -> aarch64');
                        }
                    } catch (_e) {}
                }
            }
        }, 'uname');
        log('NATIVE', 'uname() hook active');
    }

    // ASensor_getVendor — native NDK sensor API used directly by libshpssdk.so.
    // Java Sensor.getVendor() hook doesn't cover this C function.
    // On QEMU emulator all sensors return vendor "Goldfish" — definitive emulator flag.
    // Persistent allocation so the returned pointer outlives the hook call.
    // ASensor_getVendor: LOG ONLY — spoofing "AOSP"→"STMicroelectronics" was tried but
    // caused server to detect "impossible device profile" → "Halaman Tidak Tersedia" (stronger
    // than F13, blocks home page). Logging only to confirm which sensors SPS enumerates.
    var asensorVendor = resolveExport('ASensor_getVendor', 'libandroid.so');
    if (asensorVendor) {
        safeAttach(asensorVendor, {
            onEnter: function (_args) {
                this._fromSps = _spsFromHere(this.returnAddress);
            },
            onLeave: function (retval) {
                try {
                    if (!this._fromSps) return;
                    if (!retval.isNull()) {
                        var v = retval.readCString();
                        if (v) log('NATIVE', 'ASensor_getVendor (SPS) = "' + v + '"');
                    }
                } catch (_e) {}
            }
        }, 'ASensor_getVendor');
        log('NATIVE', 'ASensor_getVendor() hook active (log-only)');
    }

    // getenv() — check for QEMU-specific env vars
    var BLOCK_ENVS = { 'ANDROID_QEMUD': '0', 'QEMU_PIPE': '' };
    var getenv_sym = resolveExport('getenv', 'libc.so');
    if (getenv_sym) {
        safeAttach(getenv_sym, {
            onEnter: function (args) { try { this.name = args[0].readUtf8String(); } catch (_e) {} },
            onLeave: function (retval) {
                if (this.name && BLOCK_ENVS.hasOwnProperty(this.name) && !retval.isNull()) {
                    retval.replace(ptr(0));
                    log('NATIVE', 'getenv(' + this.name + ') -> null');
                }
            }
        }, 'getenv');
        log('NATIVE', 'getenv() hook active');
    }

    // readlink() — /proc/self/fd/X symlinks point to "/memfd:frida-agent-64.so (deleted)"
    // Guard: minimum address 0x1000 for buf (callers may pass NULL/1 on error paths).
    var readlink_sym = resolveExport('readlink', 'libc.so');
    var _minBufAddr = ptr('0x1000');
    if (readlink_sym) {
        safeAttach(readlink_sym, {
            onEnter: function (args) {
                try { this.path = args[0].readUtf8String(); } catch (_e) {}
                this.buf = args[1];
            },
            onLeave: function (retval) {
                try {
                    var n = retval.toInt32();
                    if (n <= 0 || n >= 4096) return;
                    if (!this.buf || this.buf.isNull()) return;
                    if (this.buf.compare(_minBufAddr) <= 0) return; // guard: reject 0x1 etc.
                    var resolved = this.buf.readUtf8String(n);
                    if (resolved && (resolved.indexOf('frida') !== -1 ||
                                     resolved.indexOf('gadget') !== -1 ||
                                     resolved.indexOf('xposed') !== -1)) {
                        retval.replace(ptr(-1)); // ENOENT
                        log('NATIVE', 'readlink(' + this.path + ') hidden: "' + resolved + '"');
                    }
                } catch (_e) {}
            }
        }, 'readlink');
        log('NATIVE', 'readlink() hook active');
    }

    // getauxval: Spoof AT_HWCAP for SPS calls only.
    // Real x86_64 value 0x178bfbff is a definitive emulator signal in the SPS token.
    // Exynos 9820 (SM-G9750) ARM64 HWCAP: fp|asimd|evtstrm|aes|pmull|sha1|sha2|crc32
    //   |atomics|fphp|asimdhp|cpuid|asimdrdm|jscvt|fcma|lrcpc = 0xFFFF
    // Keep ARP unblocked (blocking ARP caused stronger "Halaman Tidak Tersedia" block).
    try {
        var _arm64Hwcap = ptr(0xFFFF); // ARM64 Exynos 9820 typical HWCAP
        var getauxval_ptr = resolveExport('getauxval', 'libc.so');
        if (getauxval_ptr) {
            safeAttach(getauxval_ptr, {
                onEnter: function (args) {
                    try { this._auxType = args[0].toInt32(); this._fromSps = _spsFromHere(this.returnAddress); } catch (_e) {}
                },
                onLeave: function (retval) {
                    try {
                        if (this._fromSps) {
                            if (this._auxType === 16) { // AT_HWCAP
                                log('NATIVE', 'getauxval(AT_HWCAP) [SPS] ' + retval.toUInt32().toString(16) + ' -> 0xffff');
                                retval.replace(_arm64Hwcap);
                            } else if (this._auxType === 15 || this._auxType === 26) {
                                log('NATIVE', 'getauxval(' + this._auxType + ') [SPS] = ' + retval.toUInt32().toString(16));
                            }
                        }
                    } catch (_e) {}
                }
            }, 'getauxval');
            log('NATIVE', 'getauxval() hook active (AT_HWCAP SPS-only -> 0xffff ARM64)');
        }
    } catch (e) { log('WARN', 'getauxval hook: ' + e.message); }
}

// ─── Entry ───────────────────────────────────────────────────────────────────
// Native hooks: install immediately (no Java bridge needed)
log('INIT', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
log('INIT', '  Shopee Lite bypass  pid=' + Process.id + '  arch=' + Process.arch);
log('INIT', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
dumpModules();
bypassNativeExists();
hideFrida();
bypassNativeSecurity();

// Java hooks: must wait for Shopee's DEX to be loaded into a class loader.
// After pm clear / fresh install, Zygote forks the process before the APK's
// DEX is loaded. Java.available becomes true (ART is running) but
// Java.use('com.shopee.*') throws ClassNotFoundException because the Shopee
// class loader isn't the active one yet.
// Fix: enumerate all class loaders, wait until one has CommonInfo, then set
// Java.classFactory.loader so all subsequent Java.use() calls hit Shopee DEX.

// ─── OkHttp request capture (no body read → no crash) ────────────────────────
// Hook OkHttpClient.newCall() — fires BEFORE the request is executed.
// Only reads URL/method/headers — never touches request or response body.
// Output: [REQ] {"method":"GET","url":"...","cookie":"..."} — parsed by replay.js.

function hookOkHttpRequests() {
    var CAPTURE_HEADERS = [
        'cookie', 'Cookie', 'authorization', 'Authorization',
        'sz-token', 'shopee-session', 'x-csrftoken', 'X-CSRFToken',
        'if-none-match', 'If-None-Match', 'x-sap-ri', 'x-sap-sec'
    ];
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function (req) {
            try {
                var url    = req.url().toString();
                var method = req.method();
                var hh     = req.headers();
                var out    = { method: method, url: url };
                for (var i = 0; i < CAPTURE_HEADERS.length; i++) {
                    var v = hh.get(CAPTURE_HEADERS[i]);
                    if (v) {
                        var k = CAPTURE_HEADERS[i].toLowerCase();
                        out[k] = v.length > 300 ? v.substring(0, 300) + '...' : v;
                    }
                }
                log('REQ', JSON.stringify(out));
            } catch (_e) {}
            return this.newCall(req);
        };
        log('REQ', 'OkHttpClient.newCall hooked (request capture)');
    } catch (e) {
        log('WARN', 'hookOkHttpRequests: ' + e.message);
    }
}

var _javaRetries = 0;

function doInstallHooks() {
    Java.perform(function () {
        log('INIT', 'Java.perform started (attempt ' + _javaRetries + ')');
        hookOkHttpRequests();   // request-only capture (no body = safe)
        bypassRootBeer();
        bypassCoreRootCheck();
        bypassEmulator();
        bypassTelemetry();
        bypassSPSSdk();
        bypassSSL();
        spoofBuild();
        generateFilteredMaps();  // must run after Java is ready; writes fake_maps_sps

        // Intercept WebView URL loads.
        // Shopee's traffic verification redirects to /verify/traffic/error when device risk is HIGH.
        // Bypass: redirect to the home page instead, which loads as guest content without risk check.
        try {
            const WebView = Java.use('android.webkit.WebView');
            const Activity  = Java.use('android.app.Activity');

            function interceptTrafficError(webView) {
                // Finish the host WebPageActivity_ and relaunch the app's main intent with
                // FLAG_ACTIVITY_CLEAR_TASK so the logged-in home page appears regardless
                // of how LoginActivity was started (HaTe tap vs su am start).
                try {
                    var ctx = webView.getContext();
                    var act = Java.cast(ctx, Activity);
                    log('WEBVIEW', 'traffic/error -> clearing task and relaunching home');
                    try {
                        var pm = ctx.getPackageManager();
                        var launchIntent = pm.getLaunchIntentForPackage('com.shopee.lite.id');
                        if (launchIntent !== null) {
                            launchIntent.setFlags(0x10000000 | 0x20000000); // NEW_TASK | CLEAR_TASK
                            ctx.startActivity(launchIntent);
                            log('WEBVIEW', 'relaunched main with CLEAR_TASK');
                        }
                    } catch (e2) {
                        log('WEBVIEW', 'relaunch failed: ' + e2.message);
                    }
                    act.finish();
                } catch (e) {
                    log('WEBVIEW', 'interceptTrafficError failed: ' + e.message);
                }
            }

            WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
                log('WEBVIEW', 'loadUrl: ' + url);
                if (url && url.indexOf('/verify/traffic/error') !== -1) {
                    if (url.indexOf('is_logged_in=true') !== -1) {
                        if (!_trafficIntercepted) {
                            // First post-login traffic check: CLEAR_TASK relaunch to logged-in home
                            _trafficIntercepted = true;
                            interceptTrafficError(this);
                        } else {
                            // Subsequent fires (from relaunched app): just finish WebPageActivity
                            log('WEBVIEW', 'traffic/error (repeat) -> just finish WebPageActivity');
                            try {
                                var ctx2 = this.getContext();
                                Java.cast(ctx2, Activity).finish();
                            } catch (e2) { log('WEBVIEW', 'repeat finish: ' + e2.message); }
                        }
                        return;
                    }
                    // Pre-login startup check (is_logged_in=false) — let HaTe show; UI automation taps "Log In"
                }
                return this.loadUrl(url);
            };
            WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
                log('WEBVIEW', 'loadUrl+headers: ' + url);
                if (url && url.indexOf('/verify/traffic/error') !== -1) {
                    if (url.indexOf('is_logged_in=true') !== -1) {
                        if (!_trafficIntercepted) {
                            _trafficIntercepted = true;
                            interceptTrafficError(this);
                        } else {
                            log('WEBVIEW', 'traffic/error (repeat) -> just finish');
                            try {
                                var ctx3 = this.getContext();
                                Java.cast(ctx3, Activity).finish();
                            } catch (e3) { log('WEBVIEW', 'repeat finish: ' + e3.message); }
                        }
                        return;
                    }
                }
                return this.loadUrl(url, headers);
            };
        } catch (e) { log('WARN', 'WebView.loadUrl hook: ' + e.message); }

        log('INIT', 'All hooks installed');
    });
}

function checkAndInstall() {
    _javaRetries++;

    if (typeof Java === 'undefined' || !Java.available) {
        if (_javaRetries <= 200) { setTimeout(checkAndInstall, 100); }
        else { log('ERROR', 'Java bridge never became available'); }
        return;
    }

    // Find the class loader that has Shopee's DEX
    var shopeeLoader = null;
    try {
        Java.enumerateClassLoadersSync().forEach(function (loader) {
            if (shopeeLoader) return;
            try {
                loader.loadClass('com.shopee.luban.common.model.common.CommonInfo');
                shopeeLoader = loader;
            } catch (_e) {}
        });
    } catch (_e) {}

    if (!shopeeLoader) {
        if (_javaRetries <= 200) {
            setTimeout(checkAndInstall, 200);
        } else {
            log('WARN', 'Shopee loader not found after ' + _javaRetries + ' retries — using default');
            doInstallHooks();
        }
        return;
    }

    // Pin the correct loader so Java.use() resolves Shopee classes
    Java.classFactory.loader = shopeeLoader;
    log('INIT', 'Shopee class loader pinned (attempt ' + _javaRetries + ')');
    doInstallHooks();
}

setTimeout(checkAndInstall, 0);
