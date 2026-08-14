"use strict";

const ENABLE_ROOT = __ENABLE_ROOT__;
const ENABLE_EMULATOR = __ENABLE_EMULATOR__;
const ENABLE_PROXY = __ENABLE_PROXY__;
const ENABLE_SSL = __ENABLE_SSL__;
const ENABLE_DEBUG = __ENABLE_DEBUG__;

Java.perform(function () {
  var rootPaths = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/vendor/bin/su",
    "/system/app/Superuser.apk",
    "/system/app/Magisk.apk",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su-backup",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su"
  ];

  var rootPackages = [
    "com.topjohnwu.magisk",
    "com.noshufou.android.su",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su"
  ];

  function log(msg) {
    console.log("[phase1-bypass] " + msg);
  }

  function installRootBypass() {
    try {
      var File = Java.use("java.io.File");
      var fileExists = File.exists.overload();
      File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (rootPaths.indexOf(path) !== -1) {
          log("hide root path: " + path);
          return false;
        }
        return fileExists.call(this);
      };
    } catch (err) {
      log("File.exists hook failed: " + err);
    }

    try {
      var Runtime = Java.use("java.lang.Runtime");
      var execString = Runtime.exec.overload("java.lang.String");
      execString.implementation = function (cmd) {
        var lower = String(cmd).toLowerCase();
        if (
          lower.indexOf("su") !== -1 ||
          lower.indexOf("getprop") !== -1 ||
          lower.indexOf("mount") !== -1 ||
          lower.indexOf("which") !== -1
        ) {
          log("block runtime exec: " + cmd);
          return execString.call(this, "grep");
        }
        return execString.call(this, cmd);
      };
    } catch (err) {
      log("Runtime.exec hook failed: " + err);
    }

    try {
      var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
      var getPackageInfo = ApplicationPackageManager.getPackageInfo.overload("java.lang.String", "int");
      getPackageInfo.implementation = function (pkg, flags) {
        if (rootPackages.indexOf(String(pkg)) !== -1) {
          log("hide root package: " + pkg);
          throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
        }
        return getPackageInfo.call(this, pkg, flags);
      };
    } catch (err) {
      log("getPackageInfo hook failed: " + err);
    }
  }

  function installEmulatorBypass() {
    try {
      var Build = Java.use("android.os.Build");
      Build.FINGERPRINT.value = "google/redfin/redfin:13/TQ3A.230805.001/1234567:user/release-keys";
      Build.MODEL.value = "Pixel 5";
      Build.MANUFACTURER.value = "Google";
      Build.BRAND.value = "google";
      Build.DEVICE.value = "redfin";
      Build.PRODUCT.value = "redfin";
      Build.HARDWARE.value = "redfin";
      log("spoof android.os.Build fields");
    } catch (err) {
      log("Build spoof failed: " + err);
    }

  }

  function installPropertyBypass() {
    try {
      var SystemProperties = Java.use("android.os.SystemProperties");
      var getProperty = SystemProperties.get.overload("java.lang.String");
      getProperty.implementation = function (key) {
        if (ENABLE_ROOT) {
          if (key === "ro.debuggable" || key === "ro.secure") {
            log("spoof root-related property: " + key);
            return key === "ro.debuggable" ? "0" : "1";
          }
          if (key === "ro.build.tags") {
            return "release-keys";
          }
        }
        if (ENABLE_EMULATOR) {
          if (
            key === "ro.kernel.qemu" ||
            key === "ro.hardware" ||
            key === "ro.product.model" ||
            key === "ro.product.manufacturer"
          ) {
            log("spoof emulator property: " + key);
            if (key === "ro.kernel.qemu") return "0";
            if (key === "ro.hardware") return "redfin";
            if (key === "ro.product.model") return "Pixel 5";
            if (key === "ro.product.manufacturer") return "Google";
          }
        }
        return getProperty.call(this, key);
      };
    } catch (err) {
      log("SystemProperties.get hook failed: " + err);
    }
  }

  function installProxyBypass() {
    try {
      var System = Java.use("java.lang.System");
      var getProperty = System.getProperty.overload("java.lang.String");
      getProperty.implementation = function (key) {
        if (
          key === "http.proxyHost" ||
          key === "http.proxyPort" ||
          key === "https.proxyHost" ||
          key === "https.proxyPort"
        ) {
          log("hide proxy property: " + key);
          return null;
        }
        return getProperty.call(this, key);
      };
    } catch (err) {
      log("System.getProperty hook failed: " + err);
    }
  }

  function installDebugBypass() {
    try {
      var Debug = Java.use("android.os.Debug");
      Debug.isDebuggerConnected.implementation = function () {
        log("force Debug.isDebuggerConnected -> false");
        return false;
      };
      Debug.waitForDebugger.implementation = function () {
        log("skip Debug.waitForDebugger");
        return;
      };
    } catch (err) {
      log("android.os.Debug hook skipped: " + err);
    }
  }

  function installSslPinningBypass() {
    try {
      var CertificatePinner = Java.use("okhttp3.CertificatePinner");
      CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
        log("bypass okhttp3.CertificatePinner.check for " + hostname);
        return;
      };
    } catch (err) {
      log("okhttp3 CertificatePinner hook skipped: " + err);
    }

    try {
      var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        log("bypass TrustManagerImpl.verifyChain for " + host);
        return untrustedChain;
      };
    } catch (err) {
      log("TrustManagerImpl hook skipped: " + err);
    }

    try {
      var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
      var HostnameVerifier = Java.registerClass({
        name: "dev.codex.bypass.HostnameVerifier",
        implements: [Java.use("javax.net.ssl.HostnameVerifier")],
        methods: {
          verify: function () {
            return true;
          }
        }
      });
      HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier.$new());
      log("set permissive HostnameVerifier");
    } catch (err) {
      log("HostnameVerifier hook skipped: " + err);
    }

    try {
      var SSLContext = Java.use("javax.net.ssl.SSLContext");
      var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
      var TrustManager = Java.registerClass({
        name: "dev.codex.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () {
            return [];
          }
        }
      });
      var trustManagers = [TrustManager.$new()];
      var sslInit = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
      );
      sslInit.implementation = function (keyManager, trustManager, secureRandom) {
        log("replace SSLContext trust managers");
        return sslInit.call(this, keyManager, trustManagers, secureRandom);
      };
    } catch (err) {
      log("SSLContext hook skipped: " + err);
    }
  }

  if (ENABLE_ROOT) {
    installRootBypass();
  }
  if (ENABLE_EMULATOR) {
    installEmulatorBypass();
  }
  if (ENABLE_ROOT || ENABLE_EMULATOR) {
    installPropertyBypass();
  }
  if (ENABLE_PROXY) {
    installProxyBypass();
  }
  if (ENABLE_SSL) {
    installSslPinningBypass();
  }
  if (ENABLE_DEBUG) {
    installDebugBypass();
  }
  log("template hooks installed");
});
