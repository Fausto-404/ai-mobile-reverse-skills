"use strict";

/**
 * 通用 DEX Dumper - 基于 ART 虚拟机底层拦截
 *
 * 原理：
 *   所有壳的最终目标都是把解密后的 DEX 加载进 ART 虚拟机。
 *   ART 加载 DEX 的路径只有两条：
 *     1. DexFile::OpenMemory (libart.so) - 从内存 buffer 加载
 *     2. InMemoryDexClassLoader (Java 层) - Android 8+ 常用
 *
 *   不针对特定壳，在最底层拦截，任何壳都能覆盖。
 *
 * 用法：
 *   frida -U -f com.target.app -l dex_dumper_art.js --no-pause
 *   frida -U --attach-pid 1234 -l dex_dumper_art.js
 *
 * 输出：
 *   /sdcard/dump/classes_0.dex
 *   /sdcard/dump/classes_1.dex
 *   ...
 */

var DUMP_DIR = "/sdcard/dump/";
var counter = 0;
var dumped_sizes = new Set();  // 避免重复 dump 同一个 DEX

// 确保 dump 目录存在
function ensureDumpDir() {
    var File = Java.use("java.io.File");
    var dir = File.$new(DUMP_DIR);
    if (!dir.exists()) {
        dir.mkdirs();
    }
}

// 写入文件
function writeDex(bytes, filename) {
    var path = DUMP_DIR + filename;
    var fos = Java.use("java.io.FileOutputStream").$new(path);
    var ba = Java.array("byte", bytes);
    fos.write(ba);
    fos.close();
    console.log("[dex-dump] written: " + path + " (" + bytes.length + " bytes)");
}

// 检查是否是合法的 DEX magic
function isDexMagic(ptr) {
    try {
        // DEX magic: 64 65 78 0a (dex\n)
        var b0 = ptr.readU8();
        var b1 = ptr.add(1).readU8();
        var b2 = ptr.add(2).readU8();
        return b0 === 0x64 && b1 === 0x65 && b2 === 0x78;
    } catch (e) {
        return false;
    }
}

// 从 DEX header 读取 file_size
function getDexSize(ptr) {
    try {
        // DEX header offset 32: file_size (uint32, little-endian)
        return ptr.add(32).readU32();
    } catch (e) {
        return 0;
    }
}

// dump 一块内存中的 DEX
function dumpFromPointer(ptr, size, tag) {
    try {
        if (!isDexMagic(ptr)) return;

        var fileSize = size > 0 ? size : getDexSize(ptr);
        if (fileSize < 0x70 || fileSize > 50 * 1024 * 1024) return;  // 太小或太大都不合理

        // 去重
        var key = fileSize + "_" + ptr.readU32();
        if (dumped_sizes.has(key)) return;
        dumped_sizes.add(key);

        var bytes = ptr.readByteArray(fileSize);
        writeDex(bytes, "classes_" + counter++ + "_" + tag + ".dex");
    } catch (e) {
        console.log("[dex-dump] dump failed: " + e);
    }
}


// ─── 方法 1：Hook libart.so OpenMemory ────────────────────────────────────────
// 覆盖范围：几乎所有壳（最底层）

function hookArtOpenMemory() {
    var libart = Process.findModuleByName("libart.so");
    if (!libart) {
        console.log("[dex-dump] libart.so not found, skipping native hook");
        return;
    }

    // 不同 Android 版本的符号名不同，尝试多个
    var openMemorySymbols = [
        "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS0_6HeaderEPS9_",
        "_ZN3art7DexFile10OpenMemoryEPKhjRKSsPhPNS_6MemMapEPPS0_",
        "_ZN3art7DexFile10OpenMemoryEPKhjRKSsjPNS_6MemMapEPS0_PS0_",
    ];

    var hooked = false;
    for (var sym of openMemorySymbols) {
        var addr = libart.findExportByName(sym);
        if (!addr) addr = Module.findExportByName("libart.so", sym);
        if (!addr) continue;

        Interceptor.attach(addr, {
            onEnter: function (args) {
                // args[0] = const uint8_t* base (DEX 内容指针)
                // args[1] = size_t size
                this.base = args[0];
                this.size = args[1].toInt32();
            },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                dumpFromPointer(this.base, this.size, "art");
            }
        });

        console.log("[dex-dump] hooked libart OpenMemory @ " + addr);
        hooked = true;
        break;
    }

    if (!hooked) {
        // 符号不匹配时，用模式搜索
        console.log("[dex-dump] OpenMemory symbol not found, trying pattern search...");
        hookArtOpenMemoryByPattern(libart);
    }
}

function hookArtOpenMemoryByPattern(libart) {
    // 在 libart.so 中搜索 DEX magic 相关代码段（不同机型可能不同，这里做简单尝试）
    var exports = libart.enumerateExports();
    for (var exp of exports) {
        if (exp.name.indexOf("OpenDex") !== -1 || exp.name.indexOf("openDex") !== -1) {
            console.log("[dex-dump] found candidate: " + exp.name);
        }
    }
}


// ─── 方法 2：Hook InMemoryDexClassLoader (Android 8+) ─────────────────────────
// 覆盖范围：使用内存加载 DEX 的现代壳（腾讯乐固等）

function hookInMemoryDexClassLoader() {
    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader")
            .implementation = function (buffer, parent) {
                try {
                    // 读取 ByteBuffer 中的 DEX 内容
                    var capacity = buffer.capacity();
                    var bytes = [];
                    var dup = buffer.duplicate();
                    dup.rewind();
                    for (var i = 0; i < capacity; i++) {
                        bytes.push(dup.get());
                    }

                    if (capacity > 0x70) {
                        // 检查 DEX magic
                        if (bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78) {
                            var ba = Java.array("byte", bytes);
                            writeDex(ba, "classes_" + counter++ + "_imdcl.dex");
                        }
                    }
                } catch (e) {
                    console.log("[dex-dump] InMemoryDexClassLoader hook error: " + e);
                }
                return this.$init(buffer, parent);
            };

        console.log("[dex-dump] hooked InMemoryDexClassLoader");
    } catch (e) {
        console.log("[dex-dump] InMemoryDexClassLoader not available: " + e);
    }
}


// ─── 方法 3：Hook DexClassLoader / PathClassLoader ────────────────────────────
// 覆盖范围：从文件路径加载 DEX 的壳（落盘再加载的方案）

function hookDexClassLoader() {
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.overload(
            "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader"
        ).implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log("[dex-dump] DexClassLoader loading: " + dexPath);

            // 如果是文件路径，直接读取文件
            try {
                var File = Java.use("java.io.File");
                var f = File.$new(dexPath);
                if (f.exists() && f.length() > 0x70) {
                    var fis = Java.use("java.io.FileInputStream").$new(f);
                    var size = f.length();
                    var ba = Java.array("byte", new Array(size).fill(0));
                    fis.read(ba);
                    fis.close();

                    // 检查 DEX magic
                    if (ba[0] === 0x64 && ba[1] === 0x65 && ba[2] === 0x78) {
                        var filename = "classes_" + counter++ + "_dcl.dex";
                        writeDex(ba, filename);
                    }
                }
            } catch (e) {
                console.log("[dex-dump] file read error: " + e);
            }

            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
        console.log("[dex-dump] hooked DexClassLoader");
    } catch (e) {
        console.log("[dex-dump] DexClassLoader hook failed: " + e);
    }
}


// ─── 主入口 ───────────────────────────────────────────────────────────────────

Java.perform(function () {
    ensureDumpDir();
    console.log("[dex-dump] DEX dumper started, output: " + DUMP_DIR);

    // 按可靠性顺序安装所有 hook
    hookInMemoryDexClassLoader();   // 最精准，先装
    hookDexClassLoader();           // 文件路径加载的壳
    hookArtOpenMemory();            // 兜底：native 层

    console.log("[dex-dump] all hooks installed");
    console.log("[dex-dump] waiting for DEX loading...");
});
