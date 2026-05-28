class-dump
==========

`class-dump` is a command-line utility for examining the Objective-C
segment of Mach-O files. It generates declarations for the classes,
categories and protocols — the same information provided by `otool -ov`,
but presented as normal Objective-C declarations.

This repository is a heavily extended fork of Steve Nygard's original
`class-dump` (https://github.com/nygard/class-dump). In addition to the
original Objective-C dumping it adds:

* **dyld_shared_cache** inspection, extraction, and bulk class-dump
  (`--dsc-info`, `--dsc-list-images`, `--dsc-extract`, `--dsc-class-dump`).
* **Kernelcache fileset** listing, extraction, and per-kext class-dump /
  C++ / Swift header dumping
  (`--list-fileset`, `--extract-fileset`, `--fileset-class-dump`).
* **Kernelcache (de)compression / decryption**: unwrap `comp`
  (LZSS/LZVN) and bare LZFSE kernels, unwrap IMG4/IM4P containers, and
  re-compress raw kernels (`--decompress`, `--decrypt`, `--compress`).
* **C++** class header generation from Itanium-mangled symbols (`--cpp`).
* **Swift** type/extension dumping via `libswiftCore` `swift_demangle`
  (`--swift`).
* **Mach-O editing**: change `LC_ID_DYLIB`, rewrite `LC_LOAD_DYLIB` /
  `LC_RPATH`, add/delete rpaths, strip code signatures, thin universal
  binaries (`--id`, `--change`, `--rpath`, `--add-rpath`, `--delete-rpath`,
  `--strip-codesig`, `--thin`).
* **Mach-O introspection** helpers (`--show-mach-header`,
  `--show-load-commands`, `--lipo-info`, `--list-arches`).
* **Cross-binary type resolution** via a shared type pool fed by
  `--scan-dir` / `--auto-scan`.
* **Ghidra-backed decompilation** of every dumped binary into pseudo-C
  (`--decompile`), with language-shaped variants that demangle symbol
  names and rewrite the body into the target language:
  `--decompile-swift` groups Swift-mangled functions under their owning
  type as `class Module.Type { func ... }`, `--decompile-objc` groups
  Objective-C method IMPs into `@implementation` blocks with
  `objc_msgSend(recv,"sel",args)` rewritten as `[recv sel:args]`, and
  `--decompile-cpp` applies Itanium return/parameter types before
  decompiling so signatures carry real types rather than `undefined`.

Source for this fork:

    https://github.com/andyvand/class-dump

Original project page:

    http://stevenygard.com/projects/class-dump


Usage
-----

    class-dump [options] <mach-o-file>

### Classic options

      -a             show instance variable offsets
      -A             show implementation addresses
      --arch <arch>  pick an architecture from a fat binary
                     (ppc, ppc64, i386, x86_64, armv6, armv7, armv7s, arm64)
      -C <regex>     only display classes matching regular expression
      -f <str>       find string in method name
      -H             generate per-class header files (use -o for output dir)
      -I             sort classes, categories, and protocols by inheritance
      -o <dir>       output directory used for -H
      -r             recursively expand frameworks and fixed VM shared libraries
      -s             sort classes and categories by name
      -S             sort methods by name
      -t             suppress header in output, for testing
      --hide <sect>  hide a section of the output (`structures`,
                     `protocols`, or `all` for both)
      --version      print the class-dump version and exit
      --list-arches  list the arches in the file, then exit
      --sdk-ios <v>  iOS SDK version to resolve frameworks against
      --sdk-mac <v>  macOS SDK version to resolve frameworks against
      --sdk-root <path>  full SDK root path

### Mach-O introspection

      --show-mach-header     dump the Mach-O header and exit
      --show-load-commands   dump the Mach-O load commands and exit
      --lipo-info            list architectures in a fat archive and exit

### Mach-O editing (writes a new binary to `--out`)

      --thin <arch>          extract a single architecture
      --out <file>           output path for write/extract operations
      --id <name>            set LC_ID_DYLIB (must fit in original space)
      --change OLD,NEW       rewrite LC_LOAD_DYLIB / LC_REEXPORT_DYLIB / etc.
      --rpath OLD,NEW        rewrite LC_RPATH
      --add-rpath <path>     add LC_RPATH (uses load command region slack)
      --delete-rpath <path>  delete LC_RPATH
      --strip-codesig        remove LC_CODE_SIGNATURE and trailing signature

### dyld_shared_cache

      --dsc-info             print dyld_shared_cache header info
      --dsc-list-images      list all images in a dyld_shared_cache
      --dsc-extract DIR      extract every dylib from a cache to DIR
                             (uses Apple's dsc_extractor.bundle from Xcode)
      --with-cache FILE      use a cache to resolve selectors / type strings
                             when dumping cache-extracted dylibs
      --dsc-class-dump CACHE_OR_DIR --out OUTDIR
                             extract every dylib (or use already-extracted
                             dir) and class-dump each into OUTDIR/<install>/
      --dsc-image-timeout SEC  per-image wall-clock timeout (default 180s)
      --dsc-skip-existing    skip images whose output subdir is non-empty
      --dsc-in-process       run all images in-process (legacy; less robust)

By default `--dsc-class-dump` spawns an isolated child process per image
so a hang or crash in one image (e.g. WebKit) cannot stall the whole
batch. The parent prints a heartbeat every 15s naming the stuck worker's
pid so you can `sample` it.

### Kernelcache

      --list-fileset                       list LC_FILESET_ENTRY entries
      --extract-fileset NAME --out FILE    extract a fileset entry (raw slice)
      --fileset-class-dump --out OUTDIR    walk every LC_FILESET_ENTRY and dump
                                           per-kext headers into OUTDIR/<id>/.
                                           Without --cpp/--swift this emits the
                                           usual Objective-C header bundle;
                                           with --cpp it emits C++ headers
                                           reconstructed from each kext's
                                           LC_SYMTAB (kexts are mostly C++);
                                           with --swift it emits Swift
                                           extensions.

### Kernelcache (de)compression and decryption

      --decompress --out FILE
                             decompress a 'comp' (LZSS/LZVN) prelinked
                             kernel or a bare LZFSE stream and write the
                             raw bytes to FILE
      --decrypt --out FILE   unwrap an IMG4/IM4P kernelcache (and expand
                             its inner LZFSE/LZSS payload) and write the
                             result to FILE
      --compress lzss|lzvn|lzfse --out FILE
                             re-compress a raw kernel into a 'comp'
                             container (lzss/lzvn) or a bare LZFSE stream
                             and write it to FILE

Compressed or encrypted kernelcaches are also unwrapped automatically on
the normal class-dump and `--list-fileset` / `--extract-fileset` /
`--fileset-class-dump` paths, so you usually only need `--decompress` /
`--decrypt` when you want the raw bytes on disk.

### C++ and Swift

      --cpp     dump C++ classes from LC_SYMTAB Itanium-mangled symbols
      --swift   dump Swift extensions/types (mangled symbols demangled via
                libswiftCore)

These can be combined with `--dsc-class-dump` and `--dsc-extract` to
additionally produce `<install-path>.cpp_h/` and `<install-path>.swift_h/`
subdirectories alongside the Objective-C headers.

### Cross-binary type resolution

      --scan-dir DIR    recursively pool type encodings from Mach-O files
                        under DIR so struct/union/protocol references in
                        the primary binary resolve to fuller definitions
                        (repeatable; pool images themselves are not emitted)
      --auto-scan       also scan the input's containing directory

### Decompilation (requires Ghidra)

      --decompile          run Ghidra headless over each dumped binary and
                           write a pseudo-C .c file next to the .h output
      --decompile-swift    emit a .swift file containing only Swift-mangled
                           functions, grouped under their owning type as
                           `class Module.Type { func name(params) -> T { ... } }`.
                           Bodies are heuristically rewritten from Ghidra
                           pseudo-C into Swift-ish syntax (swift_retain /
                           swift_release etc. dropped, `->` rewritten to
                           `.`, C casts collapsed, witness tables / type
                           metadata accessors skipped).
      --decompile-objc     emit a .m file containing only Objective-C method
                           IMPs (`-[Class sel]` / `+[Class sel]`), grouped
                           by class as `@implementation Class ... @end`.
                           Bodies are heuristically rewritten:
                           `objc_msgSend(recv,"sel",args)` becomes
                           `[recv sel:args]` (iterated so nested sends
                           collapse), `objc_storeStrong(&dst,src)` becomes
                           `dst = src`, ARC retain/release/autorelease are
                           dropped, `_OBJC_CLASS_$_Foo` becomes
                           `[Foo class]`, `objc_alloc_init(_OBJC_CLASS_$_X)`
                           becomes `[[X alloc] init]`.
      --decompile-cpp      emit a .cpp file containing only Itanium-mangled
                           C++ functions, with names demangled and Itanium
                           return/parameter types applied before decompiling
                           (so signatures carry real types rather than
                           Ghidra's `undefined`).

The `--decompile-swift` and `--decompile-objc` output is a *Swift-shaped*
and *ObjC-shaped sketch* derived from the decompile — meant for reading
and grepping, not for feeding back to a compiler. Ghidra is found via
`$GHIDRA_HOME`, or by searching `/Applications/ghidra*`, `~/ghidra*`,
`/opt/ghidra*`, and `/opt/homebrew/Caskroom/ghidra/*`. The four
`--decompile*` flags can be combined; each hooks into `--dsc-class-dump`,
`--dsc-extract`, `--extract-fileset`, and `--fileset-class-dump` as well
as plain single-file dumps.


Examples
--------

Class-dump AppKit:

    class-dump /System/Library/Frameworks/AppKit.framework

Class-dump UIKit and everything it links against against a specific SDK:

    class-dump /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/UIKit.framework -r --sdk-ios 17.0

Inspect a dyld_shared_cache:

    class-dump --dsc-info     /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
    class-dump --dsc-list-images /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

Extract every dylib from a cache:

    class-dump --dsc-extract /tmp/cache-extracted /path/to/dyld_shared_cache_arm64e

Class-dump every image in a cache, including C++ and Swift, with a
60 second per-image timeout, decompiling each binary to pseudo-C plus
Swift-shaped `.swift`, ObjC-shaped `.m`, and demangled `.cpp` output:

    class-dump --dsc-class-dump /path/to/dyld_shared_cache_arm64e \
               --out /tmp/dump --cpp --swift \
               --dsc-image-timeout 60 \
               --decompile --decompile-cpp --decompile-swift --decompile-objc

List and extract a kernelcache fileset entry:

    class-dump --list-fileset kernelcache.release.iphone16
    class-dump --extract-fileset com.apple.driver.AppleH16 \
               kernelcache.release.iphone16 --out AppleH16.macho

C++-dump every kext in a fileset kernelcache (one directory per kext):

    class-dump --fileset-class-dump --cpp \
               --out /tmp/kcache-cpp kernelcache.release.iphone16

Decrypt an IMG4 kernelcache, then re-compress the raw kernel as LZFSE:

    class-dump --decrypt kernelcache.release.iphone16 --out kernel.raw
    class-dump --compress lzfse kernel.raw --out kernel.lzfse

Rewrite a dylib's install name and add an rpath:

    class-dump MyLib.dylib --id @rpath/MyLib.dylib --add-rpath @loader_path/../Frameworks --out MyLib.dylib.new

Strip a code signature and extract the arm64 slice of a fat binary:

    class-dump --strip-codesig fat.dylib --out fat.unsigned.dylib
    class-dump --thin arm64 fat.unsigned.dylib --out arm64.dylib


License
-------

This file is part of class-dump, a utility for examining the
Objective-C segment of Mach-O files.
Copyright (C) 1997-2019 Steve Nygard.
Fork additions Copyright (C) Andy Vandijck and contributors.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


Contact
-------

Original author: Steve Nygard (`nygard at gmail.com`).

This fork is maintained at https://github.com/andyvand/class-dump.
