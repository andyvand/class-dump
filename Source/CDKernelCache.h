// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.
//
//  Kernelcache container support: transparently unwraps the formats that
//  Apple ships kernelcaches in before class-dump's Mach-O parser sees them,
//  and provides the inverse operations as explicit commands.
//
//  Handled containers:
//    * IMG4 / IM4P  -- ASN.1 DER wrapper (e.g. img4 kernelcaches). Parsed with
//                      a small self-contained DER reader (no libtasn1). The
//                      unwrapped payload is fed back through the decoder so a
//                      compressed inner payload is also expanded.
//    * "complzss"   -- Apple's prelinked-kernel compression header (signature
//                      'comp'), payload compressed with LZSS or LZVN.
//    * bare LZFSE   -- raw LZFSE stream ('bvx' magic).
//
//  Compression direction (LZSS / LZVN / LZFSE) is provided for re-packing a
//  decompressed kernel back into a 'comp' container or an LZFSE stream.
//
//  Ports the codec/container logic from AnV's decompkernelcache and the IMG4
//  unwrap from Peter Nguyen's kernelcache_decryptor, backed by the vendored
//  lzfse + lzvn sources under ThirdParty/.

#import <Foundation/Foundation.h>

extern NSString * const CDKernelCacheErrorDomain;

typedef NS_ENUM(NSInteger, CDKernelCacheCompression) {
    CDKernelCacheCompressionLZSS,
    CDKernelCacheCompressionLZVN,
    CDKernelCacheCompressionLZFSE,
};

@interface CDKernelCache : NSObject

// YES if `data` begins with a recognized container magic (IMG4/IM4P, 'comp'
// prelinked-kernel header, or an LZFSE 'bvx' stream).
+ (BOOL)isKernelCacheContainer:(NSData *)data;

// Transparent decode used on the read path. If `data` is a recognized
// container it is decoded -- recursively, so an IM4P wrapping an LZFSE payload
// is fully expanded -- and the inner Mach-O/fat data is returned. If nothing
// is recognized `data` is returned unchanged. On a decode failure the original
// `data` is returned and *error (if non-NULL) is set; callers on the read path
// may safely ignore the error and proceed with the original bytes.
// `didDecode` (if non-NULL) is set to YES only when a container was unwrapped.
+ (NSData *)decodedDataFromData:(NSData *)data
                      didDecode:(BOOL *)didDecode
                          error:(NSError **)error;

// Explicit one-shot operations (used by the --decompress / --decrypt /
// --compress command-line flags). These fail (return nil + *error) when the
// input is not the expected kind of container.

// Decompress a 'comp' (LZSS/LZVN) or bare LZFSE stream to raw bytes.
+ (NSData *)decompressData:(NSData *)data error:(NSError **)error;

// Unwrap an IMG4/IM4P payload. The 4-character payload type (e.g. "krnl") is
// returned via `outType` when non-NULL. The unwrapped payload is itself run
// through the decompressor, so the result is the fully expanded inner data.
+ (NSData *)extractIMG4Payload:(NSData *)data
                          type:(NSString **)outType
                         error:(NSError **)error;

// Re-compress raw bytes. LZSS/LZVN produce a 'comp' prelinked-kernel container
// (384-byte header + payload); LZFSE produces a bare LZFSE stream.
+ (NSData *)compressData:(NSData *)data
                  method:(CDKernelCacheCompression)method
                   error:(NSError **)error;

@end
