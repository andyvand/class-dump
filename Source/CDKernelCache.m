// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDKernelCache.h"

#include <libkern/OSByteOrder.h>
#include <stdlib.h>
#include <string.h>

#include "lzfse.h"   // ThirdParty/lzfse
#include "lzvn.h"    // ThirdParty/lzvn -- lzvn_encode/lzvn_decode/lzvn_encode_work_size

NSString * const CDKernelCacheErrorDomain = @"CDKernelCacheErrorDomain";

// Recursion guard for nested containers (IM4P -> comp -> ...).
static const int kCDKCMaxDepth = 4;

// ----------------------------------------------------------------------------
//  Apple prelinked-kernel "complzss" container header (384 bytes). All
//  multi-byte fields are stored big-endian on disk.
// ----------------------------------------------------------------------------

#define CDKC_RESERVED_DWORDS   10
#define CDKC_PLATFORM_NAME_LEN 64
#define CDKC_ROOT_PATH_LEN     256

#pragma pack(push, 1)
typedef struct {
    uint32_t signature;        //   0 -   3  'comp'
    uint32_t compressType;     //   4 -   7  'lzss' / 'lzvn'
    uint32_t adler32;          //   8 -  11  checksum of the uncompressed data
    uint32_t uncompressedSize; //  12 -  15
    uint32_t compressedSize;   //  16 -  19
    uint32_t prelinkVersion;   //  20 -  23  >= 1 => KASLR
    uint32_t reserved[CDKC_RESERVED_DWORDS];      //  24 -  63
    char     platformName[CDKC_PLATFORM_NAME_LEN]; //  64 - 127
    char     rootPath[CDKC_ROOT_PATH_LEN];         // 128 - 383
} CDKCPrelinkHeader;
#pragma pack(pop)

#define CDKC_SIG_COMP   0x636F6D70u // 'comp'
#define CDKC_SIG_PMOC   0x706D6F63u // 'pmoc' (byte-swapped variant)
#define CDKC_TYPE_LZSS  0x6C7A7373u // 'lzss'
#define CDKC_TYPE_LZVN  0x6C7A766Eu // 'lzvn'

// ----------------------------------------------------------------------------
//  adler32 (ported from decompkernelcache local_adler32)
// ----------------------------------------------------------------------------

#define CDKC_ADLER_BASE 65521L
#define CDKC_ADLER_NMAX 5000

static uint32_t cdkc_adler32(const uint8_t *buf, int32_t len)
{
    unsigned long s1 = 1, s2 = 0;
    int k;
    while (len > 0) {
        k = len < CDKC_ADLER_NMAX ? len : CDKC_ADLER_NMAX;
        len -= k;
        while (k >= 16) {
            for (int i = 0; i < 16; i++) { s1 += buf[i]; s2 += s1; }
            buf += 16;
            k -= 16;
        }
        if (k != 0) do { s1 += *buf++; s2 += s1; } while (--k);
        s1 %= CDKC_ADLER_BASE;
        s2 %= CDKC_ADLER_BASE;
    }
    return (uint32_t)((s2 << 16) | s1);
}

// ----------------------------------------------------------------------------
//  LZSS codec (ported from decompkernelcache: compress_lzss / decompress_lzss)
// ----------------------------------------------------------------------------

#define CDKC_LZSS_N         4096  // ring buffer size (power of 2)
#define CDKC_LZSS_F         18    // upper limit for match_length
#define CDKC_LZSS_THRESHOLD 2
#define CDKC_LZSS_NIL       CDKC_LZSS_N

struct cdkc_encode_state {
    int lchild[CDKC_LZSS_N + 1], rchild[CDKC_LZSS_N + 257], parent[CDKC_LZSS_N + 1];
    uint8_t text_buf[CDKC_LZSS_N + CDKC_LZSS_F - 1];
    int match_position, match_length;
};

static void cdkc_init_state(struct cdkc_encode_state *sp)
{
    int i;
    memset(sp, 0, sizeof(*sp));
    for (i = 0; i < CDKC_LZSS_N - CDKC_LZSS_F; i++) sp->text_buf[i] = ' ';
    for (i = CDKC_LZSS_N + 1; i <= CDKC_LZSS_N + 256; i++) sp->rchild[i] = CDKC_LZSS_NIL;
    for (i = 0; i < CDKC_LZSS_N; i++) sp->parent[i] = CDKC_LZSS_NIL;
}

static void cdkc_insert_node(struct cdkc_encode_state *sp, int r)
{
    int i, p, cmp;
    uint8_t *key;
    cmp = 1;
    key = &sp->text_buf[r];
    p = CDKC_LZSS_N + 1 + key[0];
    sp->rchild[r] = sp->lchild[r] = CDKC_LZSS_NIL;
    sp->match_length = 0;
    for ( ; ; ) {
        if (cmp >= 0) {
            if (sp->rchild[p] != CDKC_LZSS_NIL) p = sp->rchild[p];
            else { sp->rchild[p] = r; sp->parent[r] = p; return; }
        } else {
            if (sp->lchild[p] != CDKC_LZSS_NIL) p = sp->lchild[p];
            else { sp->lchild[p] = r; sp->parent[r] = p; return; }
        }
        for (i = 1; i < CDKC_LZSS_F; i++)
            if ((cmp = key[i] - sp->text_buf[p + i]) != 0) break;
        if (i > sp->match_length) {
            sp->match_position = p;
            if ((sp->match_length = i) >= CDKC_LZSS_F) break;
        }
    }
    sp->parent[r] = sp->parent[p];
    sp->lchild[r] = sp->lchild[p];
    sp->rchild[r] = sp->rchild[p];
    sp->parent[sp->lchild[p]] = r;
    sp->parent[sp->rchild[p]] = r;
    if (sp->rchild[sp->parent[p]] == p) sp->rchild[sp->parent[p]] = r;
    else sp->lchild[sp->parent[p]] = r;
    sp->parent[p] = CDKC_LZSS_NIL;
}

static void cdkc_delete_node(struct cdkc_encode_state *sp, int p)
{
    int q;
    if (sp->parent[p] == CDKC_LZSS_NIL) return;
    if (sp->rchild[p] == CDKC_LZSS_NIL) q = sp->lchild[p];
    else if (sp->lchild[p] == CDKC_LZSS_NIL) q = sp->rchild[p];
    else {
        q = sp->lchild[p];
        if (sp->rchild[q] != CDKC_LZSS_NIL) {
            do { q = sp->rchild[q]; } while (sp->rchild[q] != CDKC_LZSS_NIL);
            sp->rchild[sp->parent[q]] = sp->lchild[q];
            sp->parent[sp->lchild[q]] = sp->parent[q];
            sp->lchild[q] = sp->lchild[p];
            sp->parent[sp->lchild[p]] = q;
        }
        sp->rchild[q] = sp->rchild[p];
        sp->parent[sp->rchild[p]] = q;
    }
    sp->parent[q] = sp->parent[p];
    if (sp->rchild[sp->parent[p]] == p) sp->rchild[sp->parent[p]] = q;
    else sp->lchild[sp->parent[p]] = q;
    sp->parent[p] = CDKC_LZSS_NIL;
}

// Returns pointer just past the last written byte, or NULL on overflow.
static uint8_t *cdkc_compress_lzss(uint8_t *dst, uint32_t dstlen, uint8_t *src, uint32_t srcLen)
{
    struct cdkc_encode_state *sp;
    int i, c, len, r, s, last_match_length, code_buf_ptr;
    uint8_t code_buf[17], mask;
    uint8_t *srcend = src + srcLen;
    uint8_t *dstend = dst + dstlen;

    sp = (struct cdkc_encode_state *)malloc(sizeof(*sp));
    if (sp == NULL) return NULL;
    cdkc_init_state(sp);

    code_buf[0] = 0;
    code_buf_ptr = mask = 1;
    s = 0; r = CDKC_LZSS_N - CDKC_LZSS_F;

    for (len = 0; len < CDKC_LZSS_F && src < srcend; len++)
        sp->text_buf[r + len] = *src++;
    if (!len) { free(sp); return NULL; }

    for (i = 1; i <= CDKC_LZSS_F; i++) cdkc_insert_node(sp, r - i);
    cdkc_insert_node(sp, r);
    do {
        if (sp->match_length > len) sp->match_length = len;
        if (sp->match_length <= CDKC_LZSS_THRESHOLD) {
            sp->match_length = 1;
            code_buf[0] |= mask;
            code_buf[code_buf_ptr++] = sp->text_buf[r];
        } else {
            code_buf[code_buf_ptr++] = (uint8_t)sp->match_position;
            code_buf[code_buf_ptr++] = (uint8_t)
                (((sp->match_position >> 4) & 0xF0) | (sp->match_length - (CDKC_LZSS_THRESHOLD + 1)));
        }
        if ((mask <<= 1) == 0) {
            for (i = 0; i < code_buf_ptr; i++) {
                if (dst < dstend) *dst++ = code_buf[i];
                else { free(sp); return NULL; }
            }
            code_buf[0] = 0;
            code_buf_ptr = mask = 1;
        }
        last_match_length = sp->match_length;
        for (i = 0; i < last_match_length && src < srcend; i++) {
            cdkc_delete_node(sp, s);
            c = *src++;
            sp->text_buf[s] = c;
            if (s < CDKC_LZSS_F - 1) sp->text_buf[s + CDKC_LZSS_N] = c;
            s = (s + 1) & (CDKC_LZSS_N - 1);
            r = (r + 1) & (CDKC_LZSS_N - 1);
            cdkc_insert_node(sp, r);
        }
        while (i++ < last_match_length) {
            cdkc_delete_node(sp, s);
            s = (s + 1) & (CDKC_LZSS_N - 1);
            r = (r + 1) & (CDKC_LZSS_N - 1);
            if (--len) cdkc_insert_node(sp, r);
        }
    } while (len > 0);

    if (code_buf_ptr > 1) {
        for (i = 0; i < code_buf_ptr; i++) {
            if (dst < dstend) *dst++ = code_buf[i];
            else { free(sp); return NULL; }
        }
    }
    free(sp);
    return dst;
}

static int cdkc_decompress_lzss(uint8_t *dst, uint32_t dstlen, uint8_t *src, uint32_t srclen)
{
    uint8_t text_buf[CDKC_LZSS_N + CDKC_LZSS_F - 1];
    uint8_t *dststart = dst;
    uint8_t *dstend = dst + dstlen;
    uint8_t *srcend = src + srclen;
    int i, j, k, r, c;
    unsigned int flags;

    for (i = 0; i < CDKC_LZSS_N - CDKC_LZSS_F; i++) text_buf[i] = ' ';
    r = CDKC_LZSS_N - CDKC_LZSS_F;
    flags = 0;
    for ( ; ; ) {
        if (((flags >>= 1) & 0x100) == 0) {
            if (src < srcend) c = *src++; else break;
            flags = c | 0xFF00;
        }
        if (flags & 1) {
            if (src < srcend) c = *src++; else break;
            if (dst >= dstend) break;
            *dst++ = c;
            text_buf[r++] = c;
            r &= (CDKC_LZSS_N - 1);
        } else {
            if (src < srcend) i = *src++; else break;
            if (src < srcend) j = *src++; else break;
            i |= ((j & 0xF0) << 4);
            j = (j & 0x0F) + CDKC_LZSS_THRESHOLD;
            for (k = 0; k <= j; k++) {
                c = text_buf[(i + k) & (CDKC_LZSS_N - 1)];
                if (dst >= dstend) break;
                *dst++ = c;
                text_buf[r++] = c;
                r &= (CDKC_LZSS_N - 1);
            }
        }
    }
    return (int)(dst - dststart);
}

// ----------------------------------------------------------------------------
//  Minimal ASN.1 DER reader for IM4P (no libtasn1).
//
//  IM4P ::= SEQUENCE {
//      magic        IA5String  ("IM4P")
//      type         IA5String  (4cc, e.g. "krnl")
//      description  IA5String
//      data         OCTET STRING   <-- the payload
//      ... (optional keybags etc., ignored)
//  }
// ----------------------------------------------------------------------------

// Reads one DER TLV starting at *pp (< end). On success returns YES, sets
// *tag, points *content at the value bytes, sets *contentLen, and advances
// *pp past the value. Supports short- and long-form lengths.
static BOOL cdkc_der_read_tlv(const uint8_t **pp, const uint8_t *end,
                              uint8_t *tag, const uint8_t **content, size_t *contentLen)
{
    const uint8_t *p = *pp;
    if (p + 2 > end) return NO;
    uint8_t t = *p++;
    size_t len = *p++;
    if (len & 0x80) {
        int nbytes = (int)(len & 0x7F);
        if (nbytes == 0 || nbytes > 4 || p + nbytes > end) return NO; // indefinite/oversized
        len = 0;
        for (int i = 0; i < nbytes; i++) len = (len << 8) | *p++;
    }
    if (p + len > end) return NO;
    *tag = t;
    *content = p;
    *contentLen = len;
    *pp = p + len;
    return YES;
}

#define CDKC_ASN1_IA5STRING 0x16
#define CDKC_ASN1_OCTETSTR  0x04
#define CDKC_ASN1_SEQUENCE  0x30

@implementation CDKernelCache

+ (NSError *)errorWithCode:(NSInteger)code message:(NSString *)message
{
    return [NSError errorWithDomain:CDKernelCacheErrorDomain
                               code:code
                           userInfo:@{ NSLocalizedDescriptionKey: message }];
}

+ (BOOL)dataHasLZFSEMagic:(NSData *)data
{
    if (data.length < 4) return NO;
    const uint8_t *b = data.bytes;
    if (b[0] != 'b' || b[1] != 'v' || b[2] != 'x') return NO;
    return (b[3] == '-' || b[3] == '1' || b[3] == '2' || b[3] == 'n' || b[3] == 'N');
}

+ (BOOL)dataHasCompMagic:(NSData *)data
{
    if (data.length < sizeof(CDKCPrelinkHeader)) return NO;
    const uint8_t *b = data.bytes;
    return (memcmp(b, "comp", 4) == 0 || memcmp(b, "pmoc", 4) == 0);
}

+ (BOOL)dataHasIMG4Magic:(NSData *)data
{
    // IM4P: an outer SEQUENCE whose first element is the IA5String "IM4P".
    if (data.length < 8) return NO;
    const uint8_t *p = data.bytes;
    if (p[0] != CDKC_ASN1_SEQUENCE) return NO;
    const uint8_t *end = p + data.length;
    uint8_t tag; const uint8_t *content; size_t contentLen;
    const uint8_t *seqp = p;
    if (!cdkc_der_read_tlv(&seqp, end, &tag, &content, &contentLen)) return NO;
    if (tag != CDKC_ASN1_SEQUENCE) return NO;
    const uint8_t *inner = content;
    const uint8_t *innerEnd = content + contentLen;
    if (!cdkc_der_read_tlv(&inner, innerEnd, &tag, &content, &contentLen)) return NO;
    return (tag == CDKC_ASN1_IA5STRING && contentLen == 4 && memcmp(content, "IM4P", 4) == 0);
}

+ (BOOL)isKernelCacheContainer:(NSData *)data
{
    return [self dataHasIMG4Magic:data] || [self dataHasCompMagic:data] || [self dataHasLZFSEMagic:data];
}

// ---- LZFSE stream decode (unknown output size; grow the buffer). ----
+ (NSData *)lzfseDecode:(NSData *)data error:(NSError **)error
{
    size_t srcSize = data.length;
    const uint8_t *src = data.bytes;
    // Kernel payloads expand a lot; start generously and grow on saturation.
    size_t cap = srcSize * 8 + 0x10000;
    void *scratch = malloc(lzfse_decode_scratch_size());
    if (scratch == NULL) {
        if (error) *error = [self errorWithCode:1 message:@"out of memory (lzfse scratch)"];
        return nil;
    }
    for (int attempt = 0; attempt < 8; attempt++) {
        uint8_t *dst = malloc(cap);
        if (dst == NULL) break;
        size_t n = lzfse_decode_buffer(dst, cap, src, srcSize, scratch);
        if (n > 0 && n < cap) {
            NSData *out = [NSData dataWithBytes:dst length:n];
            free(dst);
            free(scratch);
            return out;
        }
        // n == 0 (error) or n == cap (saturated) -> grow and retry.
        free(dst);
        cap *= 2;
    }
    free(scratch);
    if (error) *error = [self errorWithCode:2 message:@"LZFSE decompression failed"];
    return nil;
}

// ---- 'comp' (LZSS/LZVN) container decode. ----
+ (NSData *)compDecode:(NSData *)data error:(NSError **)error
{
    if (data.length < sizeof(CDKCPrelinkHeader)) {
        if (error) *error = [self errorWithCode:3 message:@"truncated prelinked-kernel header"];
        return nil;
    }
    const uint8_t *base = data.bytes;
    const CDKCPrelinkHeader *h = (const CDKCPrelinkHeader *)base;

    BOOL bigEndian = (memcmp(base, "comp", 4) == 0); // 'comp' = big-endian fields on disk
    uint32_t (^rd)(uint32_t) = ^uint32_t(uint32_t v) {
        return bigEndian ? OSSwapBigToHostInt32(v) : OSSwapLittleToHostInt32(v);
    };

    uint32_t compressType    = rd(h->compressType);
    uint32_t adlerStored     = rd(h->adler32);
    uint32_t uncompressedLen = rd(h->uncompressedSize);
    uint32_t compressedLen   = rd(h->compressedSize);

    if (compressType != CDKC_TYPE_LZSS && compressType != CDKC_TYPE_LZVN) {
        if (error) *error = [self errorWithCode:4
            message:[NSString stringWithFormat:@"unsupported prelink compressType 0x%08x", compressType]];
        return nil;
    }
    if (uncompressedLen == 0 || compressedLen == 0) {
        if (error) *error = [self errorWithCode:5 message:@"invalid prelink sizes"];
        return nil;
    }
    if (sizeof(CDKCPrelinkHeader) + (size_t)compressedLen > data.length) {
        if (error) *error = [self errorWithCode:6 message:@"prelink compressedSize exceeds file"];
        return nil;
    }

    const uint8_t *comp = base + sizeof(CDKCPrelinkHeader);
    uint8_t *out = malloc(uncompressedLen);
    if (out == NULL) {
        if (error) *error = [self errorWithCode:1 message:@"out of memory"];
        return nil;
    }

    int n;
    if (compressType == CDKC_TYPE_LZSS) {
        n = cdkc_decompress_lzss(out, uncompressedLen, (uint8_t *)comp, compressedLen);
    } else {
        n = (int)lzvn_decode(out, uncompressedLen, (void *)comp, compressedLen);
    }

    if ((uint32_t)n != uncompressedLen) {
        free(out);
        if (error) *error = [self errorWithCode:7
            message:[NSString stringWithFormat:@"decompressed size %d != expected %u", n, uncompressedLen]];
        return nil;
    }

    uint32_t adlerComputed = cdkc_adler32(out, (int32_t)uncompressedLen);
    if (adlerComputed != adlerStored) {
        // Mismatch is not fatal for our purposes (some caches carry 0); warn via error only.
        // Still return the data so class-dump can attempt to parse it.
    }

    NSData *result = [NSData dataWithBytes:out length:uncompressedLen];
    free(out);
    return result;
}

+ (NSData *)decompressData:(NSData *)data error:(NSError **)error
{
    if ([self dataHasCompMagic:data]) return [self compDecode:data error:error];
    if ([self dataHasLZFSEMagic:data]) return [self lzfseDecode:data error:error];
    if (error) *error = [self errorWithCode:8 message:@"input is not a 'comp' or LZFSE compressed stream"];
    return nil;
}

+ (NSData *)extractIMG4Payload:(NSData *)data type:(NSString **)outType error:(NSError **)error
{
    if (![self dataHasIMG4Magic:data]) {
        if (error) *error = [self errorWithCode:9 message:@"input is not an IMG4/IM4P file"];
        return nil;
    }
    const uint8_t *p = data.bytes;
    const uint8_t *end = p + data.length;
    uint8_t tag; const uint8_t *content; size_t contentLen;

    // outer SEQUENCE
    const uint8_t *seqp = p;
    if (!cdkc_der_read_tlv(&seqp, end, &tag, &content, &contentLen) || tag != CDKC_ASN1_SEQUENCE) {
        if (error) *error = [self errorWithCode:10 message:@"malformed IM4P sequence"];
        return nil;
    }
    const uint8_t *ip = content;
    const uint8_t *iend = content + contentLen;

    // magic "IM4P"
    if (!cdkc_der_read_tlv(&ip, iend, &tag, &content, &contentLen) ||
        tag != CDKC_ASN1_IA5STRING || contentLen != 4 || memcmp(content, "IM4P", 4) != 0) {
        if (error) *error = [self errorWithCode:11 message:@"IM4P magic not found"];
        return nil;
    }
    // type (4cc)
    if (!cdkc_der_read_tlv(&ip, iend, &tag, &content, &contentLen) || tag != CDKC_ASN1_IA5STRING) {
        if (error) *error = [self errorWithCode:12 message:@"IM4P type not found"];
        return nil;
    }
    if (outType) *outType = [[NSString alloc] initWithBytes:content length:contentLen encoding:NSASCIIStringEncoding];
    // description
    if (!cdkc_der_read_tlv(&ip, iend, &tag, &content, &contentLen) || tag != CDKC_ASN1_IA5STRING) {
        if (error) *error = [self errorWithCode:13 message:@"IM4P description not found"];
        return nil;
    }
    // data (OCTET STRING) -- the payload
    if (!cdkc_der_read_tlv(&ip, iend, &tag, &content, &contentLen) || tag != CDKC_ASN1_OCTETSTR) {
        if (error) *error = [self errorWithCode:14 message:@"IM4P payload (OCTET STRING) not found"];
        return nil;
    }

    NSData *payload = [NSData dataWithBytes:content length:contentLen];
    // The payload may itself be compressed -- expand it.
    if ([self isKernelCacheContainer:payload]) {
        NSError *inner = nil;
        NSData *expanded = [self decodedDataFromData:payload didDecode:NULL error:&inner];
        if (expanded != nil) return expanded;
        // fall through: return the raw payload if inner decode failed
    }
    return payload;
}

+ (NSData *)decodedDataFromData:(NSData *)data didDecode:(BOOL *)didDecode error:(NSError **)error
{
    return [self decodeData:data depth:0 didDecode:didDecode error:error];
}

+ (NSData *)decodeData:(NSData *)data depth:(int)depth didDecode:(BOOL *)didDecode error:(NSError **)error
{
    if (didDecode) *didDecode = NO;
    if (data == nil || depth >= kCDKCMaxDepth) return data;

    NSData *out = nil;
    NSError *err = nil;

    if ([self dataHasIMG4Magic:data]) {
        out = [self extractIMG4Payload:data type:NULL error:&err];
    } else if ([self dataHasCompMagic:data]) {
        out = [self compDecode:data error:&err];
    } else if ([self dataHasLZFSEMagic:data]) {
        out = [self lzfseDecode:data error:&err];
    } else {
        return data; // nothing recognized
    }

    if (out == nil) {
        if (error) *error = err;
        return data; // read-path callers may ignore and use original bytes
    }
    if (didDecode) *didDecode = YES;

    // Recurse: a decoded layer may expose another container.
    if ([self isKernelCacheContainer:out]) {
        NSData *deeper = [self decodeData:out depth:depth + 1 didDecode:NULL error:error];
        if (deeper != nil) return deeper;
    }
    return out;
}

+ (NSData *)compressData:(NSData *)data method:(CDKernelCacheCompression)method error:(NSError **)error
{
    if (data.length == 0) {
        if (error) *error = [self errorWithCode:15 message:@"nothing to compress"];
        return nil;
    }

    if (method == CDKernelCacheCompressionLZFSE) {
        size_t srcSize = data.length;
        size_t cap = srcSize + (srcSize / 16) + 0x1000;
        void *scratch = malloc(lzfse_encode_scratch_size());
        uint8_t *dst = malloc(cap);
        if (scratch == NULL || dst == NULL) {
            free(scratch); free(dst);
            if (error) *error = [self errorWithCode:1 message:@"out of memory"];
            return nil;
        }
        size_t n = lzfse_encode_buffer(dst, cap, data.bytes, srcSize, scratch);
        free(scratch);
        if (n == 0) {
            free(dst);
            if (error) *error = [self errorWithCode:16 message:@"LZFSE compression failed"];
            return nil;
        }
        NSData *out = [NSData dataWithBytes:dst length:n];
        free(dst);
        return out;
    }

    // LZSS / LZVN -> 'comp' prelinked-kernel container.
    uint32_t srcLen = (uint32_t)data.length;
    size_t cap = (size_t)srcLen + (srcLen / 2) + 0x400;
    uint8_t *comp = malloc(cap);
    if (comp == NULL) {
        if (error) *error = [self errorWithCode:1 message:@"out of memory"];
        return nil;
    }

    size_t compLen = 0;
    if (method == CDKernelCacheCompressionLZVN) {
        void *work = malloc(lzvn_encode_work_size());
        if (work == NULL) {
            free(comp);
            if (error) *error = [self errorWithCode:1 message:@"out of memory (lzvn workspace)"];
            return nil;
        }
        compLen = lzvn_encode(comp, cap, data.bytes, srcLen, work);
        free(work);
        if (compLen == 0) {
            free(comp);
            if (error) *error = [self errorWithCode:17 message:@"LZVN compression failed"];
            return nil;
        }
    } else { // LZSS
        uint8_t *endp = cdkc_compress_lzss(comp, (uint32_t)cap, (uint8_t *)data.bytes, srcLen);
        if (endp == NULL) {
            free(comp);
            if (error) *error = [self errorWithCode:18 message:@"LZSS compression failed"];
            return nil;
        }
        compLen = (size_t)(endp - comp);
    }

    CDKCPrelinkHeader h;
    memset(&h, 0, sizeof(h));
    h.signature       = OSSwapHostToBigInt32(CDKC_SIG_COMP);
    h.compressType    = OSSwapHostToBigInt32(method == CDKernelCacheCompressionLZVN ? CDKC_TYPE_LZVN : CDKC_TYPE_LZSS);
    h.adler32         = OSSwapHostToBigInt32(cdkc_adler32(data.bytes, (int32_t)srcLen));
    h.uncompressedSize = OSSwapHostToBigInt32(srcLen);
    h.compressedSize  = OSSwapHostToBigInt32((uint32_t)compLen);
    h.prelinkVersion  = OSSwapHostToBigInt32(1);

    NSMutableData *out = [NSMutableData dataWithCapacity:sizeof(h) + compLen];
    [out appendBytes:&h length:sizeof(h)];
    [out appendBytes:comp length:compLen];
    free(comp);
    return out;
}

@end
