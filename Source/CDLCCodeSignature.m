// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCCodeSignature.h"

#import "CDMachOFile.h"

// Apple's CodeDirectory blob layout. The kernel's <kern/cs_blobs.h> defines
// these but isn't part of the public SDK; redefining the public bits here.

#define CSMAGIC_REQUIREMENT             0xfade0c00
#define CSMAGIC_REQUIREMENTS            0xfade0c01
#define CSMAGIC_CODEDIRECTORY           0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE      0xfade0cc0
#define CSMAGIC_EMBEDDED_SIGNATURE_OLD  0xfade0b02
#define CSMAGIC_EMBEDDED_ENTITLEMENTS   0xfade7171
#define CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xfade7172
#define CSMAGIC_DETACHED_SIGNATURE      0xfade0cc1
#define CSMAGIC_BLOBWRAPPER             0xfade0b01

#define CSSLOT_CODEDIRECTORY            0
#define CSSLOT_INFOSLOT                 1
#define CSSLOT_REQUIREMENTS             2
#define CSSLOT_RESOURCEDIR              3
#define CSSLOT_APPLICATION              4
#define CSSLOT_ENTITLEMENTS             5
#define CSSLOT_DER_ENTITLEMENTS         7
#define CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000
#define CSSLOT_SIGNATURESLOT            0x10000

struct cs_blob_index {
    uint32_t type;
    uint32_t offset;
};

struct cs_super_blob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    struct cs_blob_index index[];
};

struct cs_code_directory {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t  hashSize;
    uint8_t  hashType;
    uint8_t  platform;
    uint8_t  pageSize;
    uint32_t spare2;
    /* version >= 0x20100 */
    uint32_t scatterOffset;
    /* version >= 0x20200 */
    uint32_t teamOffset;
    /* version >= 0x20300 */
    uint32_t spare3;
    uint64_t codeLimit64;
    /* version >= 0x20400 */
    uint64_t execSegBase;
    uint64_t execSegLimit;
    uint64_t execSegFlags;
};

static uint32_t cs_swap32(uint32_t v) { return CFSwapInt32BigToHost(v); }
static uint64_t cs_swap64(uint64_t v) { return CFSwapInt64BigToHost(v); }

static NSString *HashTypeName(uint8_t h)
{
    switch (h) {
        case 1: return @"SHA1";
        case 2: return @"SHA256";
        case 3: return @"SHA256_TRUNCATED";
        case 4: return @"SHA384";
        case 5: return @"SHA512";
        default: return [NSString stringWithFormat:@"unknown(%u)", h];
    }
}

static NSString *MagicName(uint32_t m)
{
    switch (m) {
        case CSMAGIC_REQUIREMENT:                return @"REQUIREMENT";
        case CSMAGIC_REQUIREMENTS:               return @"REQUIREMENTS";
        case CSMAGIC_CODEDIRECTORY:              return @"CODEDIRECTORY";
        case CSMAGIC_EMBEDDED_SIGNATURE:         return @"EMBEDDED_SIGNATURE";
        case CSMAGIC_EMBEDDED_SIGNATURE_OLD:     return @"EMBEDDED_SIGNATURE_OLD";
        case CSMAGIC_EMBEDDED_ENTITLEMENTS:      return @"EMBEDDED_ENTITLEMENTS";
        case CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:  return @"EMBEDDED_DER_ENTITLEMENTS";
        case CSMAGIC_DETACHED_SIGNATURE:         return @"DETACHED_SIGNATURE";
        case CSMAGIC_BLOBWRAPPER:                return @"BLOBWRAPPER";
        default: return [NSString stringWithFormat:@"0x%08x", m];
    }
}

static NSString *SlotName(uint32_t t)
{
    switch (t) {
        case CSSLOT_CODEDIRECTORY:    return @"CodeDirectory";
        case CSSLOT_INFOSLOT:         return @"Info";
        case CSSLOT_REQUIREMENTS:     return @"Requirements";
        case CSSLOT_RESOURCEDIR:      return @"ResourceDir";
        case CSSLOT_APPLICATION:      return @"Application";
        case CSSLOT_ENTITLEMENTS:     return @"Entitlements";
        case CSSLOT_DER_ENTITLEMENTS: return @"DER-Entitlements";
        case CSSLOT_SIGNATURESLOT:    return @"Signature";
        default:
            if (t >= CSSLOT_ALTERNATE_CODEDIRECTORIES && t < CSSLOT_SIGNATURESLOT) {
                return [NSString stringWithFormat:@"AltCodeDirectory %u", t - CSSLOT_ALTERNATE_CODEDIRECTORIES];
            }
            return [NSString stringWithFormat:@"slot 0x%x", t];
    }
}

@implementation CDLCCodeSignature
{
    BOOL _parsed;
    NSString *_signingIdentifier;
    NSString *_teamIdentifier;
    uint8_t _hashType;
    uint32_t _codeDirectoryFlags;
}

- (NSString *)signingIdentifier { [self ensureParsed]; return _signingIdentifier; }
- (NSString *)teamIdentifier { [self ensureParsed]; return _teamIdentifier; }
- (uint8_t)hashType { [self ensureParsed]; return _hashType; }
- (uint32_t)codeDirectoryFlags { [self ensureParsed]; return _codeDirectoryFlags; }

- (void)ensureParsed
{
    if (_parsed) return;
    _parsed = YES;

    NSData *blob = [self linkeditData];
    NSUInteger total = [blob length];
    if (total < sizeof(struct cs_super_blob)) return;

    const uint8_t *base = (const uint8_t *)[blob bytes];
    struct cs_super_blob sb;
    memcpy(&sb, base, sizeof(sb));
    uint32_t magic = cs_swap32(sb.magic);
    uint32_t count = cs_swap32(sb.count);
    if (magic != CSMAGIC_EMBEDDED_SIGNATURE) return;
    if (sizeof(struct cs_super_blob) + (NSUInteger)count * sizeof(struct cs_blob_index) > total) return;

    for (uint32_t i = 0; i < count; i++) {
        struct cs_blob_index idx;
        memcpy(&idx, base + sizeof(struct cs_super_blob) + i * sizeof(struct cs_blob_index), sizeof(idx));
        uint32_t slotType = cs_swap32(idx.type);
        uint32_t offset = cs_swap32(idx.offset);
        if (slotType != CSSLOT_CODEDIRECTORY || offset + sizeof(struct cs_code_directory) > total) continue;

        struct cs_code_directory cd;
        memcpy(&cd, base + offset, sizeof(cd));
        uint32_t cdMagic = cs_swap32(cd.magic);
        if (cdMagic != CSMAGIC_CODEDIRECTORY) continue;

        uint32_t version = cs_swap32(cd.version);
        _codeDirectoryFlags = cs_swap32(cd.flags);
        _hashType = cd.hashType;

        uint32_t identOffset = cs_swap32(cd.identOffset);
        if (identOffset && offset + identOffset < total) {
            _signingIdentifier = [NSString stringWithUTF8String:(const char *)(base + offset + identOffset)] ?: @"";
        }
        if (version >= 0x20200) {
            uint32_t teamOffset = cs_swap32(cd.teamOffset);
            if (teamOffset && offset + teamOffset < total) {
                _teamIdentifier = [NSString stringWithUTF8String:(const char *)(base + offset + teamOffset)] ?: @"";
            }
        }
        return;
    }
}

- (void)appendToString:(NSMutableString *)resultString verbose:(BOOL)isVerbose;
{
    [super appendToString:resultString verbose:isVerbose];

    NSData *blob = [self linkeditData];
    NSUInteger total = [blob length];
    if (total < sizeof(struct cs_super_blob)) {
        [resultString appendString:@"  (no code signature payload)\n"];
        return;
    }
    const uint8_t *base = (const uint8_t *)[blob bytes];

    struct cs_super_blob sb;
    memcpy(&sb, base, sizeof(sb));
    uint32_t magic = cs_swap32(sb.magic);
    uint32_t length = cs_swap32(sb.length);
    uint32_t count = cs_swap32(sb.count);

    [resultString appendFormat:@"     magic 0x%08x (%@)\n", magic, MagicName(magic)];
    [resultString appendFormat:@"    length %u\n", length];
    [resultString appendFormat:@"     count %u\n", count];

    if (magic != CSMAGIC_EMBEDDED_SIGNATURE) return;

    for (uint32_t i = 0; i < count; i++) {
        NSUInteger idxOff = sizeof(struct cs_super_blob) + i * sizeof(struct cs_blob_index);
        if (idxOff + sizeof(struct cs_blob_index) > total) break;
        struct cs_blob_index idx;
        memcpy(&idx, base + idxOff, sizeof(idx));
        uint32_t slotType = cs_swap32(idx.type);
        uint32_t offset = cs_swap32(idx.offset);
        [resultString appendFormat:@"    slot[%u] %@ at 0x%x\n", i, SlotName(slotType), offset];

        if (slotType == CSSLOT_CODEDIRECTORY && offset + sizeof(struct cs_code_directory) <= total) {
            struct cs_code_directory cd;
            memcpy(&cd, base + offset, sizeof(cd));
            uint32_t cdMagic = cs_swap32(cd.magic);
            if (cdMagic != CSMAGIC_CODEDIRECTORY) continue;
            uint32_t version = cs_swap32(cd.version);
            [resultString appendFormat:@"      CodeDirectory:\n"];
            [resultString appendFormat:@"        version    0x%x\n", version];
            [resultString appendFormat:@"        flags      0x%x\n", cs_swap32(cd.flags)];
            [resultString appendFormat:@"        hashType   %u (%@)\n", cd.hashType, HashTypeName(cd.hashType)];
            [resultString appendFormat:@"        hashSize   %u\n", cd.hashSize];
            [resultString appendFormat:@"        platform   %u\n", cd.platform];
            [resultString appendFormat:@"        pageSize   %u (%u)\n", cd.pageSize, cd.pageSize ? (1u << cd.pageSize) : 0];
            [resultString appendFormat:@"        codeLimit  %u\n", cs_swap32(cd.codeLimit)];
            [resultString appendFormat:@"        nSpecial   %u\n", cs_swap32(cd.nSpecialSlots)];
            [resultString appendFormat:@"        nCode      %u\n", cs_swap32(cd.nCodeSlots)];

            uint32_t identOffset = cs_swap32(cd.identOffset);
            if (identOffset && offset + identOffset < total) {
                [resultString appendFormat:@"        ident      %s\n", (const char *)(base + offset + identOffset)];
            }
            if (version >= 0x20200) {
                uint32_t teamOffset = cs_swap32(cd.teamOffset);
                if (teamOffset && offset + teamOffset < total) {
                    [resultString appendFormat:@"        team       %s\n", (const char *)(base + offset + teamOffset)];
                }
            }
            if (version >= 0x20400) {
                [resultString appendFormat:@"        execBase   0x%llx\n", cs_swap64(cd.execSegBase)];
                [resultString appendFormat:@"        execLimit  0x%llx\n", cs_swap64(cd.execSegLimit)];
                [resultString appendFormat:@"        execFlags  0x%llx\n", cs_swap64(cd.execSegFlags)];
            }
        } else if (slotType == CSSLOT_ENTITLEMENTS && offset + 8 <= total) {
            uint32_t blobMagic;
            uint32_t blobLen;
            memcpy(&blobMagic, base + offset, 4);
            memcpy(&blobLen, base + offset + 4, 4);
            blobMagic = cs_swap32(blobMagic);
            blobLen = cs_swap32(blobLen);
            if (blobMagic == CSMAGIC_EMBEDDED_ENTITLEMENTS && offset + blobLen <= total && blobLen >= 8) {
                NSUInteger payloadLen = blobLen - 8;
                NSString *plist = [[NSString alloc] initWithBytes:base + offset + 8 length:payloadLen encoding:NSUTF8StringEncoding];
                [resultString appendString:@"      entitlements (xml):\n"];
                for (NSString *line in [plist componentsSeparatedByString:@"\n"]) {
                    [resultString appendFormat:@"        %@\n", line];
                }
            }
        }
    }
}

@end
