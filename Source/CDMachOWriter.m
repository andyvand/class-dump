// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDMachOWriter.h"

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/arch.h>
#include <libkern/OSByteOrder.h>

NSString * const CDMachOWriterErrorDomain = @"CDMachOWriterErrorDomain";

#define LCAlignment(is64) ((is64) ? 8 : 4)

static NSError *MakeError(CDMachOWriterError code, NSString *desc)
{
    return [NSError errorWithDomain:CDMachOWriterErrorDomain code:code
                           userInfo:@{ NSLocalizedDescriptionKey: desc ?: @"" }];
}

@implementation CDMachOWriter
{
    NSMutableData *_data;
    NSUInteger _sliceOffset;
    NSUInteger _sliceLength;
    BOOL _is64Bit;
    BOOL _isLittleEndian; // file's byte order vs host
}

- (instancetype)initWithData:(NSMutableData *)data sliceOffset:(NSUInteger)offset sliceLength:(NSUInteger)length
{
    self = [super init];
    if (!self) return nil;
    if (offset + 4 > [data length]) return nil;

    _data = data;
    _sliceOffset = offset;
    _sliceLength = length;

    uint32_t magic;
    memcpy(&magic, (const uint8_t *)[data bytes] + offset, 4);

    switch (magic) {
        case MH_MAGIC:    _is64Bit = NO;  _isLittleEndian = (NSHostByteOrder() == NS_LittleEndian); break;
        case MH_CIGAM:    _is64Bit = NO;  _isLittleEndian = (NSHostByteOrder() == NS_BigEndian); break;
        case MH_MAGIC_64: _is64Bit = YES; _isLittleEndian = (NSHostByteOrder() == NS_LittleEndian); break;
        case MH_CIGAM_64: _is64Bit = YES; _isLittleEndian = (NSHostByteOrder() == NS_BigEndian); break;
        default: return nil;
    }

    return self;
}

- (NSUInteger)sliceOffset    { return _sliceOffset; }
- (NSUInteger)sliceLength    { return _sliceLength; }
- (BOOL)is64Bit              { return _is64Bit; }
- (BOOL)isLittleEndian       { return _isLittleEndian; }

#pragma mark - Byte helpers

- (uint32_t)readU32At:(NSUInteger)abs
{
    uint32_t v;
    memcpy(&v, (const uint8_t *)[_data bytes] + abs, sizeof(v));
    return v; // file order; we treat the file as host-byte-order in practice (almost always little-endian)
}

- (void)writeU32:(uint32_t)v at:(NSUInteger)abs
{
    uint8_t *bytes = (uint8_t *)[_data mutableBytes];
    memcpy(bytes + abs, &v, sizeof(v));
}

- (NSUInteger)mhSize { return _is64Bit ? sizeof(struct mach_header_64) : sizeof(struct mach_header); }

- (uint32_t)ncmds
{
    NSUInteger off = _sliceOffset + offsetof(struct mach_header, ncmds);
    return [self readU32At:off];
}

- (uint32_t)sizeofcmds
{
    NSUInteger off = _sliceOffset + offsetof(struct mach_header, sizeofcmds);
    return [self readU32At:off];
}

- (void)setNcmds:(uint32_t)n sizeofcmds:(uint32_t)s
{
    [self writeU32:n at:_sliceOffset + offsetof(struct mach_header, ncmds)];
    [self writeU32:s at:_sliceOffset + offsetof(struct mach_header, sizeofcmds)];
}

#pragma mark - LC iteration

// Calls block(cmd, cmdsize, lcAbsOffset, stop). Block may read but not mutate
// while iterating; if a mutation is made, abort and re-iterate.
- (void)forEachLoadCommand:(void(^)(uint32_t cmd, uint32_t cmdsize, NSUInteger lcAbs, BOOL *stop))block
{
    NSUInteger lcAbs = _sliceOffset + [self mhSize];
    uint32_t ncmds = [self ncmds];
    BOOL stop = NO;
    for (uint32_t i = 0; i < ncmds && !stop; i++) {
        uint32_t cmd     = [self readU32At:lcAbs];
        uint32_t cmdsize = [self readU32At:lcAbs + 4];
        if (cmdsize == 0) break;
        block(cmd, cmdsize, lcAbs, &stop);
        lcAbs += cmdsize;
    }
}

- (NSUInteger)lcRegionEnd
{
    return _sliceOffset + [self mhSize] + [self sizeofcmds];
}

#pragma mark - install_name_tool style edits

- (BOOL)replaceLCStringAt:(NSUInteger)lcAbs cmdsize:(uint32_t)cmdsize stringOffsetField:(NSUInteger)stringOffsetFieldAbs newPath:(NSString *)newPath error:(NSError **)error
{
    uint32_t stringOff = [self readU32At:stringOffsetFieldAbs];
    if (stringOff < 8 || stringOff > cmdsize) {
        if (error) *error = MakeError(CDMachOWriterErrorBadFile, @"invalid lc_str offset");
        return NO;
    }
    NSUInteger pathStart = lcAbs + stringOff;
    NSUInteger pathCapacity = cmdsize - stringOff;
    NSData *newBytes = [newPath dataUsingEncoding:NSUTF8StringEncoding];
    if ([newBytes length] + 1 > pathCapacity) {
        if (error) *error = MakeError(CDMachOWriterErrorPathTooLong,
            [NSString stringWithFormat:@"new path needs %lu bytes (incl. NUL), available %lu",
                                        (unsigned long)([newBytes length] + 1), (unsigned long)pathCapacity]);
        return NO;
    }
    uint8_t *bytes = (uint8_t *)[_data mutableBytes];
    memset(bytes + pathStart, 0, pathCapacity);
    memcpy(bytes + pathStart, [newBytes bytes], [newBytes length]);
    return YES;
}

- (NSString *)stringAtLcAbs:(NSUInteger)lcAbs cmdsize:(uint32_t)cmdsize stringOffsetField:(NSUInteger)stringOffsetFieldAbs
{
    uint32_t stringOff = [self readU32At:stringOffsetFieldAbs];
    if (stringOff < 8 || stringOff > cmdsize) return nil;
    NSUInteger pathStart = lcAbs + stringOff;
    NSUInteger maxLen = cmdsize - stringOff;
    const char *p = (const char *)[_data bytes] + pathStart;
    size_t actual = strnlen(p, maxLen);
    return [[NSString alloc] initWithBytes:p length:actual encoding:NSUTF8StringEncoding];
}

- (BOOL)setDylibID:(NSString *)newPath error:(NSError **)error
{
    __block BOOL found = NO;
    __block BOOL ok = NO;
    __block NSError *innerErr = nil;
    [self forEachLoadCommand:^(uint32_t cmd, uint32_t cmdsize, NSUInteger lcAbs, BOOL *stop) {
        if (cmd != LC_ID_DYLIB) return;
        found = YES;
        // dylib_command: cmd, cmdsize, dylib { name.offset, timestamp, current_version, compatibility_version }
        // path string offset is at dylib_command offset 8 (just after cmd/cmdsize)
        ok = [self replaceLCStringAt:lcAbs cmdsize:cmdsize stringOffsetField:lcAbs + 8 newPath:newPath error:&innerErr];
        *stop = YES;
    }];
    if (!found) {
        if (error) *error = MakeError(CDMachOWriterErrorPathNotFound, @"no LC_ID_DYLIB in this image");
        return NO;
    }
    if (!ok && error) *error = innerErr;
    return ok;
}

- (BOOL)changeDylibLikeFromOldPath:(NSString *)oldPath toNewPath:(NSString *)newPath cmds:(NSSet<NSNumber *> *)cmds error:(NSError **)error
{
    __block BOOL changed = NO;
    __block BOOL ok = YES;
    __block NSError *innerErr = nil;
    [self forEachLoadCommand:^(uint32_t cmd, uint32_t cmdsize, NSUInteger lcAbs, BOOL *stop) {
        if (![cmds containsObject:@(cmd)]) return;
        NSString *cur = [self stringAtLcAbs:lcAbs cmdsize:cmdsize stringOffsetField:lcAbs + 8];
        if (![cur isEqualToString:oldPath]) return;
        if (![self replaceLCStringAt:lcAbs cmdsize:cmdsize stringOffsetField:lcAbs + 8 newPath:newPath error:&innerErr]) {
            ok = NO;
            *stop = YES;
            return;
        }
        changed = YES;
    }];
    if (!ok) { if (error) *error = innerErr; return NO; }
    if (!changed) {
        if (error) *error = MakeError(CDMachOWriterErrorPathNotFound,
            [NSString stringWithFormat:@"path '%@' not found in load commands", oldPath]);
        return NO;
    }
    return YES;
}

- (BOOL)changeInstallName:(NSString *)oldPath to:(NSString *)newPath error:(NSError **)error
{
    NSSet<NSNumber *> *cmds = [NSSet setWithObjects:
        @(LC_LOAD_DYLIB), @(LC_LOAD_WEAK_DYLIB), @(LC_REEXPORT_DYLIB),
        @(LC_LAZY_LOAD_DYLIB), @(LC_LOAD_UPWARD_DYLIB), nil];
    return [self changeDylibLikeFromOldPath:oldPath toNewPath:newPath cmds:cmds error:error];
}

- (BOOL)changeRPath:(NSString *)oldPath to:(NSString *)newPath error:(NSError **)error
{
    __block BOOL changed = NO;
    __block BOOL ok = YES;
    __block NSError *innerErr = nil;
    [self forEachLoadCommand:^(uint32_t cmd, uint32_t cmdsize, NSUInteger lcAbs, BOOL *stop) {
        if (cmd != LC_RPATH) return;
        // rpath_command: cmd, cmdsize, lc_str path
        NSString *cur = [self stringAtLcAbs:lcAbs cmdsize:cmdsize stringOffsetField:lcAbs + 8];
        if (![cur isEqualToString:oldPath]) return;
        if (![self replaceLCStringAt:lcAbs cmdsize:cmdsize stringOffsetField:lcAbs + 8 newPath:newPath error:&innerErr]) {
            ok = NO;
            *stop = YES;
            return;
        }
        changed = YES;
    }];
    if (!ok) { if (error) *error = innerErr; return NO; }
    if (!changed) {
        if (error) *error = MakeError(CDMachOWriterErrorPathNotFound,
            [NSString stringWithFormat:@"rpath '%@' not found", oldPath]);
        return NO;
    }
    return YES;
}

#pragma mark - rpath add/delete

- (NSUInteger)slackBytesAfterLCs
{
    // Slack = bytes from end of LC region up to start of first segment file data.
    // For simplicity: minimum file offset of any segment > 0 with filesize > 0.
    NSUInteger lcEnd = [self lcRegionEnd];
    NSUInteger minFileoff = NSUIntegerMax;
    BOOL is64 = _is64Bit;
    NSUInteger lcAbs = _sliceOffset + [self mhSize];
    uint32_t ncmds = [self ncmds];
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd     = [self readU32At:lcAbs];
        uint32_t cmdsize = [self readU32At:lcAbs + 4];
        if (cmd == LC_SEGMENT && !is64) {
            // segment_command.fileoff at offset 32 (cmd 4 + cmdsize 4 + segname 16 + vmaddr 4 + vmsize 4)
            NSUInteger off = lcAbs + 4 + 4 + 16 + 4 + 4;
            uint32_t fo = [self readU32At:off];
            uint32_t fs = [self readU32At:off + 4];
            if (fs > 0 && fo > 0 && fo < minFileoff) minFileoff = fo;
        } else if (cmd == LC_SEGMENT_64 && is64) {
            // segment_command_64: cmd 4, cmdsize 4, segname 16, vmaddr 8, vmsize 8 -> fileoff at +40
            NSUInteger off = lcAbs + 4 + 4 + 16 + 8 + 8;
            uint64_t fo, fs;
            memcpy(&fo, (const uint8_t *)[_data bytes] + off,     8);
            memcpy(&fs, (const uint8_t *)[_data bytes] + off + 8, 8);
            if (fs > 0 && fo > 0 && fo < minFileoff) minFileoff = (NSUInteger)fo;
        }
        lcAbs += cmdsize;
    }
    if (minFileoff == NSUIntegerMax) return 0;
    NSUInteger absMinFileoff = _sliceOffset + minFileoff;
    if (absMinFileoff <= lcEnd) return 0;
    return absMinFileoff - lcEnd;
}

- (BOOL)addRPath:(NSString *)path error:(NSError **)error
{
    // Check duplicate
    __block BOOL exists = NO;
    [self forEachLoadCommand:^(uint32_t cmd, uint32_t cmdsize, NSUInteger lcAbs, BOOL *stop) {
        if (cmd != LC_RPATH) return;
        NSString *cur = [self stringAtLcAbs:lcAbs cmdsize:cmdsize stringOffsetField:lcAbs + 8];
        if ([cur isEqualToString:path]) { exists = YES; *stop = YES; }
    }];
    if (exists) {
        if (error) *error = MakeError(CDMachOWriterErrorRPathExists,
            [NSString stringWithFormat:@"rpath '%@' already present", path]);
        return NO;
    }

    NSData *pathBytes = [path dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger headerSize = 4 + 4 + 4; // cmd, cmdsize, path.offset
    NSUInteger needed = headerSize + [pathBytes length] + 1;
    NSUInteger align = LCAlignment(_is64Bit);
    needed = (needed + align - 1) & ~(align - 1);

    NSUInteger slack = [self slackBytesAfterLCs];
    if (needed > slack) {
        if (error) *error = MakeError(CDMachOWriterErrorNoSpace,
            [NSString stringWithFormat:@"need %lu bytes for new LC_RPATH; only %lu free in load command region",
                (unsigned long)needed, (unsigned long)slack]);
        return NO;
    }

    NSUInteger writeAt = [self lcRegionEnd];
    uint8_t *bytes = (uint8_t *)[_data mutableBytes];
    memset(bytes + writeAt, 0, needed);
    [self writeU32:LC_RPATH at:writeAt];
    [self writeU32:(uint32_t)needed at:writeAt + 4];
    [self writeU32:(uint32_t)headerSize at:writeAt + 8]; // path.offset = 12 (just after lc_str field)
    memcpy(bytes + writeAt + headerSize, [pathBytes bytes], [pathBytes length]);

    [self setNcmds:[self ncmds] + 1 sizeofcmds:[self sizeofcmds] + (uint32_t)needed];
    return YES;
}

- (BOOL)deleteRPath:(NSString *)path error:(NSError **)error
{
    __block NSUInteger foundAbs = NSUIntegerMax;
    __block uint32_t foundSize = 0;
    [self forEachLoadCommand:^(uint32_t cmd, uint32_t cmdsize, NSUInteger lcAbs, BOOL *stop) {
        if (cmd != LC_RPATH) return;
        NSString *cur = [self stringAtLcAbs:lcAbs cmdsize:cmdsize stringOffsetField:lcAbs + 8];
        if ([cur isEqualToString:path]) {
            foundAbs = lcAbs;
            foundSize = cmdsize;
            *stop = YES;
        }
    }];
    if (foundAbs == NSUIntegerMax) {
        if (error) *error = MakeError(CDMachOWriterErrorPathNotFound,
            [NSString stringWithFormat:@"rpath '%@' not found", path]);
        return NO;
    }
    NSUInteger lcEnd = [self lcRegionEnd];
    NSUInteger trailingBytes = lcEnd - (foundAbs + foundSize);
    uint8_t *bytes = (uint8_t *)[_data mutableBytes];
    if (trailingBytes > 0) memmove(bytes + foundAbs, bytes + foundAbs + foundSize, trailingBytes);
    memset(bytes + lcEnd - foundSize, 0, foundSize);
    [self setNcmds:[self ncmds] - 1 sizeofcmds:[self sizeofcmds] - foundSize];
    return YES;
}

#pragma mark - Strip code signature

- (BOOL)stripCodeSignature:(NSError **)error
{
    __block NSUInteger lcAbs = NSUIntegerMax;
    __block uint32_t cmdsize = 0;
    __block uint32_t dataoff = 0;
    __block uint32_t datasize = 0;
    [self forEachLoadCommand:^(uint32_t cmd, uint32_t cs, NSUInteger absOff, BOOL *stop) {
        if (cmd != LC_CODE_SIGNATURE) return;
        lcAbs = absOff;
        cmdsize = cs;
        dataoff = [self readU32At:absOff + 8];
        datasize = [self readU32At:absOff + 12];
        *stop = YES;
    }];
    if (lcAbs == NSUIntegerMax) {
        if (error) *error = MakeError(CDMachOWriterErrorNoCodeSignature, @"no LC_CODE_SIGNATURE present");
        return NO;
    }

    // Remove the LC entry: shift trailing LCs up, zero freed bytes.
    NSUInteger lcEnd = [self lcRegionEnd];
    NSUInteger trailingBytes = lcEnd - (lcAbs + cmdsize);
    uint8_t *bytes = (uint8_t *)[_data mutableBytes];
    if (trailingBytes > 0) memmove(bytes + lcAbs, bytes + lcAbs + cmdsize, trailingBytes);
    memset(bytes + lcEnd - cmdsize, 0, cmdsize);
    [self setNcmds:[self ncmds] - 1 sizeofcmds:[self sizeofcmds] - cmdsize];

    // Truncate the slice at the start of code signature data.
    if (dataoff > 0 && datasize > 0) {
        NSUInteger absDataStart = _sliceOffset + dataoff;
        NSUInteger absDataEnd   = absDataStart + datasize;
        if (absDataEnd <= _sliceOffset + _sliceLength) {
            // Shrink __LINKEDIT segment by datasize.
            [self shrinkLinkeditBy:datasize];
            // Remove the trailing data.
            [_data replaceBytesInRange:NSMakeRange(absDataStart, datasize) withBytes:NULL length:0];
            _sliceLength -= datasize;
        }
    }
    return YES;
}

- (void)shrinkLinkeditBy:(uint32_t)delta
{
    BOOL is64 = _is64Bit;
    NSUInteger lcAbs = _sliceOffset + [self mhSize];
    uint32_t ncmds = [self ncmds];
    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd     = [self readU32At:lcAbs];
        uint32_t cmdsize = [self readU32At:lcAbs + 4];
        BOOL is32Seg = (cmd == LC_SEGMENT && !is64);
        BOOL is64Seg = (cmd == LC_SEGMENT_64 && is64);
        if (is32Seg || is64Seg) {
            // segname at lcAbs + 8
            char segname[17] = {0};
            memcpy(segname, (const uint8_t *)[_data bytes] + lcAbs + 8, 16);
            if (strcmp(segname, "__LINKEDIT") == 0) {
                if (is64Seg) {
                    // vmsize at +24, filesize at +40
                    NSUInteger vmsizeOff   = lcAbs + 8 + 16 + 8;
                    NSUInteger filesizeOff = lcAbs + 8 + 16 + 8 + 8 + 8;
                    uint64_t vmsize, filesize;
                    memcpy(&vmsize,   (const uint8_t *)[_data bytes] + vmsizeOff,   8);
                    memcpy(&filesize, (const uint8_t *)[_data bytes] + filesizeOff, 8);
                    if (vmsize > delta)   vmsize   -= delta;
                    if (filesize > delta) filesize -= delta;
                    uint8_t *bytes = (uint8_t *)[_data mutableBytes];
                    memcpy(bytes + vmsizeOff,   &vmsize,   8);
                    memcpy(bytes + filesizeOff, &filesize, 8);
                } else {
                    // segment_command (32-bit): vmsize at +28, filesize at +36
                    NSUInteger vmsizeOff   = lcAbs + 8 + 16 + 4;
                    NSUInteger filesizeOff = lcAbs + 8 + 16 + 4 + 4 + 4;
                    uint32_t vmsize   = [self readU32At:vmsizeOff];
                    uint32_t filesize = [self readU32At:filesizeOff];
                    if (vmsize > delta)   vmsize   -= delta;
                    if (filesize > delta) filesize -= delta;
                    [self writeU32:vmsize   at:vmsizeOff];
                    [self writeU32:filesize at:filesizeOff];
                }
                return;
            }
        }
        lcAbs += cmdsize;
    }
}

@end

#pragma mark - Fat helpers

@implementation CDMachOWriter (Fat)

+ (NSArray<NSString *> *)architecturesInData:(NSData *)data
{
    if ([data length] < 8) return @[];
    uint32_t magic;
    memcpy(&magic, [data bytes], 4);
    BOOL isFat = (magic == FAT_MAGIC || magic == FAT_CIGAM);
    BOOL isFat64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
    BOOL swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
    if (isFat || isFat64) {
        NSMutableArray *out = [NSMutableArray array];
        uint32_t nfat;
        memcpy(&nfat, (const uint8_t *)[data bytes] + 4, 4);
        if (swap) nfat = OSSwapInt32(nfat);
        NSUInteger entrySize = isFat64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
        NSUInteger off = sizeof(struct fat_header);
        for (uint32_t i = 0; i < nfat; i++) {
            if (off + entrySize > [data length]) break;
            cpu_type_t ct;     memcpy(&ct, (const uint8_t *)[data bytes] + off,     4);
            cpu_subtype_t cs;  memcpy(&cs, (const uint8_t *)[data bytes] + off + 4, 4);
            if (swap) { ct = OSSwapInt32(ct); cs = OSSwapInt32(cs); }
            const NXArchInfo *ai = NXGetArchInfoFromCpuType(ct, cs);
            [out addObject:ai ? [NSString stringWithUTF8String:ai->name]
                              : [NSString stringWithFormat:@"0x%x:0x%x", ct, cs]];
            off += entrySize;
        }
        return out;
    }
    if (magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == MH_CIGAM || magic == MH_CIGAM_64) {
        cpu_type_t ct;
        cpu_subtype_t cs;
        memcpy(&ct, (const uint8_t *)[data bytes] + 4, 4);
        memcpy(&cs, (const uint8_t *)[data bytes] + 8, 4);
        if (magic == MH_CIGAM || magic == MH_CIGAM_64) { ct = OSSwapInt32(ct); cs = OSSwapInt32(cs); }
        const NXArchInfo *ai = NXGetArchInfoFromCpuType(ct, cs);
        return @[ai ? [NSString stringWithUTF8String:ai->name]
                    : [NSString stringWithFormat:@"0x%x:0x%x", ct, cs]];
    }
    return @[];
}

+ (NSData *)thinSliceForArch:(NSString *)archName fromFatData:(NSData *)data error:(NSError **)error
{
    if ([data length] < 8) {
        if (error) *error = MakeError(CDMachOWriterErrorBadFile, @"file too small");
        return nil;
    }
    uint32_t magic;
    memcpy(&magic, [data bytes], 4);

    if (magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == MH_CIGAM || magic == MH_CIGAM_64) {
        // Already thin; return as-is if arch matches, else fail.
        NSArray *archs = [self architecturesInData:data];
        if ([archs count] == 1 && [archs[0] isEqualToString:archName]) return data;
        if (error) *error = MakeError(CDMachOWriterErrorArchNotFound,
            [NSString stringWithFormat:@"file is thin %@; requested %@", archs[0], archName]);
        return nil;
    }

    BOOL isFat = (magic == FAT_MAGIC || magic == FAT_CIGAM);
    BOOL isFat64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
    BOOL swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
    if (!isFat && !isFat64) {
        if (error) *error = MakeError(CDMachOWriterErrorNotMachO, @"not a Mach-O or fat file");
        return nil;
    }

    uint32_t nfat;
    memcpy(&nfat, (const uint8_t *)[data bytes] + 4, 4);
    if (swap) nfat = OSSwapInt32(nfat);

    NSUInteger entrySize = isFat64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
    NSUInteger off = sizeof(struct fat_header);
    for (uint32_t i = 0; i < nfat; i++) {
        if (off + entrySize > [data length]) break;
        cpu_type_t ct;     memcpy(&ct, (const uint8_t *)[data bytes] + off,     4);
        cpu_subtype_t cs;  memcpy(&cs, (const uint8_t *)[data bytes] + off + 4, 4);
        uint64_t sliceOff = 0;
        uint64_t sliceLen = 0;
        if (isFat64) {
            uint64_t o, l;
            memcpy(&o, (const uint8_t *)[data bytes] + off + 8,  8);
            memcpy(&l, (const uint8_t *)[data bytes] + off + 16, 8);
            if (swap) { o = OSSwapInt64(o); l = OSSwapInt64(l); }
            sliceOff = o; sliceLen = l;
        } else {
            uint32_t o, l;
            memcpy(&o, (const uint8_t *)[data bytes] + off + 8,  4);
            memcpy(&l, (const uint8_t *)[data bytes] + off + 12, 4);
            if (swap) { o = OSSwapInt32(o); l = OSSwapInt32(l); }
            sliceOff = o; sliceLen = l;
        }
        if (swap) { ct = OSSwapInt32(ct); cs = OSSwapInt32(cs); }

        const NXArchInfo *ai = NXGetArchInfoFromCpuType(ct, cs);
        NSString *thisName = ai ? [NSString stringWithUTF8String:ai->name]
                                : [NSString stringWithFormat:@"0x%x:0x%x", ct, cs];
        if ([thisName isEqualToString:archName]) {
            if (sliceOff + sliceLen > [data length]) {
                if (error) *error = MakeError(CDMachOWriterErrorBadFile, @"fat arch slice out of bounds");
                return nil;
            }
            return [data subdataWithRange:NSMakeRange((NSUInteger)sliceOff, (NSUInteger)sliceLen)];
        }
        off += entrySize;
    }
    if (error) *error = MakeError(CDMachOWriterErrorArchNotFound,
        [NSString stringWithFormat:@"arch '%@' not in fat archive", archName]);
    return nil;
}

@end
