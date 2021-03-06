/*
 * storage_source.h: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009, 2012-2016 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "storage_source_conf.h"

#ifndef DEV_BSIZE
# define DEV_BSIZE 512
#endif

virStorageSourcePtr
virStorageSourceGetMetadataFromFD(const char *path,
                                  int fd,
                                  int format);

virStorageSourcePtr
virStorageSourceGetMetadataFromBuf(const char *path,
                                   char *buf,
                                   size_t len,
                                   int format)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

virStorageSourcePtr
virStorageSourceChainLookup(virStorageSourcePtr chain,
                            virStorageSourcePtr startFrom,
                            const char *name,
                            unsigned int idx,
                            virStorageSourcePtr *parent)
    ATTRIBUTE_NONNULL(1);

int
virStorageSourceUpdatePhysicalSize(virStorageSourcePtr src,
                                   int fd,
                                   struct stat const *sb);

int
virStorageSourceUpdateBackingSizes(virStorageSourcePtr src,
                                   int fd,
                                   struct stat const *sb);

int
virStorageSourceUpdateCapacity(virStorageSourcePtr src,
                               char *buf,
                               ssize_t len);

int
virStorageSourceNewFromBacking(virStorageSourcePtr parent,
                               virStorageSourcePtr *backing);

int
virStorageSourceParseRBDColonString(const char *rbdstr,
                                    virStorageSourcePtr src)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
virStorageSourceGetRelativeBackingPath(virStorageSourcePtr top,
                                       virStorageSourcePtr base,
                                       char **relpath)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
virStorageSourceNewFromBackingAbsolute(const char *path,
                                       virStorageSourcePtr *src);

int
virStorageSourceInit(virStorageSourcePtr src);

int
virStorageSourceInitAs(virStorageSourcePtr src,
                       uid_t uid, gid_t gid);

void
virStorageSourceDeinit(virStorageSourcePtr src);

int
virStorageSourceCreate(virStorageSourcePtr src);

int
virStorageSourceUnlink(virStorageSourcePtr src);

int
virStorageSourceStat(virStorageSourcePtr src,
                     struct stat *st);

ssize_t
virStorageSourceRead(virStorageSourcePtr src,
                     size_t offset,
                     size_t len,
                     char **buf);

const char *
virStorageSourceGetUniqueIdentifier(virStorageSourcePtr src);

int
virStorageSourceAccess(virStorageSourcePtr src,
                       int mode);

int
virStorageSourceChown(const virStorageSource *src,
                      uid_t uid,
                      gid_t gid);

int
virStorageSourceSupportsSecurityDriver(const virStorageSource *src);

int
virStorageSourceSupportsAccess(const virStorageSource *src);

int
virStorageSourceSupportsCreate(const virStorageSource *src);

int
virStorageSourceSupportsBackingChainTraversal(const virStorageSource *src);

int
virStorageSourceGetMetadata(virStorageSourcePtr src,
                            uid_t uid, gid_t gid,
                            bool report_broken)
    ATTRIBUTE_NONNULL(1);

int
virStorageSourceGetBackingStoreStr(virStorageSourcePtr src,
                                   char **backing)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virStorageSourceReportBrokenChain(int errcode,
                                  virStorageSourcePtr src,
                                  virStorageSourcePtr parent);
