/*
 * huawei_stratovirt_conf.h: huawei stratovirt conf functions
 * Manage configuration parameters.
 *
 * Copyright (C) 2022-2022 HUAWEI, Inc.
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
 *
 */

#pragma once

#include "qemu_migration.h"
#include "qemu_capabilities.h"
#include "qemu_command.h"
#include "virconftypes.h"

#define STRATOVIRT_DRIVER_NAME "StratoVirt"
#define STRATOVIRT_CMD "stratovirt"

#define stratovirtSecurityGetNested virSecurityManagerGetNested
#define stratovirtSecurityNew virSecurityManagerNew
#define stratovirtSecurityNewStack virSecurityManagerNewStack
#define stratovirtSecurityStackAddNested virSecurityManagerStackAddNested

typedef virQEMUDriver virStratoVirtDriver;
typedef virStratoVirtDriver *virStratoVirtDriverPtr;

typedef virQEMUDriverConfig virStratoVirtDriverConfig;
typedef virStratoVirtDriverConfig *virStratoVirtDriverConfigPtr;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virStratoVirtDriverConfig, virObjectUnref);

typedef virQEMUCaps virStratoVirtCaps;
typedef virStratoVirtCaps *virStratoVirtCapsPtr;

virCapsPtr virStratoVirtDriverGetCapabilities(virStratoVirtDriverPtr driver,bool refresh);
virStratoVirtDriverConfigPtr virStratoVirtDriverConfigNew(bool privileged);
virStratoVirtDriverConfigPtr virStratoVirtDriverGetConfig(virStratoVirtDriverPtr driver);
virDomainXMLOptionPtr stratovirtDomainXMLConfInit(virStratoVirtDriverPtr driver);

static inline void stratovirtDriverLock(virStratoVirtDriverPtr driver)
{
    virMutexLock(&driver->lock);
}

static inline void stratovirtDriverUnlock(virStratoVirtDriverPtr driver)
{
    virMutexUnlock(&driver->lock);
}

char *stratovirtGetBaseHugepagePath(virHugeTLBFSPtr hugepage);
void stratovirtGetMemoryBackingBasePath(virStratoVirtDriverConfigPtr cfg,
                                        char **path);

typedef struct StratoVirtConf {
    void (*stratovirtSharedDeviceEntryFree)(void *payload);
    virFileCachePtr (*virStratoVirtCapsCacheNew)(const char *libDir,
                                                 const char *cacheDir,
                                                 uid_t runUid,
                                                 gid_t runGid);
    int (*stratovirtCheckDiskConfig)(virDomainDiskDefPtr disk,
                                     const virDomainDef *def,
                                     virStratoVirtCapsPtr stratovirtCaps);
} virStratoVirtConf;

extern virStratoVirtConf stratovirtconf;
