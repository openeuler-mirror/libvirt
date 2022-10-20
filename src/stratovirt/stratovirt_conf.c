/*
 * huawei_stratovirt_conf.c: huawei stratovirt conf functions
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

#include <config.h>

#include "stratovirt_conf.h"
#include "stratovirt_process.h"

#include "configmake.h"
#include "virlog.h"
#include "virutil.h"
#include "viralloc.h"

VIR_LOG_INIT("stratovirt.stratovirt_conf");

#define VIR_FROM_THIS VIR_FROM_STRATOVIRT

#define STRATOVIRT_REMOTE_PORT_MIN 5900
#define STRATOVIRT_REMOTE_PORT_MAX 65535

#define STRATOVIRT_WEBSOCKET_PORT_MIN 5700
#define STRATOVIRT_WEBSOCKET_PORT_MAX 65535

static virClassPtr virStratoVirtDriverConfigClass;
static void virStratoVirtDriverConfigDispose(void *obj);

static int virStratoVirtConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virStratoVirtDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virStratoVirtConfig);

static virCapsPtr virStratoVirtCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto error;

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        goto error;

    if (virCapabilitiesInitCaches(caps) < 0)
        VIR_WARN("Failed to get host CPU cache info");

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    caps->host.arch, NULL, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM, NULL, NULL, 0, NULL);

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

virCapsPtr
virStratoVirtDriverGetCapabilities(virStratoVirtDriverPtr driver, bool refresh)
{
    virCapsPtr ret = NULL;
    if (refresh) {
        virCapsPtr caps = NULL;
        if ((caps = virStratoVirtCapsInit()) == NULL)
            return NULL;

        stratovirtDriverLock(driver);
        virObjectUnref(driver->caps);
        driver->caps = caps;
    } else {
        stratovirtDriverLock(driver);

        if (driver->caps == NULL || driver->caps->nguests == 0) {
            stratovirtDriverUnlock(driver);
            return virStratoVirtDriverGetCapabilities(driver, true);
        }
    }

    ret = virObjectRef(driver->caps);
    stratovirtDriverUnlock(driver);
    return ret;
}

#ifndef DEFAULT_LOADER_NVRAM
# define DEFAULT_LOADER_NVRAM \
    "/usr/share/edk2/ovmf/OVMF_CODE.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd"
#endif

virStratoVirtDriverConfigPtr virStratoVirtDriverConfigNew(bool privileged)
{
    virStratoVirtDriverConfigPtr cfg = NULL;

    if (virStratoVirtConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virStratoVirtDriverConfigClass)))
       return NULL;

    cfg->uri = g_strdup("stratovirt:///system");

    if (privileged) {
        if (virGetUserID(STRATOVIRT_USER, &cfg->user) < 0)
            return NULL;
        if (virGetGroupID(STRATOVIRT_GROUP, &cfg->group) < 0)
            return NULL;
    } else {
        cfg->user = (uid_t)-1;
        cfg->group = (gid_t)-1;
    }
    cfg->dynamicOwnership = privileged;
    cfg->rememberOwner = privileged;

    cfg->cgroupControllers = -1;

    if (privileged) {
        cfg->logDir = g_strdup_printf("%s/log/libvirt/stratovirt", LOCALSTATEDIR);

        cfg->configBaseDir = g_strdup(SYSCONFDIR "/libvirt");

        cfg->stateDir = g_strdup_printf("%s/libvirt/stratovirt", RUNSTATEDIR);

        cfg->cacheDir = g_strdup_printf("%s/cache/libvirt/stratovirt", LOCALSTATEDIR);

        cfg->libDir = g_strdup_printf("%s/lib/libvirt/stratovirt", LOCALSTATEDIR);

        cfg->saveDir = g_strdup_printf("%s/save", cfg->libDir);

        cfg->snapshotDir = g_strdup_printf("%s/snapshot", cfg->libDir);

        cfg->checkpointDir = g_strdup_printf("%s/checkpoint", cfg->libDir);

        cfg->autoDumpPath = g_strdup_printf("%s/dump", cfg->libDir);

        cfg->channelTargetDir = g_strdup_printf("%s/channel/target", cfg->libDir);

        cfg->nvramDir = g_strdup_printf("%s/nvram", cfg->libDir);

        cfg->memoryBackingDir = g_strdup_printf("%s/ram", cfg->libDir);
    } else {
        g_autofree char *rundir = NULL;
        g_autofree char *cachedir = NULL;

        cachedir = virGetUserCacheDirectory();

        cfg->logDir = g_strdup_printf("%s/stratovirt/log", cachedir);
        cfg->cacheDir = g_strdup_printf("%s/stratovirt/cache", cachedir);

        rundir = virGetUserRuntimeDirectory();
        cfg->stateDir = g_strdup_printf("%s/stratovirt/run", rundir);

        cfg->configBaseDir = virGetUserConfigDirectory();

        cfg->libDir = g_strdup_printf("%s/stratovirt/lib", cfg->configBaseDir);
        cfg->saveDir = g_strdup_printf("%s/stratovirt/save", cfg->configBaseDir);
        cfg->snapshotDir = g_strdup_printf("%s/stratovirt/snapshot", cfg->configBaseDir);
        cfg->checkpointDir = g_strdup_printf("%s/stratovirt/checkpoint",
                                             cfg->configBaseDir);
        cfg->autoDumpPath = g_strdup_printf("%s/stratovirt/dump", cfg->configBaseDir);
        cfg->channelTargetDir = g_strdup_printf("%s/stratovirt/channel/target",
                                                cfg->configBaseDir);
        cfg->nvramDir = g_strdup_printf("%s/nvram", cfg->configBaseDir);
        cfg->memoryBackingDir = g_strdup_printf("%s/stratovirt/ram", cfg->configBaseDir);
    }

    cfg->configDir = g_strdup_printf("%s/stratovirt", cfg->configBaseDir);
    cfg->autostartDir = g_strdup_printf("%s/stratovirt/autostart", cfg->configBaseDir);
    cfg->dbusStateDir = g_strdup_printf("%s/dubs", cfg->stateDir);

    cfg->remotePortMin = STRATOVIRT_REMOTE_PORT_MIN;
    cfg->remotePortMax = STRATOVIRT_REMOTE_PORT_MAX;

    cfg->webSocketPortMin = STRATOVIRT_WEBSOCKET_PORT_MIN;
    cfg->webSocketPortMax = STRATOVIRT_WEBSOCKET_PORT_MAX;

    if (privileged &&
        virFileFindHugeTLBFS(&cfg->hugetlbfs, &cfg->nhugetlbfs) < 0) {
        if (virGetLastErrorCode() != VIR_ERR_NO_SUPPORT)
            return NULL;
    }

    cfg->securityDefaultConfined = true;
    cfg->securityRequireConfined = false;

    cfg->keepAliveInterval = 5;
    cfg->keepAliveCount = 5;
    cfg->seccompSandbox = -1;

    cfg->logTimestamp = true;
    cfg->glusterDebugLevel = 4;
    cfg->stdioLogD = true;

    if (!(cfg->namespaces = virBitmapNew(1)))
        return NULL;

    if (privileged &&
        stratovirtDom.stratovirtDomainNamespaceAvailable(0) &&
        virBitmapSetBit(cfg->namespaces, 0) < 0)
        return NULL;

    if (virFirmwareParseList(DEFAULT_LOADER_NVRAM,
                             &cfg->firmwares,
                             &cfg->nfirmwares) < 0)
        return NULL;

    return g_steal_pointer(&cfg);
}

static void virStratoVirtDriverConfigDispose(void *obj)
{
    virStratoVirtDriverConfigPtr cfg = obj;

    virBitmapFree(cfg->namespaces);
    VIR_FREE(cfg->uri);
    VIR_FREE(cfg->configBaseDir);
    VIR_FREE(cfg->configDir);
    VIR_FREE(cfg->autostartDir);
    VIR_FREE(cfg->logDir);
    VIR_FREE(cfg->stateDir);
    VIR_FREE(cfg->dbusStateDir);
    VIR_FREE(cfg->libDir);
    VIR_FREE(cfg->cacheDir);
    VIR_FREE(cfg->saveDir);
    VIR_FREE(cfg->snapshotDir);
    VIR_FREE(cfg->checkpointDir);
    VIR_FREE(cfg->channelTargetDir);
    VIR_FREE(cfg->nvramDir);

    while (cfg->nhugetlbfs) {
        cfg->nhugetlbfs--;
        VIR_FREE(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
    }
    VIR_FREE(cfg->hugetlbfs);
    VIR_FREE(cfg->autoDumpPath);

    virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);

    VIR_FREE(cfg->memoryBackingDir);
}

virStratoVirtDriverConfigPtr virStratoVirtDriverGetConfig(virStratoVirtDriverPtr driver)
{
    virStratoVirtDriverConfigPtr conf;
    stratovirtDriverLock(driver);
    conf = virObjectRef(driver->config);
    stratovirtDriverUnlock(driver);
    return conf;
}

static virDomainXMLPrivateDataCallbacks *virStratoVirtDriverPrivateDataCallbacks(void) {
    return &virQEMUDriverPrivateDataCallbacks;
}

virDomainXMLOptionPtr stratovirtDomainXMLConfInit(virStratoVirtDriverPtr driver)
{
    virStratoVirtDriverDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&virStratoVirtDriverDomainDefParserConfig,
                                 virStratoVirtDriverPrivateDataCallbacks(),
                                 NULL, NULL, NULL);
}

char *
stratovirtGetBaseHugepagePath(virHugeTLBFSPtr hugepage)
{
    char *ret;

    ret = g_strdup_printf("%s/libvirt/stratovirt", hugepage->mnt_dir);

    return ret;
}

void
stratovirtGetMemoryBackingBasePath(virStratoVirtDriverConfigPtr cfg,
                                   char **path)
{
    *path = g_strdup_printf("%s/libvirt/stratovirt", cfg->memoryBackingDir);
}

virStratoVirtConf stratovirtconf = {
    .stratovirtSharedDeviceEntryFree = qemuSharedDeviceEntryFree,
    .virStratoVirtCapsCacheNew = virQEMUCapsCacheNew,
    .stratovirtCheckDiskConfig = qemuCheckDiskConfig,
};
