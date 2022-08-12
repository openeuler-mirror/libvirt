/*
 * huawei_stratovirt_driver.c: huawei stratovirt driver functions
 * Manage stratovirt driver and the lifecycle of domains.
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

#include "stratovirt_driver.h"
#include "stratovirt_conf.h"
#include "stratovirt_domain.h"
#include "stratovirt_process.h"

#include "virerror.h"
#include "virlog.h"
#include "virdomaincheckpointobjlist.h"
#include "viralloc.h"
#include "virpidfile.h"
#include "virtime.h"
#include "virstring.h"
#include "virdomainsnapshotobjlist.h"
#include "virutil.h"
#include "viraccessapicheck.h"
#include "domain_audit.h"
#include "locking/domain_lock.h"

#define VIR_FROM_THIS VIR_FROM_STRATOVIRT

VIR_LOG_INIT("stratovirt.stratovirt_driver");

#define STRATOVIRT_ASYNC_JOB_NONE 0
#define STRATOVIRT_ASYNC_JOB_MIGRATION_IN 2
#define STRATOVIRT_ASYNC_JOB_START 6
#define STRATOVIRT_JOB_DESTROY 2
#define VIR_STRATOVIRT_PROCESS_START_COLD 1
#define VIR_STRATOVIRT_PROCESS_STOP_MIGRATED 1

static virStratoVirtDriverPtr stratovirt_driver;

static int
stratovirtConnectURIProbe(char **uri)
{
    if (stratovirt_driver == NULL)
        return 0;

    *uri = g_strdup("stratovirt:///system");

    return 1;
}

static virDrvOpenStatus stratovirtConnectOpen(virConnectPtr conn,
                                              virConnectAuthPtr auth G_GNUC_UNUSED,
                                              virConfPtr conf G_GNUC_UNUSED,
                                              unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* uri is good but driver isn't */
    if (stratovirt_driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("stratovirt state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = stratovirt_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int stratovirtConnectClose(virConnectPtr conn)
{
    conn->privateData = NULL;
    return 0;
}

static const char *stratovirtConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "StratoVirt";
}

static int stratovirtParseVersion(unsigned long *version,
                                  const char *str)
{
    unsigned int major, minor = 0, micro = 0;
    char *tmp;

    if (virStrToLong_ui(str, &tmp, 10, &major) < 0)
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &minor) < 0)
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &micro) < 0)
        return -1;

    if (major > UINT_MAX / 1000000 || minor > 999 || micro > 999)
        return -1;

    *version = 1000000 * major + 1000 * minor + micro;
    return 0;
}

static int stratovirtConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    g_autofree char *help = NULL;
    char *tmp = NULL;
    g_autofree char *stratovirt_cmd = g_find_program_in_path(STRATOVIRT_CMD);
    g_autoptr(virCommand) cmd = NULL;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    if (!stratovirt_cmd)
        return -2;

    /* get version information */
    cmd = virCommandNewArgList(stratovirt_cmd, "-V", NULL);
    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    tmp = help;

    if ((tmp = STRSKIP(tmp, "StratoVirt ")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unexpected output of StratoVirt binary"));
        return -1;
    }

    if (stratovirtParseVersion(version, tmp) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse StratoVirt version: %s"), tmp);
        return -1;
    }

    return 0;
}

static char *stratovirtConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static int stratovirtConnectNumOfDomains(virConnectPtr conn)
{
    virStratoVirtDriverPtr driver = conn->privateData;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(driver->domains, true,
                                        virConnectNumOfDomainsCheckACL, conn);

}

static int stratovirtConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    virStratoVirtDriverPtr driver = conn->privateData;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                        virConnectListDomainsCheckACL, conn);

}

static int
stratovirtConnectListAllDomains(virConnectPtr conn,
                                virDomainPtr **domains,
                                unsigned int flags)
{
    virStratoVirtDriverPtr driver = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListExport(driver->domains, conn, domains,
                                  virConnectListAllDomainsCheckACL, flags);
}


static char *stratovirtConnectGetCapabilities(virConnectPtr conn)
{
    virStratoVirtDriverPtr driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    char *xml;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = virStratoVirtDriverGetCapabilities(driver, true)))
        return NULL;

    xml = virCapabilitiesFormatXML(caps);
    virObjectUnref(caps);
    return xml;
}

/**
 * stratovirtDomainCreateXML:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Creates a domain based on xml and starts it
 *
 * Returns a new domain object or NULL in case of failure.
 */
static virDomainPtr stratovirtDomainCreateXML(virConnectPtr conn,
                                              const char *xml,
                                              unsigned int flags)
{
    virStratoVirtDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    unsigned int start_flags = VIR_STRATOVIRT_PROCESS_START_COLD;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, driver->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    def = NULL;

    if (stratovirtPro.stratovirtProcessBeginJob(driver, vm, VIR_DOMAIN_JOB_OPERATION_START,
                                                flags) < 0){
        goto cleanup;
    }

    if (stratovirtPro.stratovirtProcessStart(conn, driver, vm, NULL, STRATOVIRT_ASYNC_JOB_START,
                                             NULL, -1, NULL, NULL,
                                             VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
                                             start_flags) < 0) {
        virDomainAuditStart(vm, "booted", false);
        stratovirtDom.stratovirtDomainRemoveInactive(driver, vm);
        stratovirtPro.stratovirtProcessEndJob(driver, vm);
        goto cleanup;
    }

    virDomainAuditStart(vm, "booted", true);
    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);
    stratovirtPro.stratovirtProcessEndJob(driver, vm);

 cleanup:
    virDomainDefFree(def);
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
stratovirtDomainDestroyFlags(virDomainPtr dom,
                             unsigned int flags)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    stratovirtDomainObjPrivatePtr priv;
    unsigned int stopFlags = 0;
    int state;
    int reason;
    bool starting;

    virCheckFlags(VIR_DOMAIN_DESTROY_GRACEFUL, -1);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    state = virDomainObjGetState(vm, &reason);
    starting = (state == VIR_DOMAIN_PAUSED &&
                reason == VIR_DOMAIN_PAUSED_STARTING_UP &&
                !priv->beingDestroyed);

    if (stratovirtPro.stratovirtProcessBeginStopJob(driver, vm, STRATOVIRT_JOB_DESTROY,
                                                    !(flags & VIR_DOMAIN_DESTROY_GRACEFUL)) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        if (starting) {
            VIR_DEBUG("Domain %s is not running anymore", vm->def->name);
            ret = 0;
        } else {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is not running"));
        }
        goto endjob;
    }

    if (priv->job.asyncJob == STRATOVIRT_ASYNC_JOB_MIGRATION_IN)
        stopFlags |= VIR_STRATOVIRT_PROCESS_STOP_MIGRATED;

    stratovirtPro.stratovirtProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED,
                                        STRATOVIRT_ASYNC_JOB_NONE, stopFlags);
    virDomainAuditStop(vm, "destroyed");

    ret = 0;
 endjob:
    if (ret == 0)
        stratovirtDom.stratovirtDomainRemoveInactive(driver, vm);
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int stratovirtDomainDestroy(virDomainPtr dom)
{
    return stratovirtDomainDestroyFlags(dom, 0);
}

static virDomainPtr stratovirtDomainLookupByID(virConnectPtr conn,
                                               int id)
{
    virStratoVirtDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(driver->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id %d"), id);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr stratovirtDomainLookupByUUID(virConnectPtr conn,
                                                 const unsigned char *uuid)
{
    virStratoVirtDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(driver->domains, uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr stratovirtDomainLookupByName(virConnectPtr conn,
                                                 const char *name)
{
    virStratoVirtDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int stratovirtSecurityInit(virStratoVirtDriverPtr driver)
{
    char **names;
    virSecurityManagerPtr mgr = NULL;
    virSecurityManagerPtr stack = NULL;
    g_autoptr(virStratoVirtDriverConfig) cfg = virStratoVirtDriverGetConfig(driver);
    unsigned int flags = 0;

    if (cfg->securityDefaultConfined)
        flags |= VIR_SECURITY_MANAGER_DEFAULT_CONFINED;
    if (cfg->securityRequireConfined)
        flags |= VIR_SECURITY_MANAGER_REQUIRE_CONFINED;
    if (driver->privileged)
        flags |= VIR_SECURITY_MANAGER_PRIVILEGED;

    if (cfg->securityDriverNames &&
        cfg->securityDriverNames[0]) {
        names = cfg->securityDriverNames;
        while (names && *names) {
            if (!(mgr = stratovirtSecurityNew(*names,
                                              STRATOVIRT_DRIVER_NAME,
                                              flags)))
                goto error;
            if (!stack) {
                if (!(stack = stratovirtSecurityNewStack(mgr)))
                    goto error;
            } else {
                if (stratovirtSecurityStackAddNested(stack, mgr) < 0)
                    goto error;
            }
            mgr = NULL;
            names++;
        }
    } else {
        if (!(mgr = stratovirtSecurityNew(NULL,
                                          STRATOVIRT_DRIVER_NAME,
                                          flags)))
            goto error;
        if (!(stack = stratovirtSecurityNewStack(mgr)))
            goto error;
        mgr = NULL;
    }

    driver->securityManager = stack;
    return 0;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Failed to initialize security drivers"));
    virObjectUnref(stack);
    virObjectUnref(mgr);
    return -1;
}

static void stratovirtProcessEventHandler(void *data, void *opaque G_GNUC_UNUSED)
{
    stratovirtProcessEventPtr processEvent = data;
    virDomainObjPtr vm = processEvent->vm;

    VIR_DEBUG("vm=%p, event=%d", vm, processEvent->eventType);

    virObjectLock(vm);

    virDomainObjEndAPI(&vm);
    stratovirtProcessEventFree(processEvent);
}

/**
 * stratovirtStateCleanup:
 *
 * Release resources allocated by StratoVirt driver
 */
static int
stratovirtStateCleanup(void)
{
    if (!stratovirt_driver)
        return -1;

    virObjectUnref(stratovirt_driver->closeCallbacks);
    virLockManagerPluginUnref(stratovirt_driver->lockManager);
    virSysinfoDefFree(stratovirt_driver->hostsysinfo);
    virPortAllocatorRangeFree(stratovirt_driver->webSocketPorts);
    virPortAllocatorRangeFree(stratovirt_driver->remotePorts);
    virHashFree(stratovirt_driver->sharedDevices);
    virObjectUnref(stratovirt_driver->hostdevMgr);
    virObjectUnref(stratovirt_driver->securityManager);
    virObjectUnref(stratovirt_driver->domainEventState);
    virObjectUnref(stratovirt_driver->qemuCapsCache);
    virObjectUnref(stratovirt_driver->xmlopt);
    virCPUDefFree(stratovirt_driver->hostcpu);
    virCapabilitiesHostNUMAUnref(stratovirt_driver->hostnuma);
    virObjectUnref(stratovirt_driver->caps);
    ebtablesContextFree(stratovirt_driver->ebtables);
    virObjectUnref(stratovirt_driver->domains);
    virThreadPoolFree(stratovirt_driver->workerPool);

    if (stratovirt_driver->lockFD != -1)
        virPidFileRelease(stratovirt_driver->config->stateDir, "driver", stratovirt_driver->lockFD);

    virObjectUnref(stratovirt_driver->config);
    virMutexDestroy(&stratovirt_driver->lock);
    VIR_FREE(stratovirt_driver);

    return 0;
}

/**
 * stratovirtStateInitialize:
 *
 * Initialization function for the StratoVirt daemon
 */
static int
stratovirtStateInitialize(bool privileged,
                          const char *root,
                          virStateInhibitCallback callback,
                          void *opaque)
{
    g_autofree char *driverConf = NULL;
    virStratoVirtDriverConfigPtr cfg;
    uid_t run_uid = -1;
    gid_t run_gid = -1;
    g_autofree char *memoryBackingPath = NULL;
    bool autostart = true;
    size_t i;
    g_autofree virSecurityManagerPtr *sec_managers = NULL;

    if (VIR_ALLOC(stratovirt_driver) < 0)
        return VIR_DRV_STATE_INIT_ERROR;

    stratovirt_driver->lockFD = -1;

    if (virMutexInit(&stratovirt_driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        VIR_FREE(stratovirt_driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver only support root user."));
        return -1;
    }

    stratovirt_driver->inhibitCallback = callback;
    stratovirt_driver->inhibitOpaque = opaque;

    stratovirt_driver->privileged = privileged;
    stratovirt_driver->hostarch = virArchFromHost();

    if (!(stratovirt_driver->domains = virDomainObjListNew()))
        goto error;

    stratovirt_driver->domainEventState = virObjectEventStateNew();
    if (!stratovirt_driver->domainEventState)
        goto error;

    if (privileged)
        stratovirt_driver->hostsysinfo = virSysinfoRead();

    if (!(stratovirt_driver->config = cfg = virStratoVirtDriverConfigNew(privileged)))
        goto error;

    if (!(driverConf = g_strdup_printf("%s/stratovirt.conf", cfg->configBaseDir)))
        goto error;

    if (virFileMakePath(cfg->stateDir) < 0) {
        virReportSystemError(errno, _("Failed to create state dir %s"),
                             cfg->stateDir);
        goto error;
    }
    if (virFileMakePath(cfg->libDir) < 0) {
        virReportSystemError(errno, _("Failed to create lib dir %s"),
                             cfg->libDir);
        goto error;
    }
    if (virFileMakePath(cfg->cacheDir) < 0) {
        virReportSystemError(errno, _("Failed to create cache dir %s"),
                             cfg->cacheDir);
        goto error;
    }
    if (virFileMakePath(cfg->saveDir) < 0) {
        virReportSystemError(errno, _("Failed to create save dir %s"),
                             cfg->saveDir);
        goto error;
    }
    if (virFileMakePath(cfg->snapshotDir) < 0) {
        virReportSystemError(errno, _("Failed to create snapshot dir %s"),
                             cfg->snapshotDir);
        goto error;
    }
    if (virFileMakePath(cfg->checkpointDir) < 0) {
        virReportSystemError(errno, _("Failed to create checkpoint dir %s"),
                             cfg->checkpointDir);
        goto error;
    }
    if (virFileMakePath(cfg->autoDumpPath) < 0) {
        virReportSystemError(errno, _("Failed to create dump dir %s"),
                             cfg->autoDumpPath);
        goto error;
    }
    if (virFileMakePath(cfg->channelTargetDir) < 0) {
        virReportSystemError(errno, _("Failed to create channel target dir %s"),
                             cfg->channelTargetDir);
        goto error;
    }
    if (virFileMakePath(cfg->memoryBackingDir) < 0) {
        virReportSystemError(errno, _("Failed to create memory backing dir %s"),
                             cfg->memoryBackingDir);
        goto error;
    }

    if ((stratovirt_driver->lockFD =
         virPidFileAcquire(cfg->stateDir, "driver", false, getpid())) < 0)
        goto error;

    if (!(stratovirt_driver->lockManager =
          virLockManagerPluginNew(cfg->lockManagerName ?
                                  cfg->lockManagerName : "nop",
                                  "stratovirt",
                                  cfg->configBaseDir,
                                  0)))
        goto error;

    if (cfg->macFilter) {
        if (!(stratovirt_driver->ebtables = ebtablesContextNew("stratovirt"))) {
            virReportSystemError(errno,
                                 _("failed to enable mac filter in '%s'"),
                                 __FILE__);
            goto error;
        }

        if (ebtablesAddForwardPolicyReject(stratovirt_driver->ebtables) < 0)
            goto error;
    }

    if ((stratovirt_driver->remotePorts =
         virPortAllocatorRangeNew(_("display"),
                                  cfg->remotePortMin,
                                  cfg->remotePortMax)) == NULL)
        goto error;

    if ((stratovirt_driver->webSocketPorts =
         virPortAllocatorRangeNew(_("webSocket"),
                                  cfg->webSocketPortMin,
                                  cfg->webSocketPortMax)) == NULL)
        goto error;

    if (stratovirtSecurityInit(stratovirt_driver) < 0)
        goto error;

    if (!(stratovirt_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto error;

    if (!(stratovirt_driver->sharedDevices = virHashCreate(30, stratovirtconf.stratovirtSharedDeviceEntryFree)))
        goto error;

    stratovirt_driver->qemuCapsCache = stratovirtconf.virStratoVirtCapsCacheNew(cfg->libDir,
                                                                                cfg->cacheDir,
                                                                                run_uid,
                                                                                run_gid);
    if (!stratovirt_driver->qemuCapsCache)
        goto error;

    if (!(sec_managers = stratovirtSecurityGetNested(stratovirt_driver->securityManager)))
        goto error;

    if (!(stratovirt_driver->xmlopt = stratovirtDomainXMLConfInit(stratovirt_driver)))
        goto error;

    for (i = 0; i < cfg->nhugetlbfs; i++) {
        g_autofree char *hugepagePath = NULL;

        hugepagePath = stratovirtGetBaseHugepagePath(&cfg->hugetlbfs[i]);

        if (!hugepagePath)
            goto error;

        if (virFileMakePath(hugepagePath) < 0) {
            virReportSystemError(errno,
                                 _("unable to create hugepage path %s"),
                                 hugepagePath);
            goto error;
        }
        if (privileged &&
            virFileUpdatePerm(cfg->hugetlbfs[i].mnt_dir,
                              0, S_IXGRP | S_IXOTH) < 0)
            goto error;
    }

    stratovirtGetMemoryBackingBasePath(cfg, &memoryBackingPath);

    if (virFileMakePath(memoryBackingPath) < 0) {
        virReportSystemError(errno,
                             _("unable to create memory backing path %s"),
                             memoryBackingPath);
        goto error;
    }

    if (privileged &&
        virFileUpdatePerm(memoryBackingPath,
                          0, S_IXGRP | S_IXOTH) < 0)
        goto error;

    if (!(stratovirt_driver->closeCallbacks = virCloseCallbacksNew()))
        goto error;

    if (virDomainObjListLoadAllConfigs(stratovirt_driver->domains,
                                       cfg->stateDir,
                                       NULL, true,
                                       stratovirt_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto error;

    stratovirt_driver->workerPool = virThreadPoolNewFull(0, 1, 0, stratovirtProcessEventHandler,
                                                         "stratovirt-event", stratovirt_driver);
    if (!stratovirt_driver->workerPool)
        goto error;

    stratovirtPro.stratovirtProcessReconnectAll(stratovirt_driver);

    if (virDriverShouldAutostart(cfg->stateDir, &autostart) < 0)
        goto error;

    return VIR_DRV_STATE_INIT_COMPLETE;

 error:
    stratovirtStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
}

static virHypervisorDriver stratovirtHypervisorDriver = {
    .name = STRATOVIRT_DRIVER_NAME,
    .connectURIProbe = stratovirtConnectURIProbe,
    .connectOpen = stratovirtConnectOpen, /* 2.2.0 */
    .connectClose = stratovirtConnectClose, /* 2.2.0 */
    .connectGetType = stratovirtConnectGetType, /* 2.2.0 */
    .connectGetVersion = stratovirtConnectGetVersion, /* 2.2.0 */
    .connectGetHostname = stratovirtConnectGetHostname, /* 2.2.0 */
    .connectListDomains = stratovirtConnectListDomains, /* 2.2.0 */
    .connectNumOfDomains = stratovirtConnectNumOfDomains, /* 2.2.0 */
    .connectListAllDomains = stratovirtConnectListAllDomains, /* 2.2.0 */
    .connectGetCapabilities = stratovirtConnectGetCapabilities, /* 2.2.0 */
    .domainCreateXML = stratovirtDomainCreateXML, /* 2.2.0 */
    .domainLookupByID = stratovirtDomainLookupByID, /* 2.2.0 */
    .domainLookupByUUID = stratovirtDomainLookupByUUID, /* 2.2.0 */
    .domainLookupByName = stratovirtDomainLookupByName, /* 2.2.0 */
    .domainDestroy = stratovirtDomainDestroy, /* 2.2.0 */
    .domainDestroyFlags = stratovirtDomainDestroyFlags, /* 2.2.0 */
};

static virConnectDriver stratovirtConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "stratovirt", NULL },
    .hypervisorDriver = &stratovirtHypervisorDriver,
};

static virStateDriver stratovirtStateDriver = {
    .name = "StratoVirt",
    .stateInitialize = stratovirtStateInitialize,
    .stateCleanup = stratovirtStateCleanup,
};

int stratovirtRegister(void)
{
    if (virRegisterConnectDriver(&stratovirtConnectDriver,
                                 true) < 0)
        return -1;
    if (virRegisterStateDriver(&stratovirtStateDriver) < 0)
        return -1;
    return 0;
}
