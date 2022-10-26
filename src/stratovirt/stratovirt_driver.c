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
#include "stratovirt_monitor.h"

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
#define STRATOVIRT_ASYNC_JOB_MIGRATION_OUT 1
#define STRATOVIRT_ASYNC_JOB_MIGRATION_IN 2
#define STRATOVIRT_ASYNC_JOB_SNAPSHOT 5
#define STRATOVIRT_ASYNC_JOB_START 6
#define STRATOVIRT_JOB_DESTROY 2
#define STRATOVIRT_JOB_SUSPEND 3
#define STRATOVIRT_JOB_MODIFY 4
#define VIR_STRATOVIRT_PROCESS_START_COLD 1
#define VIR_STRATOVIRT_PROCESS_START_PAUSED 2
#define VIR_STRATOVIRT_PROCESS_START_AUTODESTROY 4
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
    if (flags & VIR_DOMAIN_START_PAUSED)
        start_flags |= VIR_STRATOVIRT_PROCESS_START_PAUSED;
    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_STRATOVIRT_PROCESS_START_AUTODESTROY;

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

static int stratovirtDomainSuspend(virDomainPtr dom)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    stratovirtDomainObjPrivatePtr priv;
    virDomainPausedReason reason;
    int state;
    g_autoptr(virStratoVirtDriverConfig) cfg = virStratoVirtDriverGetConfig(driver);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        return -1;

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (stratovirtDom.stratovirtDomainObjBeginJob(driver, vm, STRATOVIRT_JOB_SUSPEND) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (priv->job.asyncJob == STRATOVIRT_ASYNC_JOB_MIGRATION_OUT)
        reason = VIR_DOMAIN_PAUSED_MIGRATION;
    else if (priv->job.asyncJob == STRATOVIRT_ASYNC_JOB_SNAPSHOT)
        reason = VIR_DOMAIN_PAUSED_SNAPSHOT;
    else
        reason = VIR_DOMAIN_PAUSED_USER;

    state = virDomainObjGetState(vm, NULL);
    if (state == VIR_DOMAIN_PMSUSPENDED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is pmsuspended"));
        goto endjob;
    } else if (state != VIR_DOMAIN_PAUSED) {
        if (stratovirtPro.stratovirtProcessStopCPUs(driver, vm, reason, STRATOVIRT_ASYNC_JOB_NONE) < 0)
            goto endjob;
    }
    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;

    ret = 0;

endjob:
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

cleanup:
    virDomainObjEndAPI(&vm);

    return ret;
}

static int stratovirtDomainResume(virDomainPtr dom)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    int state;
    int reason;
    g_autoptr(virStratoVirtDriverConfig) cfg = virStratoVirtDriverGetConfig(driver);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        return -1;

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (stratovirtDom.stratovirtDomainObjBeginJob(driver, vm, STRATOVIRT_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    state = virDomainObjGetState(vm, &reason);
    if (state == VIR_DOMAIN_PMSUSPENDED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is pmsuspended"));
        goto endjob;
    } else if (state == VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is already running"));
        goto endjob;
    } else if ((state == VIR_DOMAIN_CRASHED &&
                reason == VIR_DOMAIN_CRASHED_PANICKED) ||
                state == VIR_DOMAIN_PAUSED) {
        if (stratovirtPro.stratovirtProcessStartCPUs(driver, vm,
                                                     VIR_DOMAIN_RUNNING_UNPAUSED,
                                                     STRATOVIRT_ASYNC_JOB_NONE) < 0) {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("resume operation failed"));
            goto endjob;
        }
    }
    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;
    ret = 0;

 endjob:
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int stratovirtDomainShutdownFlags(virDomainPtr dom,
                                         unsigned int flags)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    stratovirtDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SHUTDOWN_DEFAULT, -1);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (stratovirtDom.stratovirtDomainObjBeginJob(driver, vm, STRATOVIRT_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_RUNNING &&
        virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("only can shutdown running/paused domain"));
        goto endjob;
    }

    stratovirtDom.stratovirtDomainObjEnterMonitor(driver, vm);
    ret = stratovirtMon.stratovirtMonitorSystemPowerdown(priv->mon);
    if (stratovirtDom.stratovirtDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

endjob:
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int stratovirtDomainShutdown(virDomainPtr dom)
{
    return stratovirtDomainShutdownFlags(dom, 0);
}

static virDomainPtr
stratovirtDomainDefineXMLFlags(virConnectPtr conn,
                               const char *xml,
                               unsigned int flags)
{
    virStratoVirtDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainDefPtr oldDef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    g_autoptr(virStratoVirtDriverConfig) cfg = virStratoVirtDriverGetConfig(driver);
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, driver->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    if (virXMLCheckIllegalChars("names", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   0, &oldDef)))
        goto cleanup;
    def = NULL;

    vm->persistent = 1;

    if (virDomainDefSave(vm->newDef ? vm->newDef : vm->def,
                         driver->xmlopt, cfg->configDir) < 0) {
        if (oldDef) {
            /* restore the old backup */
            if (virDomainObjIsActive(vm))
                vm->newDef = oldDef;
            else
                vm->def = oldDef;
            oldDef = NULL;
        } else {
            vm->persistent = 0;
            stratovirtDom.stratovirtDomainRemoveInactive(driver, vm);
        }
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

cleanup:
    virDomainDefFree(def);
    virDomainDefFree(oldDef);
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
stratovirtDomainDefineXML(virConnectPtr conn,
                          const char *xml)
{
    return stratovirtDomainDefineXMLFlags(conn, xml, 0);
}

static int stratovirtDomainCreateWithFlags(virDomainPtr dom,
                                           unsigned int flags)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned int start_flags = VIR_STRATOVIRT_PROCESS_START_COLD;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED |
                  VIR_DOMAIN_START_AUTODESTROY, -1);

    if (flags & VIR_DOMAIN_START_PAUSED)
        start_flags |= VIR_STRATOVIRT_PROCESS_START_PAUSED;
    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_STRATOVIRT_PROCESS_START_AUTODESTROY;

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (stratovirtPro.stratovirtProcessBeginJob(driver, vm, VIR_DOMAIN_JOB_OPERATION_START,
                                                flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is already running"));
        goto endjob;
    }

    if (stratovirtPro.stratovirtProcessStart(dom->conn, driver, vm, NULL,
                                             STRATOVIRT_ASYNC_JOB_START,
                                             NULL, -1, NULL, NULL,
                                             VIR_NETDEV_VPORT_PROFILE_OP_CREATE, start_flags) < 0)
        goto endjob;

    dom->id = vm->def->id;
    ret = 0;

endjob:
    stratovirtPro.stratovirtProcessEndJob(driver, vm);

cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int stratovirtDomainCreate(virDomainPtr dom)
{
    return stratovirtDomainCreateWithFlags(dom, 0);
}

static int stratovirtDomainIsActive(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int
stratovirtDomainUndefineFlags(virDomainPtr dom,
                              unsigned int flags)
{
    virStratoVirtDriverPtr driver  = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    int nsnapshots;
    int ncheckpoints;
    g_autofree char *nvram_path = NULL;
    g_autoptr(virStratoVirtDriverConfig) cfg = virStratoVirtDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA |
                  VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA |
                  VIR_DOMAIN_UNDEFINE_NVRAM |
                  VIR_DOMAIN_UNDEFINE_KEEP_NVRAM, -1);

    if ((flags & VIR_DOMAIN_UNDEFINE_NVRAM) &&
        (flags & VIR_DOMAIN_UNDEFINE_KEEP_NVRAM)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot both keep and delete nvram"));
        return -1;
    }

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUndefineFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot undefine transient domain"));
        goto cleanup;
    }

    if (stratovirtDom.stratovirtDomainObjBeginJob(driver, vm, STRATOVIRT_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) &&
        (nsnapshots = virDomainSnapshotObjListNum(vm->snapshots, NULL, 0))) {
        if (!(flags & VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("cannot delete inactive domain with %d snapshots"),
                           nsnapshots);
            goto endjob;
        }
        if (stratovirtDom.stratovirtDomainSnapshotDiscardAllMetadata(driver, vm) < 0)
            goto endjob;
    }

    if (!virDomainObjIsActive(vm) &&
        (ncheckpoints = virDomainListCheckpoints(vm->checkpoints, NULL, dom,
                                                 NULL, flags)) > 0) {
        if (!(flags & VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("cannot delete inactive domain with %d checkpoints"),
	                   ncheckpoints);
            goto endjob;
        }
        if (stratovirtDom.stratovirtDomainCheckpointDiscardAllMetadata(driver, vm) < 0)
            goto endjob;
    }

    if (vm->def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_EFI) {
        nvram_path = g_strdup_printf("%s/%s_VARS.fd", cfg->nvramDir, vm->def->name);
    } else {
        if (vm->def->os.loader)
            nvram_path = g_strdup(vm->def->os.loader->nvram);
    }


    if (nvram_path && virFileExists(nvram_path)) {
        if (flags & VIR_DOMAIN_UNDEFINE_NVRAM) {
            if (unlink(nvram_path) < 0) {
                virReportSystemError(errno,
                                     _("failed to remove nvram %s"),
                                     nvram_path);
                goto endjob;
            }
        } else if (!(flags & VIR_DOMAIN_UNDEFINE_KEEP_NVRAM)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot undefine domain with nvram"));
            goto endjob;
        }
    }

    if (virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm) < 0)
        goto cleanup;

    vm->persistent = 0;
    if (!virDomainObjIsActive(vm))
        stratovirtDom.stratovirtDomainRemoveInactive(driver, vm);
    ret = 0;

endjob:
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
stratovirtDomainUndefine(virDomainPtr dom)
{
    return  stratovirtDomainUndefineFlags(dom, 0);
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

static int stratovirtDomainOpenConsole(virDomainPtr dom,
                                       const char *dev_name G_GNUC_UNUSED,
                                       virStreamPtr st,
                                       unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainChrDefPtr chr = NULL;
    stratovirtDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_CONSOLE_SAFE | VIR_DOMAIN_CONSOLE_FORCE, -1);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (vm->def->nconsoles)
        chr = vm->def->consoles[0];
    else if (vm->def->nserials)
        chr = vm->def->serials[0];

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot find character device"));
	goto cleanup;
    }

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %s is not using a PTY"),
		       NULLSTR(chr->info.alias));
	goto cleanup;
    }

    ret = virChrdevOpen(priv->devs, chr->source, st,
                        (flags & VIR_DOMAIN_CONSOLE_FORCE) != 0);

    if (ret == 1) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Active console session exists for this domain"));
	ret = -1;
    }

cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int stratovirtDomainGetState(virDomainPtr dom,
                                    int *state,
				    int *reason,
				    unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
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

static void processMonitorEOFEvent(virStratoVirtDriverPtr driver,
                                   virDomainObjPtr vm)
{
    int stopReason = VIR_DOMAIN_SHUTOFF_SHUTDOWN;
    const char *auditReason = "shutdown";
    unsigned int stopFlags = 0;

    if (stratovirtPro.stratovirtProcessBeginStopJob(driver, vm, STRATOVIRT_JOB_DESTROY, true) < 0)
        return;

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("Domain %p '%s' is not active, ignoring EOF", vm, vm->def->name);
        goto endjob;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_SHUTDOWN) {
        VIR_DEBUG("Monitor connection to '%s' closed without SHUTDOWN event; "
                  "assuming the domain crashed", vm->def->name);
        stopReason = VIR_DOMAIN_SHUTOFF_CRASHED;
        auditReason = "failed";
    }

    stratovirtPro.stratovirtProcessStop(driver, vm, stopReason,
                                        STRATOVIRT_ASYNC_JOB_NONE,
                                        stopFlags);
    virDomainAuditStop(vm, auditReason);

endjob:
    stratovirtDom.stratovirtDomainRemoveInactive(driver, vm);
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);
}

static void stratovirtProcessEventHandler(void *data, void *opaque)
{
    stratovirtProcessEventPtr processEvent = data;
    virDomainObjPtr vm = processEvent->vm;
    virStratoVirtDriverPtr driver = opaque;

    VIR_DEBUG("vm=%p, event=%d", vm, processEvent->eventType);

    virObjectLock(vm);

    switch (processEvent->eventType) {
    case STRATOVIRT_PROCESS_EVENT_MONITOR_EOF:
        processMonitorEOFEvent(driver, vm);
        break;
    case STRATOVIRT_PROCESS_EVENT_WATCHDOG:
    case STRATOVIRT_PROCESS_EVENT_GUESTPANIC:
    case STRATOVIRT_PROCESS_EVENT_DEVICE_DELETED:
    case STRATOVIRT_PROCESS_EVENT_NIC_RX_FILTER_CHANGED:
    case STRATOVIRT_PROCESS_EVENT_SERIAL_CHANGED:
    case STRATOVIRT_PROCESS_EVENT_BLOCK_JOB:
    case STRATOVIRT_PROCESS_EVENT_JOB_STATUS_CHANGE:
    case STRATOVIRT_PROCESS_EVENT_PR_DISCONNECT:
    case STRATOVIRT_PROCESS_EVENT_RDMA_GID_STATUS_CHANGED:
    case STRATOVIRT_PROCESS_EVENT_GUEST_CRASHLOADED:
    case STRATOVIRT_PROCESS_EVENT_LAST:
    default:
        break;
    }
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
    if (virFileMakePath(cfg->nvramDir) < 0) {
        virReportSystemError(errno, _("Failed to create nvram dir %s"),
                             cfg->nvramDir);
        goto error;
    }
    if (virFileMakePath(cfg->memoryBackingDir) < 0) {
        virReportSystemError(errno, _("Failed to create memory backing dir %s"),
                             cfg->memoryBackingDir);
        goto error;
    }

    if (virDirCreate(cfg->dbusStateDir, 0770, cfg->user, cfg->group,
                     VIR_DIR_CREATE_ALLOW_EXIST) < 0) {
        virReportSystemError(errno, _("Failed to create dbus state dir %s"),
                            cfg->dbusStateDir);
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

    if (virDomainObjListLoadAllConfigs(stratovirt_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir, false,
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

static char
*stratovirtDomainGetXMLDesc(virDomainPtr dom,
                            unsigned int flags)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, driver->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
stratovirtCheckDiskConfigAgainstDomain(const virDomainDef *def,
                                       const virDomainDiskDef *disk)
{
    if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI &&
        virDomainSCSIDriveAddressIsUsed(def, &disk->info.addr.drive)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain already contains a disk with that address"));
        return -1;
    }

    return 0;
}

static int
stratovirtDomainAttachDeviceConfigPersistent(virDomainDefPtr vmdef,
                                             virDomainDeviceDefPtr dev,
                                             virStratoVirtCapsPtr stratovirtCaps,
                                             unsigned int parse_flags,
                                             virDomainXMLOptionPtr xmlopt)
{
    virDomainControllerDefPtr controller;
    virDomainDiskDefPtr disk;

    switch ((virDomainDeviceType)dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (virDomainDiskIndexByName(vmdef, disk->dst, true) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("target %s already exists"), disk->dst);
            return -1;
        }
        if (virDomainDiskTranslateSourcePool(disk) < 0)
            return -1;
        if (stratovirtconf.stratovirtCheckDiskConfig(disk, vmdef, NULL) < 0)
            return -1;
        if (stratovirtCheckDiskConfigAgainstDomain(vmdef, disk) < 0)
            return -1;
        if (virDomainDiskInsert(vmdef, disk) < 0)
            return -1;
        dev->data.disk = NULL;
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        controller = dev->data.controller;
        if (controller->idx != -1 &&
            virDomainControllerFind(vmdef, controller->type,
                                    controller->idx) >= 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("controller index='%d' already exists"),
                           controller->idx);
            return -1;
        }

        if (virDomainControllerInsert(vmdef, controller) < 0)
            return -1;
        dev->data.controller = NULL;
        break;

    case VIR_DOMAIN_DEVICE_INPUT:
        if (VIR_APPEND_ELEMENT(vmdef->inputs, vmdef->ninputs, dev->data.input) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_LAST:
         virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                        _("persistent attach of device '%s' is not supported"),
                        virDomainDeviceTypeToString(dev->type));
         return -1;
    }

    if (virDomainDefPostParse(vmdef, parse_flags, xmlopt, stratovirtCaps) < 0)
        return -1;

    return 0;
}

static int
stratovirtDomainAttachDeviceConfig(virDomainObjPtr vm,
                                   virStratoVirtDriverPtr driver,
                                   const char *xml,
                                   unsigned int flags)
{
    stratovirtDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr vmdef = NULL;
    g_autoptr(virStratoVirtDriverConfig) cfg = NULL;
    virDomainDeviceDefPtr devConf = NULL;
    int ret = -1;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;

    virCheckFlags(VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virStratoVirtDriverGetConfig(driver);

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt,
                                              priv->qemuCaps);

        if (!vmdef)
            goto cleanup;

        if (!(devConf = virDomainDeviceDefParse(xml, vmdef,
                                                driver->xmlopt, priv->qemuCaps,
                                                parse_flags)))
            goto cleanup;

        if (virDomainDeviceValidateAliasForHotplug(vm, devConf,
                                                   VIR_DOMAIN_AFFECT_CONFIG) < 0)
            goto cleanup;

        if (virDomainDefCompatibleDevice(vmdef, devConf, NULL,
                                         VIR_DOMAIN_DEVICE_ACTION_ATTACH,
                                         false) < 0)
            goto cleanup;

        if (stratovirtDomainAttachDeviceConfigPersistent(vmdef, devConf, priv->qemuCaps,
                                                         parse_flags,
                                                         driver->xmlopt) < 0)
            goto cleanup;

        if (virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir) < 0)
            goto cleanup;

        virDomainObjAssignDef(vm, vmdef, false, NULL);
        vmdef = NULL;
    }

    ret = 0;

 cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(devConf);
    return ret;
}

static int
stratovirtDomainAttachDeviceFlags(virDomainPtr dom,
                                  const char *xml,
                                  unsigned int flags)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (stratovirtDom.stratovirtDomainObjBeginJob(driver, vm, STRATOVIRT_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (stratovirtDomainAttachDeviceConfig(vm, driver, xml, flags) < 0)
        goto endjob;

    ret = 0;

 endjob:
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;

}

static int
stratovirtDomainAttachDevice(virDomainPtr dom, const char *xml)
{
    return stratovirtDomainAttachDeviceFlags(dom, xml,
                                             VIR_DOMAIN_AFFECT_CONFIG);
}

static int
stratovirtDomainDetachDeviceConfigPersistent(virDomainDefPtr vmdef,
                                             virDomainDeviceDefPtr dev,
                                             virStratoVirtCapsPtr stratovirtCaps,
                                             unsigned int parse_flags,
                                             virDomainXMLOptionPtr xmlopt)
{
    virDomainDiskDefPtr disk, det_disk;
    virDomainControllerDefPtr cont, det_cont;
    int idx;

    switch ((virDomainDeviceType)dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (!(det_disk = virDomainDiskRemoveByName(vmdef, disk->dst))) {
            virReportError(VIR_ERR_DEVICE_MISSING,
                           _("no target device %s"), disk->dst);
            return -1;
        }
        virDomainDiskDefFree(det_disk);
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        cont = dev->data.controller;
        if ((idx = virDomainControllerFind(vmdef, cont->type,
                                           cont->idx)) < 0) {
            virReportError(VIR_ERR_DEVICE_MISSING, "%s",
                           _("device not present in domain configuration"));
            return -1;
        }
        det_cont = virDomainControllerRemove(vmdef, idx);
        virDomainControllerDefFree(det_cont);
        break;

    case VIR_DOMAIN_DEVICE_INPUT:
        if ((idx = virDomainInputDefFind(vmdef, dev->data.input)) < 0) {
            virReportError(VIR_ERR_DEVICE_MISSING, "%s",
                           _("matching input device not found"));
            return -1;
        }
        VIR_DELETE_ELEMENT(vmdef->inputs, idx, vmdef->ninputs);
        break;

    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("persistent detach of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    if (virDomainDefPostParse(vmdef, parse_flags, xmlopt, stratovirtCaps) < 0)
        return -1;

    return 0;
}

static int
stratovirtDomainDetachDeviceConfig(virStratoVirtDriverPtr driver,
                                   virDomainObjPtr vm,
                                   const char *xml,
                                   unsigned int flags)
{
    stratovirtDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virStratoVirtDriverConfig) cfg = NULL;
    virDomainDeviceDefPtr dev = NULL;
    unsigned int parse_flags =  VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;
    virDomainDefPtr vmdef = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virStratoVirtDriverGetConfig(driver);

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;

    dev = virDomainDeviceDefParse(xml, vm->def,
                                  driver->xmlopt, priv->qemuCaps,
                                  parse_flags);
    if (dev == NULL)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt, priv->qemuCaps);
        if (!vmdef)
            goto cleanup;

        if (stratovirtDomainDetachDeviceConfigPersistent(vmdef, dev, priv->qemuCaps,
                                                         parse_flags,
                                                         driver->xmlopt) < 0)
            goto cleanup;

        if (virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir) < 0)
            goto cleanup;

        virDomainObjAssignDef(vm, vmdef, false, NULL);
        vmdef = NULL;
    }

    ret = 0;

 cleanup:
    virDomainDeviceDefFree(dev);
    virDomainDefFree(vmdef);
    return ret;
}

static int
stratovirtDomainDetachDeviceFlags(virDomainPtr dom,
                                  const char *xml,
                                  unsigned int flags)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (stratovirtDom.stratovirtDomainObjBeginJob(driver, vm, STRATOVIRT_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (stratovirtDomainDetachDeviceConfig(driver, vm, xml, flags) < 0)
        goto endjob;

    ret = 0;

 endjob:
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
stratovirtDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    return stratovirtDomainDetachDeviceFlags(dom, xml,
                                             VIR_DOMAIN_AFFECT_CONFIG);
}

static int
stratovirtDomainUpdateDeviceConfig(virDomainDefPtr vmdef,
                                   virDomainDeviceDefPtr dev,
                                   virStratoVirtCapsPtr stratovirtCaps,
                                   unsigned int parse_flags,
                                   virDomainXMLOptionPtr xmlopt)
{
    virDomainDiskDefPtr newDisk;
    virDomainDeviceDef oldDev = { .type = dev->type };
    int pos;

    switch ((virDomainDeviceType)dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        newDisk = dev->data.disk;
        if ((pos = virDomainDiskIndexByName(vmdef, newDisk->dst, false)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("target %s doesn't exist."), newDisk->dst);
            return -1;
        }

        oldDev.data.disk = vmdef->disks[pos];
        if (virDomainDefCompatibleDevice(vmdef, dev, &oldDev,
                                         VIR_DOMAIN_DEVICE_ACTION_UPDATE,
                                         false) < 0)
            return -1;

        virDomainDiskDefFree(vmdef->disks[pos]);
        vmdef->disks[pos] = newDisk;
        dev->data.disk = NULL;
        break;

    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("persistent update of device '%s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    if (virDomainDefPostParse(vmdef, parse_flags, xmlopt, stratovirtCaps) < 0)
        return -1;

    return 0;
}

static int
stratovirtDomainUpdateDeviceFlags(virDomainPtr dom,
                                  const char *xml,
                                  unsigned int flags)
{
    virStratoVirtDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    stratovirtDomainObjPrivatePtr priv;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    int ret = -1;
    g_autoptr(virStratoVirtDriverConfig) cfg = NULL;
    unsigned int parse_flags = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virStratoVirtDriverGetConfig(driver);

    if (!(vm = stratovirtDomainObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (stratovirtDom.stratovirtDomainObjBeginJob(driver, vm, STRATOVIRT_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        parse_flags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;

        dev = virDomainDeviceDefParse(xml, vm->def,
                                      driver->xmlopt, priv->qemuCaps,
                                      parse_flags);
        if (dev == NULL)
            goto endjob;

        vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt,
                                              priv->qemuCaps);

        if (vmdef == NULL)
            goto endjob;

        if  ((ret = stratovirtDomainUpdateDeviceConfig(vmdef, dev, priv->qemuCaps,
                                                       parse_flags,
                                                       driver->xmlopt)) < 0)
            goto endjob;

        ret = virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    stratovirtDom.stratovirtDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    return ret;
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
    .domainSuspend =stratovirtDomainSuspend, /* 2.2.0 */
    .domainResume = stratovirtDomainResume, /* 2.2.0 */
    .domainGetState = stratovirtDomainGetState, /* 2.2.0 */
    .domainLookupByID = stratovirtDomainLookupByID, /* 2.2.0 */
    .domainLookupByUUID = stratovirtDomainLookupByUUID, /* 2.2.0 */
    .domainLookupByName = stratovirtDomainLookupByName, /* 2.2.0 */
    .domainDestroy = stratovirtDomainDestroy, /* 2.2.0 */
    .domainDestroyFlags = stratovirtDomainDestroyFlags, /* 2.2.0 */
    .domainOpenConsole = stratovirtDomainOpenConsole, /* 2.2.0 */
    .domainShutdown = stratovirtDomainShutdown, /* 2.2.0 */
    .domainShutdownFlags = stratovirtDomainShutdownFlags, /* 2.2.0 */
    .domainCreate = stratovirtDomainCreate, /* 2.2.0 */
    .domainCreateWithFlags = stratovirtDomainCreateWithFlags, /* 2.2.0 */
    .domainDefineXML = stratovirtDomainDefineXML, /* 2.2.0 */
    .domainDefineXMLFlags = stratovirtDomainDefineXMLFlags, /* 2.2.0 */
    .domainUndefine = stratovirtDomainUndefine, /* 2.2.0 */
    .domainUndefineFlags = stratovirtDomainUndefineFlags, /* 2.2.0 */
    .domainIsActive = stratovirtDomainIsActive, /* 2.2.0 */
    .domainGetXMLDesc = stratovirtDomainGetXMLDesc, /* 2.2.0 */
    .domainAttachDevice = stratovirtDomainAttachDevice, /* 2.2.0 */
    .domainAttachDeviceFlags = stratovirtDomainAttachDeviceFlags, /* 2.2.0 */
    .domainDetachDevice = stratovirtDomainDetachDevice, /* 2.2.0 */
    .domainDetachDeviceFlags = stratovirtDomainDetachDeviceFlags, /* 2.2.0 */
    .domainUpdateDeviceFlags = stratovirtDomainUpdateDeviceFlags, /* 2.2.0 */
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
