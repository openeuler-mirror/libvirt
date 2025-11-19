/*
 * qemu_ham.c: QEMU ham migration handling
 *
 * Copyright (C) 2025 Huawei Technologies Co., Ltd
 */

#include "qemu_domain.h"
#include "qemu_ham.h"

#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_ham");

typedef struct _qemuHamRamBlock qemuHamRamBlock;
struct _qemuHamRamBlock {
    unsigned int numaId;
    unsigned long long hva;
    unsigned long long size;
};

typedef struct _qemuHamRamInfo qemuHamRamInfo;
struct _qemuHamRamInfo {
    int pid;
    unsigned int scna;
    unsigned int num;
    qemuHamRamBlock *blocks;
};

static void
qemuHamRamInfoFree(qemuHamRamInfo *ramInfo)
{
    if (!ramInfo)
        return;

    VIR_FREE(ramInfo->blocks);
    VIR_FREE(ramInfo);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuHamRamInfo, qemuHamRamInfoFree);

void
qemuHamMigrationInfoFree(qemuHamMigrationInfo *hamInfo)
{
    if (!hamInfo)
        return;

    VIR_FREE(hamInfo->name);
    VIR_FREE(hamInfo->srcHostname);
    VIR_FREE(hamInfo->dstHostname);
    VIR_FREE(hamInfo);
}

int
qemuDomainSendQemuMonitorCommandAsync(virDomainObj *vm,
                                      const char *cmd,
                                      char **result,
                                      virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorArbitraryCommand(priv->mon, cmd, -1, result, false);
    qemuDomainObjExitMonitor(vm);

    return ret;
}

static virJSONValue *
qemuHamSendQemuMonitorCommand(virDomainObj *vm,
                              virDomainPtr domain,
                              const char *commandName,
                              virJSONValue *arguments,
                              virDomainAsyncJob asyncJob)
{
    g_autoptr(virJSONValue) command = NULL;
    g_autoptr(virJSONValue) args = virJSONValueCopy(arguments);
    g_autofree char *monitorCmd = NULL;
    g_autofree char *result = NULL;
    int ret = -1;

    if (virJSONValueObjectAdd(&command,
                              "s:execute", commandName,
                              "A:arguments", &args,
                              NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to wrap execute command '%1$s' and arguments into a QMP command wrapper"),
                       commandName);
        return NULL;
    }

    if (!(monitorCmd = virJSONValueToString(command, false))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to convert QMP command json object to string"));
        return NULL;
    }

    if (vm)
        ret = qemuDomainSendQemuMonitorCommandAsync(vm, monitorCmd, &result, asyncJob);

    if (domain)
        ret = domain->conn->driver->domainQemuMonitorCommandAsync(domain, monitorCmd, &result, asyncJob);

    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to get result of QMP command: %1$s"), monitorCmd);
        return NULL;
    }

    return virJSONValueFromString(result);
}

static qemuHamRamInfo *
qemuHamGetRamInfo(virDomainPtr domain)
{
    g_autoptr(qemuHamRamInfo) ramInfo = g_new0(qemuHamRamInfo, 1);
    g_autoptr(virJSONValue) result = NULL;
    virJSONValue *data = NULL;
    virJSONValue *blocksArray = NULL;
    int i;

    if (!(result = qemuHamSendQemuMonitorCommand(NULL, domain, "query-ramblock",
                                                 NULL, VIR_ASYNC_JOB_MIGRATION_IN))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to execute QMP command 'query-ramblock'"));
        return NULL;
    }

    if (!(data = virJSONValueObjectGetObject(result, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("'return' member missing"));
        return NULL;
    }

    if (virJSONValueObjectGetNumberInt(data, "pid", &ramInfo->pid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("'pid' missing in return value"));
        return NULL;
    }

    if (!(blocksArray = virJSONValueObjectGetArray(data, "block"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'block' was missing or not an array"));
        return NULL;
    }

    if ((ramInfo->num = virJSONValueArraySize(blocksArray)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'block' array is empty"));
        return NULL;
    }

    ramInfo->blocks = g_new0(qemuHamRamBlock, ramInfo->num);

    for (i = 0; i < ramInfo->num; i++) {
        virJSONValue *entry = virJSONValueArrayGet(blocksArray, i);
        qemuHamRamBlock *block = ramInfo->blocks + i;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("array element missing"));
            return NULL;
        }

        if (virJSONValueObjectGetNumberUlong(entry, "hva", &block->hva) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("found block wihtout hva"));
            return NULL;
        }

        if (virJSONValueObjectGetNumberUlong(entry, "size", &block->size) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("found block wihtout size"));
            return NULL;
        }
    }

    return g_steal_pointer(&ramInfo);
}

static char *
qemuHamGetBorrowReq(qemuHamMigrationInfo *hamInfo, qemuHamRamInfo *ramInfo)
{
    g_autoptr(virJSONValue) borrowReq = virJSONValueNewObject();
    g_autoptr(virJSONValue) valist = virJSONValueNewArray();
    int i;

    if (virJSONValueObjectAppendString(borrowReq, "action", "borrow") < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add action to borrow request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendString(borrowReq, "srcHostname", hamInfo->srcHostname) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add srcHostname to borrow request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendNumberInt(borrowReq, "srcPid", hamInfo->srcPid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add srcPid to borrow request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendString(borrowReq, "dstHostname", hamInfo->dstHostname) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add dstHostname to borrow request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendNumberInt(borrowReq, "dstPid", hamInfo->dstPid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add dstPid to borrow request json object"));
        return NULL;
    }

    for (i = 0; i < ramInfo->num; i++) {
        g_autoptr(virJSONValue) va = virJSONValueNewObject();
        qemuHamRamBlock *block = ramInfo->blocks + i;

        if (virJSONValueObjectAppendNumberUlong(va, "start", block->hva) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to add start to va json object"));
            return NULL;
        }

        if (virJSONValueObjectAppendNumberUlong(va, "length", block->size) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to add length to va json object"));
            return NULL;
        }

        if (virJSONValueArrayAppend(valist, &va) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to add va to valist json array"));
            return NULL;
        }
    }

    if (virJSONValueObjectAppend(borrowReq, "valist", &valist) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add valist to borrow request json object"));
        return NULL;
    }

    return virJSONValueToString(borrowReq, false);
}

static int
qemuHamGetBorrowInfo(qemuHamMigrationInfo *hamInfo,
                     qemuHamRamInfo *ramInfo,
                     const char *respStr)
{
    g_autoptr(virJSONValue) resp = NULL;
    virJSONValue *message = NULL;
    virJSONValue *numaIdsArray = NULL;
    const char *name;
    int code;
    int i;

    if (!(resp = virJSONValueFromString(respStr))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse borrow info response to json object"));
        return -1;
    }

    if (virJSONValueObjectGetNumberInt(resp, "code", &code) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'code' missing in borrow info response"));
        return -1;
    }

    if (code != 200) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("borrow info request failed with code %1$d"), code);
        return -1;
    }

    if (!(message = virJSONValueObjectGet(resp, "message"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'message' missing in borrow info response"));
        return -1;
    }

    if (!(name = virJSONValueObjectGetString(message, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'name' missing in message json object"));
        return -1;
    }

    hamInfo->name = g_strdup(name);

    if (virJSONValueObjectGetNumberUint(message, "scna", &ramInfo->scna) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'scna' missing in message json object"));
        return -1;
    }

    if (!(numaIdsArray = virJSONValueObjectGetArray(message, "numaIds"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("'numaIds' was missing or not an array"));
        return -1;
    }

    if (ramInfo->num != virJSONValueArraySize(numaIdsArray)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("number of numa mismatch with number of block"));
        return -1;
    }

    for (i = 0; i < ramInfo->num; i++) {
        virJSONValue *entry = virJSONValueArrayGet(numaIdsArray, i);
        qemuHamRamBlock *block = ramInfo->blocks + i;

        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("array element missing"));
            return -1;
        }

        if (virJSONValueGetNumberUint(entry, &block->numaId) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing or invalid element of numaIds array"));
            return -1;
        }
    }

    return 0;
}

static int
qemuHamSendRamInfo(qemuHamRamInfo *ramInfo, virDomainObj *vm)
{
    g_autoptr(virJSONValue) arguments = virJSONValueNewObject();
    g_autoptr(virJSONValue) blocksArray = virJSONValueNewArray();
    g_autoptr(virJSONValue) result = NULL;
    int i;

    if (virJSONValueObjectAppendNumberInt(arguments, "pid", ramInfo->pid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add pid to arguments json object"));
        return -1;
    }

    if (virJSONValueObjectAppendNumberUint(arguments, "scna", ramInfo->scna) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add scna to arguments json object"));
        return -1;
    }

    for (i = 0; i < ramInfo->num; i++) {
        g_autoptr(virJSONValue) entry = virJSONValueNewObject();
        qemuHamRamBlock *block = ramInfo->blocks + i;

        if (virJSONValueObjectAppendNumberUint(entry, "numa-id", block->numaId) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to add numa id to json object"));
            return -1;
        }

        if (virJSONValueObjectAppendNumberUlong(entry, "size", block->size) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to add size to json object"));
            return -1;
        }

        if (virJSONValueArrayAppend(blocksArray, &entry) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to add entry to block json array"));
            return -1;
        }
    }

    if (virJSONValueObjectAppend(arguments, "block", &blocksArray) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add block to arguments json object"));
        return -1;
    }

    if (!(result = qemuHamSendQemuMonitorCommand(vm, NULL, "recv-rmtnuma", arguments,
                                                 VIR_ASYNC_JOB_MIGRATION_OUT))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to execute QMP command 'recv-rmtnuma'"));
        return -1;
    }

    if (virJSONValueObjectHasKey(result, "error")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("execute QMP command 'recv-rmtnuma' failed"));
        return -1;
    }

    return 0;
}

int
qemuHamModifyPgtable(virDomainObj *vm)
{
    g_autoptr(virJSONValue) result = NULL;

    if (!(result = qemuHamSendQemuMonitorCommand(vm, NULL, "modify-pgtable", NULL,
                                                 VIR_ASYNC_JOB_MIGRATION_IN))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to execute QMP command 'modify-pgtable'"));
        return -1;
    }

    if (virJSONValueObjectHasKey(result, "error")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("execute QMP command 'modify-pgtable' failed"));
        return -1;
    }

    return 0;
}

int
qemuHamRollbackPages(virDomainObj *vm)
{
    g_autoptr(virJSONValue) result = NULL;

    if (!(result = qemuHamSendQemuMonitorCommand(vm, NULL, "rollback-pages", NULL,
                                                 VIR_ASYNC_JOB_MIGRATION_OUT))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to execute QMP command 'rollback-pages'"));
        return -1;
    }

    if (virJSONValueObjectHasKey(result, "error")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("execute QMP command 'rollback-pages' failed"));
        return -1;
    }

    return 0;
}

static char *
qemuHamGetClearReq(qemuHamMigrationInfo *hamInfo, virHamClearType type)
{
    g_autofree char *clearReqInit = NULL;
    g_autoptr(virJSONValue) clearReq = NULL;

    if (!(clearReqInit = virHamGetClearReqInit(type, hamInfo->srcHostname))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add action, type and srcHostname to clear request"));
        return NULL;
    }

    if (!(clearReq = virJSONValueFromString(clearReqInit))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create clear request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendString(clearReq, "name", hamInfo->name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add name to clear request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendNumberInt(clearReq, "srcPid", hamInfo->srcPid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add srcPid to clear request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendString(clearReq, "dstHostname", hamInfo->dstHostname) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add dstHostname to clear request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendNumberInt(clearReq, "dstPid", hamInfo->dstPid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add dstPid to clear request json object"));
        return NULL;
    }

    return virJSONValueToString(clearReq, false);
}

void
qemuHamSendClearReq(qemuHamMigrationInfo *hamInfo, virHamClearType type)
{
    g_autofree char *req = NULL;

    if (!(req = qemuHamGetClearReq(hamInfo, type))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create clear request"));
        return;
    }
    VIR_INFO("Ham migration clear borrowed numa request: %s", NULLSTR(req));

    if (!virHamRackIpcSyncSendAndRecv(req))
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to clear borrowed numa"));
}

int
qemuHamMigrationPrepare(qemuHamMigrationInfo *hamInfo,
                        virConnectPtr dconn,
                        virDomainObj *vm,
                        char *cookieout,
                        int cookieoutlen)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;
    virDomainPtr ddomain = NULL;
    g_autofree char *dname = NULL;
    g_autofree char *duuidstr = NULL;
    unsigned char duuid[VIR_UUID_BUFLEN];
    g_autoptr(qemuHamRamInfo) ramInfo = NULL;
    g_autofree char *req = NULL;
    g_autofree char *resp = NULL;
    int ret = -1;

    if (cookieout && cookieoutlen &&
        cookieout[cookieoutlen-1] != '\0') {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("migration cookie was not NULL terminated"));
        return -1;
    }

    if (!virXMLParseStringCtxt(cookieout, _("(qemu_migration_cookie)"), &ctxt)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse xml context"));
        return -1;
    }

    if (!(dname = virXPathString("string(./name[1])", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing name element in migration data"));
        return -1;
    }

    if (!(duuidstr = virXPathString("string(./uuid[1])", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing uuid element in migration data"));
        return -1;
    }

    if (virUUIDParse(duuidstr, duuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("malformed uuid element"));
        return -1;
    }

    if (!(hamInfo->dstHostname = virXPathString("string(./hostname[1])", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing hostname element in migration data"));
        return -1;
    }

    ddomain = virGetDomain(dconn, dname, duuid, -1);

    VIR_DEBUG("Begin to get ram info of domain on destination for ham migration");
    if (!(ramInfo = qemuHamGetRamInfo(ddomain))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to get ram info of domain on destination"));
        goto cleanup;
    }

    hamInfo->dstPid = ramInfo->pid;

    VIR_DEBUG("Begin to get borrowed numa info for ham migration");
    if (!(req = qemuHamGetBorrowReq(hamInfo, ramInfo))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create borrow numa request"));
        goto cleanup;
    }
    VIR_INFO("Ham migration borrow numa request: %s", NULLSTR(req));

    if (!(resp = virHamRackIpcSyncSendAndRecv(req))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to get borrow response from RackAgentIpcServer"));
        goto cleanup;
    }
    VIR_INFO("Ham migration borrow numa response: %s", NULLSTR(resp));

    if (qemuHamGetBorrowInfo(hamInfo, ramInfo, resp) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to get borrow info"));
        goto cleanup;
    }

    VIR_DEBUG("Send ram info to domain on source for ham migration");
    if (qemuHamSendRamInfo(ramInfo, vm) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to send ram info to domain on source"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ddomain)
        virObjectUnref(ddomain);

    return ret;
}
