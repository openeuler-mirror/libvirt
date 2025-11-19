/*
 * virham.c: rack ipc functions for ham migration
 *
 * Copyright (C) 2025 Huawei Technologies Co., Ltd
 */

#include <dlfcn.h>

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virham.h"
#include "virjson.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.ham");

/* rack ipc path for ham migration */
#define VIR_HAM_RACK_IPC_PATH "/usr/local/softbus/ctrlbus/lib/librack_com.so"

static unsigned long long virHamCancelledTimeout = VIR_HAM_CANCELLED_TIMEOUT;
static uint16_t virHamRackIpcTimeout = VIR_HAM_RACK_IPC_TIMEOUT;

typedef int (*virHamRackIpcClientStart)(uint16_t timeout);

typedef struct _virHamRackIpcData virHamRackIpcData;
struct _virHamRackIpcData {
    uint8_t *buffer;
    uint32_t length;
};

typedef int (*virHamRackIpcSyncSend)(virHamRackIpcData *sendData, virHamRackIpcData *recvData);

typedef void (*virHamRackIpcCallback)(void *ctx,
                                      void *recv,
                                      uint32_t len,
                                      int32_t result);

typedef struct _virHamRackIpcCallbackDef virHamRackIpcCallbackDef;
struct _virHamRackIpcCallbackDef {
    virHamRackIpcCallback cb;
    void *cbCtx;
};

typedef int (*virHamRackIpcAsyncSend)(virHamRackIpcData *sendData, virHamRackIpcCallbackDef *callback);

typedef struct _virHamRackIpcClient virHamRackIpcClient;
struct _virHamRackIpcClient {
    virHamRackIpcClientStart start;
    virHamRackIpcSyncSend syncSend;
    virHamRackIpcAsyncSend asyncSend;
};

static virHamRackIpcClient *rackIpcClient;

static void
virHamRackIpcDataFree(virHamRackIpcData *data)
{
    if (!data)
        return;

    VIR_FREE(data->buffer);
    VIR_FREE(data);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virHamRackIpcData, virHamRackIpcDataFree);

static int
virHamRackIpcInitialize(void)
{
    void *handle = NULL;
    int code;

    if (!virFileExists(VIR_HAM_RACK_IPC_PATH)) {
        VIR_WARN("Ham rack ipc file doesn't exist");
        return -1;
    }

    if (!(handle = dlopen(VIR_HAM_RACK_IPC_PATH, RTLD_NOW | RTLD_LOCAL))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to load rack ipc file: %1$s"), dlerror());
        return -1;
    }

    rackIpcClient = g_new0(virHamRackIpcClient, 1);

    if (!(rackIpcClient->start = dlsym(handle, "RackStartIpcClientWithTimeout"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find symbol 'RackStartIpcClientWithTimeout': %1$s"), dlerror());
        goto error;
    }

    if (!(rackIpcClient->syncSend = dlsym(handle, "RackSyncSendForHam"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find symbol 'RackSyncSendForHam': %1$s"), dlerror());
        goto error;
    }

    if (!(rackIpcClient->asyncSend = dlsym(handle, "RackAsyncSendForHam"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to find symbol 'RackAsyncSendForHam': %1$s"), dlerror());
        goto error;
    }

    if ((code = rackIpcClient->start(virHamRackIpcTimeout)) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to start RackIpcClient with code %1$d"), code);
        goto error;
    }

    return 0;

 error:
    dlclose(handle);
    VIR_FREE(rackIpcClient);
    return -1;
}

char *
virHamRackIpcSyncSendAndRecv(const char *req)
{
    g_autoptr(virHamRackIpcData) sendData = g_new0(virHamRackIpcData, 1);
    g_autoptr(virHamRackIpcData) recvData = g_new0(virHamRackIpcData, 1);
    int code;
    g_autofree char *resp = NULL;

    if (!rackIpcClient && virHamRackIpcInitialize() < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to initialize RackIpcClient"));
        return NULL;
    }

    sendData->length = strlen(req);
    sendData->buffer = g_malloc0(sendData->length);
    memcpy(sendData->buffer, req, sendData->length);

    if ((code = rackIpcClient->syncSend(sendData, recvData)) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to communicate with RackAgentIpcServer with code %1$d"), code);
        return NULL;
    }

    if (!(resp = g_new0(char, recvData->length + 1))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to allocate memory of the length %1$u"), recvData->length);
        return NULL;
    }

    memcpy(resp, recvData->buffer, recvData->length);
    /* MatrixVirt returned length does not include the string terminator */
    resp[recvData->length] = '\0';

    return g_steal_pointer(&resp);
}

char *
virHamGetClearReqInit(virHamClearType type, const char *hostname)
{
    g_autoptr(virJSONValue) clearReq = virJSONValueNewObject();

    if (virJSONValueObjectAppendString(clearReq, "action", "clear") < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add action to clear request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendNumberInt(clearReq, "type", type) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add type to clear request json object"));
        return NULL;
    }

    if (virJSONValueObjectAppendString(clearReq, "srcHostname", hostname) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to add srcHostname to clear request json object"));
        return NULL;
    }

    return virJSONValueToString(clearReq, false);
}

static int
virHamRackIpcAsyncSendAndRecv(const char *req, virHamRackIpcCallbackDef *callback)
{
    g_autoptr(virHamRackIpcData) sendData = g_new0(virHamRackIpcData, 1);
    int code;

    if (!rackIpcClient && virHamRackIpcInitialize() < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to initialize RackIpcClient"));
        return -1;
    }

    sendData->length = strlen(req);
    sendData->buffer = g_malloc0(sendData->length);
    memcpy(sendData->buffer, req, sendData->length);

    if ((code = rackIpcClient->asyncSend(sendData, callback)) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to send request to RackAgentIpcServer with code %1$d"), code);
        return -1;
    }

    return 0;
}

void
virHamClearAll(const char *hostname)
{
    g_autofree char *req = NULL;
    virHamRackIpcCallbackDef *callback = g_new0(virHamRackIpcCallbackDef, 1);

    if (!(req = virHamGetClearReqInit(VIR_HAM_CLEAR_ALL, hostname))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create clear request"));
        return;
    }
    VIR_INFO("Ham migration clear all borrowed numa nodes request: %s", NULLSTR(req));

    if (virHamRackIpcAsyncSendAndRecv(req, callback) < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to clear all borrowed numa nodes"));
}

void
virHamSetupTimeOut(unsigned long long cancelledTimeout, uint16_t rackIpcTimeout){
    virHamCancelledTimeout = cancelledTimeout;
    virHamRackIpcTimeout = rackIpcTimeout;
}

unsigned long long
virHamGetCancelledTimeout(void){
    return virHamCancelledTimeout * 1000;
}
