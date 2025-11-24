/*
 * qemu_ham.h: QEMU ham migration handling
 *
 * Copyright (C) 2025 Huawei Technologies Co., Ltd
 */

#ifndef QEMU_HAM_H
#define QEMU_HAM_H

#include "virconftypes.h"
#include "virdomainjob.h"
#include "virham.h"

typedef struct _qemuHamMigrationInfo qemuHamMigrationInfo;
struct _qemuHamMigrationInfo {
    char *name;
    char *srcHostname;
    char *dstHostname;
    int srcPid;
    int dstPid;
};

void qemuHamMigrationInfoFree(qemuHamMigrationInfo *hamInfo);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuHamMigrationInfo, qemuHamMigrationInfoFree);

int qemuDomainSendQemuMonitorCommand(virDomainObj *vm,
                                          const char *cmd,
                                          char **result,
                                          virDomainAsyncJob asyncJob);

int qemuHamMigrationPrepare(qemuHamMigrationInfo *hamInfo,
                            virConnectPtr dconn,
                            virDomainObj *vm,
                            char *cookieout,
                            int cookieoutlen);

int qemuHamModifyPgtable(virDomainObj *vm);

int qemuHamRollbackPages(virDomainObj *vm);

void qemuHamSendClearReq(qemuHamMigrationInfo *hamInfo, virHamClearType type);

#endif
