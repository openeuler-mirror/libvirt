/*
 * huawei_stratovirt_process.h: huawei stratovirt process functions
 * Manage process
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

#include "stratovirt_domain.h"
#include "qemu_process.h"

typedef qemuDomainAsyncJob stratovirtDomainAsyncJob;
typedef qemuDomainJob stratovirtDomainJob;

typedef struct StratoVirtProcess {
    void (*stratovirtProcessReconnectAll)(virStratoVirtDriverPtr driver);
    int (*stratovirtProcessBeginJob)(virStratoVirtDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainJobOperation operation,
                                     unsigned long apiFlags);
    int (*stratovirtProcessStart)(virConnectPtr conn,
                                  virStratoVirtDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virCPUDefPtr updatedCPU,
                                  stratovirtDomainAsyncJob asyncJob,
                                  const char *migrateFrom,
                                  int migrateFd,
                                  const char *migratePath,
                                  virDomainMomentObjPtr snapshot,
                                  virNetDevVPortProfileOp vmop,
                                  unsigned int flags);
    void (*stratovirtProcessEndJob)(virStratoVirtDriverPtr driver,
                                    virDomainObjPtr vm);
    int (*stratovirtProcessBeginStopJob)(virStratoVirtDriverPtr driver,
                                         virDomainObjPtr vm,
                                         stratovirtDomainJob job,
                                         bool forcekill);
    void (*stratovirtProcessStop)(virStratoVirtDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virDomainShutoffReason reason,
                                  stratovirtDomainAsyncJob asyncjob,
                                  unsigned int flags);
    int (*stratovirtProcessStopCPUs)(virStratoVirtDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainPausedReason reason,
                                     stratovirtDomainAsyncJob asyncJob);
    int (*stratovirtProcessStartCPUs)(virStratoVirtDriverPtr driver,
                                      virDomainObjPtr vm,
                                      virDomainRunningReason reason,
                                      stratovirtDomainAsyncJob asyncJob);
} virStratoVirtProcess;

extern virStratoVirtProcess stratovirtPro;
