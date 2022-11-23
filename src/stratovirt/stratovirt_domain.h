/*
 * huawei_stratovirt_domain.h: huawei stratovirt domain functions
 * Manage domain state.
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

#include "stratovirt_conf.h"

#include "qemu_hotplug.h"
#include "qemu_checkpoint.h"

typedef enum {
    STRATOVIRT_PROCESS_EVENT_WATCHDOG = 0,
    STRATOVIRT_PROCESS_EVENT_GUESTPANIC,
    STRATOVIRT_PROCESS_EVENT_DEVICE_DELETED,
    STRATOVIRT_PROCESS_EVENT_NIC_RX_FILTER_CHANGED,
    STRATOVIRT_PROCESS_EVENT_SERIAL_CHANGED,
    STRATOVIRT_PROCESS_EVENT_BLOCK_JOB,
    STRATOVIRT_PROCESS_EVENT_JOB_STATUS_CHANGE,
    STRATOVIRT_PROCESS_EVENT_MONITOR_EOF,
    STRATOVIRT_PROCESS_EVENT_PR_DISCONNECT,
    STRATOVIRT_PROCESS_EVENT_RDMA_GID_STATUS_CHANGED,
    STRATOVIRT_PROCESS_EVENT_GUEST_CRASHLOADED,

    STRATOVIRT_PROCESS_EVENT_LAST
} stratovirtProcessEventType;

typedef struct _stratovirtProcessEvent stratovirtProcessEvent;
typedef stratovirtProcessEvent *stratovirtProcessEventPtr;
typedef qemuDomainNamespace stratovirtDomainNamespace;
typedef qemuDomainJob stratovirtDomainJob;

void stratovirtProcessEventFree(stratovirtProcessEventPtr event);

struct _stratovirtProcessEvent {
    virDomainObjPtr vm;
    stratovirtProcessEventType eventType;
    int action;
    int status;
    void *data;
};

extern virDomainDefParserConfig virStratoVirtDriverDomainDefParserConfig;

typedef qemuDomainObjPrivate stratovirtDomainObjPrivate;
typedef stratovirtDomainObjPrivate *stratovirtDomainObjPrivatePtr;

virDomainObjPtr stratovirtDomainObjFromDomain(virDomainPtr domain);
void stratovirtDomainUpdateCurrentMemorySize(virDomainObjPtr vm);

typedef struct StratoVirtDomain {
    bool (*stratovirtDomainNamespaceAvailable)(stratovirtDomainNamespace ns G_GNUC_UNUSED);
    void (*stratovirtDomainRemoveInactive)(virStratoVirtDriverPtr driver,
                                           virDomainObjPtr vm);
    void (*stratovirtDomainObjEndJob)(virStratoVirtDriverPtr driver,
                                      virDomainObjPtr obj);
    int (*stratovirtDomainObjBeginJob)(virStratoVirtDriverPtr driver,
                                       virDomainObjPtr obj,
                                       stratovirtDomainJob job);
    void (*stratovirtDomainObjEnterMonitor)(virStratoVirtDriverPtr driver,
                                            virDomainObjPtr obj);
    int (*stratovirtDomainObjExitMonitor)(virStratoVirtDriverPtr driver,
                                          virDomainObjPtr obj);
    int (*stratovirtDomainSnapshotDiscardAllMetadata)(virStratoVirtDriverPtr driver,
                                                     virDomainObjPtr vm);
    int (*stratovirtDomainCheckpointDiscardAllMetadata)(virStratoVirtDriverPtr driver,
                                                       virDomainObjPtr vm);
    int (*stratovirtDomainAssignAddresses)(virDomainDefPtr def,
                                           virStratoVirtCapsPtr stratovirtCaps,
					   virStratoVirtDriverPtr driver,
					   virDomainObjPtr obj,
					   bool newDomain);
} virStratoVirtDomain;

extern virStratoVirtDomain stratovirtDom;
