/*
 * huawei_stratovirt_process.c: huawei stratovirt process functions
 * Manage process.
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

#include "stratovirt_process.h"

#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_STRATOVIRT

VIR_LOG_INIT("stratovirt.stratovirt_process");

virStratoVirtProcess stratovirtPro = {
    .stratovirtProcessReconnectAll = qemuProcessReconnectAll,
    .stratovirtProcessBeginJob = qemuProcessBeginJob,
    .stratovirtProcessStart = qemuProcessStart,
    .stratovirtProcessEndJob = qemuProcessEndJob,
    .stratovirtProcessBeginStopJob = qemuProcessBeginStopJob,
    .stratovirtProcessStop = qemuProcessStop,
    .stratovirtProcessStopCPUs = qemuProcessStopCPUs,
    .stratovirtProcessStartCPUs = qemuProcessStartCPUs,
};