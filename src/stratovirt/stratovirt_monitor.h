/*
 * huawei_stratovirt_monitor.h: huawei stratovirt monitor functions
 * interaction with stratovirt monitor console.
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

#include "internal.h"

#include "qemu_monitor.h"

typedef qemuMonitor stratovirtMonitor;
typedef stratovirtMonitor *stratovirtMonitorPtr;

typedef struct StratoVirtMonitor {
    int (*stratovirtMonitorSystemPowerdown)(stratovirtMonitorPtr mon);
} virStratoVirtMonitor;

extern virStratoVirtMonitor stratovirtMon;