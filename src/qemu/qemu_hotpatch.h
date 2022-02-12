/*
 * huawei_qemu_hotpatch.h: huawei qemu hotpatch functions
 *
 * Copyright (C) 2021-2021 HUAWEI, Inc.
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

#include <unistd.h>
#include "qemu/qemu_conf.h"

char *
qemuDomainHotpatchQuery(virDomainObjPtr vm);

char *
qemuDomainHotpatchApply(virDomainObjPtr vm,
                        const char *patch);

char *
qemuDomainHotpatchUnapply(virDomainObjPtr vm,
                          const char *id);

char *
qemuDomainHotpatchAutoload(virDomainObjPtr vm, char *path_config);
