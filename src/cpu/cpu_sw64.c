/*
 * cpu_sw64.c: CPU driver for sw64 CPUs
 *
 * Copyright (C) 2021 Lu Feifei
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
 * Authors:
 *      Lu Feifei <lufeifei@wxiat.com>
 */

#include <config.h>

#include "viralloc.h"
#include "cpu.h"
#include "cpu_sw64.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CPU
#define ARRAY_CARDINALITY(Array) (sizeof(Array) / sizeof(*(Array)))

static const virArch archs[] = { VIR_ARCH_SW_64 };

static int
virCPUsw64GetHost(virCPUDefPtr cpu ATTRIBUTE_UNUSED,
                  virDomainCapsCPUModelsPtr models ATTRIBUTE_UNUSED)
{
    return 0;
}

static virCPUCompareResult
virCPUsw64Compare(virCPUDefPtr host ATTRIBUTE_UNUSED,
                  virCPUDefPtr cpu ATTRIBUTE_UNUSED,
                  bool failMessages ATTRIBUTE_UNUSED)
{
    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPUsw64Update(virCPUDefPtr guest,
                 const virCPUDef *host ATTRIBUTE_UNUSED)
{
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;

    return 0;
}

struct cpuArchDriver cpuDriverSW64 = {
    .name = "sw_64",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .getHost = virCPUsw64GetHost,
    .compare = virCPUsw64Compare,
    .decode = NULL,
    .encode = NULL,
    .baseline = NULL,
    .update = virCPUsw64Update,
};
