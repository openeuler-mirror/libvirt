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
 */

#include <config.h>

#include "viralloc.h"
#include "cpu.h"
#include "cpu_sw64.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CPU

static const virArch archs[] = { VIR_ARCH_SW_64 };

static int
virCPUsw64GetHost(virCPUDef *cpu G_GNUC_UNUSED,
                  virDomainCapsCPUModels *models G_GNUC_UNUSED)
{
    return 0;
}

static virCPUCompareResult
virCPUsw64Compare(virCPUDef *host G_GNUC_UNUSED,
                  virCPUDef *cpu G_GNUC_UNUSED,
                  bool failMessages G_GNUC_UNUSED)
{
    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPUsw64Update(virCPUDef *guest,
                 const virCPUDef *host G_GNUC_UNUSED,
                 bool relative G_GNUC_UNUSED)
{
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;

    return 0;
}

struct cpuArchDriver cpuDriverSW64 = {
    .name = "sw_64",
    .arch = archs,
    .narch = G_N_ELEMENTS(archs),
    .getHost = virCPUsw64GetHost,
    .compare = virCPUsw64Compare,
    .decode = NULL,
    .encode = NULL,
    .baseline = NULL,
    .update = virCPUsw64Update,
};
