/*
 * cpu_loongarch_data.h: 64-bit LOONGARCH CPU specific data
 *
 * Copyright (C) 2023 Loongson Technology.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __VIR_CPU_LOONGARCH_DATA_H__
# define __VIR_CPU_LOONGARCH_DATA_H__

# include <stdint.h>

typedef struct _virCPULoongArchPrid virCPULoongArchPrid;
struct _virCPULoongArchPrid {
    uint32_t value;
    uint32_t mask;
};

# define VIR_CPU_LOONGARCH_DATA_INIT { 0 }

typedef struct _virCPULoongArchData virCPULoongArchData;
struct _virCPULoongArchData {
    size_t len;
    virCPULoongArchPrid *prid;
};

#endif /* __VIR_CPU_MIPS64_DATA_H__ */
