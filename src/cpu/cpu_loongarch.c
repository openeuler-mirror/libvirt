/*
 * cpu_loongarch.c: CPU driver for 64-bit LOONGARCH CPUs
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "virlog.h"
#include "viralloc.h"
#include "cpu.h"
#include "virstring.h"
#include "cpu_map.h"
#include "virbuffer.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu_loongarch");

static const virArch archs[] = { VIR_ARCH_LOONGARCH64 };

typedef struct {
    char *name;
} LoongArch_vendor;

typedef struct {
    char *name;
    const LoongArch_vendor *vendor;
    virCPULoongArchData data;
} LoongArch_model;

typedef struct {
    size_t nvendors;
    LoongArch_vendor **vendors;
    size_t nmodels;
    LoongArch_model **models;
} LoongArch_map;

static void
LoongArchDataClear(virCPULoongArchData *data)
{
    if (!data)
        return;

    VIR_FREE(data->prid);
}

static int
LoongArchDataCopy(virCPULoongArchData *dst, const virCPULoongArchData *src)
{
    size_t i;

    if (VIR_ALLOC_N(dst->prid, src->len) < 0)
        return -1;

    dst->len = src->len;

    for (i = 0; i < src->len; i++) {
        dst->prid[i].value = src->prid[i].value;
        dst->prid[i].mask = src->prid[i].mask;
    }

    return 0;
}

static void
LoongArchVendorFree(LoongArch_vendor *vendor)
{
    if (!vendor)
        return;

    VIR_FREE(vendor->name);
    VIR_FREE(vendor);
}

static LoongArch_vendor *
LoongArchVendorFind(const LoongArch_map *map,
                    const char *name)
{
    size_t i;

    for (i = 0; i < map->nvendors; i++) {
        if (STREQ(map->vendors[i]->name, name))
            return map->vendors[i];
    }

    return NULL;
}

static void
LoongArchModelFree(LoongArch_model *model)
{
    if (!model)
        return;

    LoongArchDataClear(&model->data);
    VIR_FREE(model->name);
    VIR_FREE(model);
}

static LoongArch_model *
LoongArchModelCopy(const LoongArch_model *model)
{
    LoongArch_model *copy;

    if (VIR_ALLOC(copy) < 0)
        goto cleanup;

    copy->name = g_strdup(model->name);

    if (LoongArchDataCopy(&copy->data, &model->data) < 0)
        goto cleanup;

    copy->vendor = model->vendor;

    return copy;

 cleanup:
    LoongArchModelFree(copy);
    return NULL;
}

static LoongArch_model *
LoongArchModelFind(const LoongArch_map *map,
                   const char *name)
{
    size_t i;

    for (i = 0; i < map->nmodels; i++) {
        if (STREQ(map->models[i]->name, name))
            return map->models[i];
    }

    return NULL;
}

static LoongArch_model *
LoongArchModelFindPrid(const LoongArch_map *map,
                       uint32_t prid)
{
    size_t i;
    size_t j;

    for (i = 0; i < map->nmodels; i++) {
        LoongArch_model *model = map->models[i];
        for (j = 0; j < model->data.len; j++) {
            if ((prid & model->data.prid[j].mask) == model->data.prid[j].value)
                return model;
        }
    }

    return NULL;
}

static LoongArch_model *
LoongArchModelFromCPU(const virCPUDef *cpu,
                      const LoongArch_map *map)
{
    LoongArch_model *model;

    if (!cpu->model) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("no CPU model specified"));
        return NULL;
    }

    if (!(model = LoongArchModelFind(map, cpu->model))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU model %s"), cpu->model);
        return NULL;
    }

    return LoongArchModelCopy(model);
}

static void
LoongArchMapFree(LoongArch_map *map)
{
    size_t i;

    if (!map)
        return;

    for (i = 0; i < map->nmodels; i++)
        LoongArchModelFree(map->models[i]);
    VIR_FREE(map->models);

    for (i = 0; i < map->nvendors; i++)
        LoongArchVendorFree(map->vendors[i]);
    VIR_FREE(map->vendors);

    VIR_FREE(map);
}

static int
LoongArchVendorParse(xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                     const char *name,
                     void *data)
{
    LoongArch_map *map = data;
    LoongArch_vendor *vendor;
    int ret = -1;

    if (VIR_ALLOC(vendor) < 0)
        return ret;
    vendor->name = g_strdup(name);

    if (LoongArchVendorFind(map, vendor->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor %s already defined"), vendor->name);
        goto cleanup;
    }

    if (VIR_APPEND_ELEMENT(map->vendors, map->nvendors, vendor) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    LoongArchVendorFree(vendor);
    return ret;
}

static int
LoongArchModelParse(xmlXPathContextPtr ctxt,
                    const char *name,
                    void *data)
{
    LoongArch_map *map = data;
    LoongArch_model *model;
    xmlNodePtr *nodes = NULL;
    char *vendor = NULL;
    unsigned long prid;
    size_t i;
    int n;
    int ret = -1;

    if (VIR_ALLOC(model) < 0)
        goto cleanup;

    model->name = g_strdup(name);

    if (LoongArchModelFind(map, model->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %s already defined"), model->name);
        goto cleanup;
    }

    if (virXPathBoolean("boolean(./vendor)", ctxt)) {
        vendor = virXPathString("string(./vendor/@name)", ctxt);
        if (!vendor) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid vendor element in CPU model %s"),
                           model->name);
            goto cleanup;
        }

        if (!(model->vendor = LoongArchVendorFind(map, vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown vendor %s referenced by CPU model %s"),
                           vendor, model->name);
            goto cleanup;
        }
    }

    if ((n = virXPathNodeSet("./prid", ctxt, &nodes)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing Prid information for CPU model %s"),
                       model->name);
        goto cleanup;
    }

    if (VIR_ALLOC_N(model->data.prid, n) < 0)
        goto cleanup;

    model->data.len = n;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];

        if (virXPathULongHex("string(./@value)", ctxt, &prid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid Prid value in CPU model %s"),
                           model->name);
            goto cleanup;
        }
        model->data.prid[i].value = prid;

        if (virXPathULongHex("string(./@mask)", ctxt, &prid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid PVR mask in CPU model %s"),
                           model->name);
            goto cleanup;
        }
        model->data.prid[i].mask = prid;
    }

    if (VIR_APPEND_ELEMENT(map->models, map->nmodels, model) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    LoongArchModelFree(model);
    VIR_FREE(vendor);
    VIR_FREE(nodes);
    return ret;
}

static LoongArch_map *
LoongArchLoadMap(void)
{
    LoongArch_map *map;

    if (VIR_ALLOC(map) < 0)
        goto cleanup;

    if (cpuMapLoad("loongarch64", LoongArchVendorParse, NULL, LoongArchModelParse, map) < 0)
        goto cleanup;

    return map;

 cleanup:
    LoongArchMapFree(map);
    return NULL;
}

static virCPUDataPtr
LoongArchMakeCPUData(virArch arch,
                     virCPULoongArchData *data)
{
    virCPUDataPtr cpuData;

    if (VIR_ALLOC(cpuData) < 0)
        return NULL;

    cpuData->arch = arch;

    if (LoongArchDataCopy(&cpuData->data.loongarch, data) < 0)
        VIR_FREE(cpuData);

    return cpuData;
}

static virCPUCompareResult
LoongArchCompute(virCPUDefPtr host,
                 const virCPUDef *other,
                 virCPUDataPtr *guestData,
                 char **message)
{
    LoongArch_map *map = NULL;
    LoongArch_model *host_model = NULL;
    LoongArch_model *guest_model = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;
    virArch arch;
    size_t i;

    /* Ensure existing configurations are handled correctly */
    if (!(cpu = virCPUDefCopy(other)))
        goto cleanup;

    if (cpu->arch != VIR_ARCH_NONE) {
        bool found = false;

        for (i = 0; i < G_N_ELEMENTS(archs); i++) {
            if (archs[i] == cpu->arch) {
                found = true;
                break;
            }
        }

        if (!found) {
            VIR_DEBUG("CPU arch %s does not match host arch",
                      virArchToString(cpu->arch));
	    if (message) {
                *message = g_strdup_printf(_("CPU arch %s does not match host arch"),
                                             virArchToString(cpu->arch));
            }
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
            goto cleanup;
        }
        arch = cpu->arch;
    } else {
        arch = host->arch;
    }

    if (cpu->vendor &&
        (!host->vendor || STRNEQ(cpu->vendor, host->vendor))) {
        VIR_DEBUG("host CPU vendor does not match required CPU vendor %s",
                  cpu->vendor);
	if (message) {
            *message = g_strdup_printf(_("host CPU vendor does not match required "
                                         "CPU vendor %s"), cpu->vendor);
	}
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto cleanup;
    }

    if (!(map = LoongArchLoadMap()))
        goto cleanup;

    /* Host CPU information */
    if (!(host_model = LoongArchModelFromCPU(host, map)))
        goto cleanup;

    if (cpu->type == VIR_CPU_TYPE_GUEST) {
        /* Guest CPU information */
        switch (cpu->mode) {
        case VIR_CPU_MODE_HOST_MODEL:
        case VIR_CPU_MODE_HOST_PASSTHROUGH:
            /* host-model and host-passthrough:
             * the guest CPU is the same as the host */
            guest_model = LoongArchModelCopy(host_model);
            break;

        case VIR_CPU_MODE_CUSTOM:
            /* custom:
             * look up guest CPU information */
            guest_model = LoongArchModelFromCPU(cpu, map);
            break;
        }
    } else {
        /* Other host CPU information */
        guest_model = LoongArchModelFromCPU(cpu, map);
    }

    if (!guest_model)
        goto cleanup;

    if (STRNEQ(guest_model->name, host_model->name)) {
        VIR_DEBUG("host CPU model does not match required CPU model %s",
                  guest_model->name);
        if (message) {
            *message = g_strdup_printf(_("host CPU model does not match required "
                                         "CPU model %s"),guest_model->name);
	}
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto cleanup;
    }

    if (guestData)
        if (!(*guestData = LoongArchMakeCPUData(arch, &guest_model->data)))
            goto cleanup;

    ret = VIR_CPU_COMPARE_IDENTICAL;

 cleanup:
    virCPUDefFree(cpu);
    LoongArchMapFree(map);
    LoongArchModelFree(host_model);
    LoongArchModelFree(guest_model);
    return ret;
}

static virCPUCompareResult
virCPULoongArchCompare(virCPUDefPtr host,
                       virCPUDefPtr cpu,
                       bool failIncompatible)
{
    virCPUCompareResult ret;
    char *message = NULL;

    if (!host || !host->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("unknown host CPU"));
        } else {
            VIR_WARN("unknown host CPU");
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        }
        return -1;
    }

    ret = LoongArchCompute(host, cpu, NULL, &message);

    if (failIncompatible && ret == VIR_CPU_COMPARE_INCOMPATIBLE) {
        ret = VIR_CPU_COMPARE_ERROR;
        if (message) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s", message);
        } else {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, NULL);
        }
    }
    VIR_FREE(message);

    return ret;
}

static int
LoongArchDriverDecode(virCPUDefPtr cpu,
                      const virCPUData *data,
                      virDomainCapsCPUModelsPtr models)
{
    int ret = -1;
    LoongArch_map *map;
    const LoongArch_model *model;

    if (!data || !(map = LoongArchLoadMap()))
        return -1;

    if (!(model = LoongArchModelFindPrid(map, data->data.loongarch.prid[0].value))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Cannot find CPU model with Prid 0x%08x"),
                       data->data.loongarch.prid[0].value);
        goto cleanup;
    }

    if (!virCPUModelIsAllowed(model->name, models)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU model %s is not supported by hypervisor"),
                       model->name);
        goto cleanup;
    }

    cpu->model = g_strdup(model->name);
    if (model->vendor) {
        cpu->vendor = g_strdup(model->vendor->name);
    }
    ret = 0;

 cleanup:
    LoongArchMapFree(map);

    return ret;
}

static void
virCPULoongArchDataFree(virCPUDataPtr data)
{
    if (!data)
        return;

    LoongArchDataClear(&data->data.loongarch);
    VIR_FREE(data);
}

static int
virCPULoongArchGetHostPRID(void)
{
    return 0x14c010;
}

static int
virCPULoongArchGetHost(virCPUDefPtr cpu,
                       virDomainCapsCPUModelsPtr models)
{
    virCPUDataPtr cpuData = NULL;
    virCPULoongArchData *data;
    int ret = -1;

    if (!(cpuData = virCPUDataNew(archs[0])))
        goto cleanup;

    data = &cpuData->data.loongarch;
    if (VIR_ALLOC(data->prid) < 0)
        goto cleanup;


    data->len = 1;

    data->prid[0].value = virCPULoongArchGetHostPRID();
    data->prid[0].mask = 0xffff00ul;

    ret = LoongArchDriverDecode(cpu, cpuData, models);

 cleanup:
    virCPULoongArchDataFree(cpuData);
    return ret;
}


static int
virCPULoongArchUpdate(virCPUDefPtr guest,
                      const virCPUDef *host ATTRIBUTE_UNUSED)
{
    /*
     * - host-passthrough doesn't even get here
     * - host-model is used for host CPU running in a compatibility mode and
     *   it needs to remain unchanged
     * - custom doesn't support any optional features, there's nothing to
     *   update
     */

    if (guest->mode == VIR_CPU_MODE_CUSTOM)
        guest->match = VIR_CPU_MATCH_EXACT;

    return 0;
}

static virCPUDefPtr
LoongArchDriverBaseline(virCPUDefPtr *cpus,
                        unsigned int ncpus,
                        virDomainCapsCPUModelsPtr models ATTRIBUTE_UNUSED,
                        const char **features ATTRIBUTE_UNUSED,
                        bool migratable ATTRIBUTE_UNUSED)
{
    LoongArch_map *map;
    const LoongArch_model *model;
    const LoongArch_vendor *vendor = NULL;
    virCPUDefPtr cpu = NULL;
    size_t i;

    if (!(map = LoongArchLoadMap()))
        goto error;

    if (!(model = LoongArchModelFind(map, cpus[0]->model))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU model %s"), cpus[0]->model);
        goto error;
    }

    for (i = 0; i < ncpus; i++) {
        const LoongArch_vendor *vnd;

        if (STRNEQ(cpus[i]->model, model->name)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("CPUs are incompatible"));
            goto error;
        }

        if (!cpus[i]->vendor)
            continue;

        if (!(vnd = LoongArchVendorFind(map, cpus[i]->vendor))) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Unknown CPU vendor %s"), cpus[i]->vendor);
            goto error;
        }

        if (model->vendor) {
            if (model->vendor != vnd) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("CPU vendor %s of model %s differs from "
                                 "vendor %s"),
                               model->vendor->name, model->name,
                               vnd->name);
                goto error;
            }
        } else if (vendor) {
            if (vendor != vnd) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("CPU vendors do not match"));
                goto error;
            }
        } else {
            vendor = vnd;
        }
    }

    cpu = virCPUDefNew();
    cpu->model = g_strdup(model->name);
    if (vendor) {
        cpu->vendor = g_strdup(vendor->name);
    }
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_FORBID;

 cleanup:
    LoongArchMapFree(map);
    return cpu;

 error:
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}

static int
virCPULoongArchDriverGetModels(char ***models)
{
    LoongArch_map *map;
    size_t i;
    int ret = -1;

    if (!(map = LoongArchLoadMap())) {
        goto error;
    }

    if (models) {
        if (VIR_ALLOC_N(*models, map->nmodels + 1) < 0)
            goto error;

        for (i = 0; i < map->nmodels; i++) {
            (*models)[i] = g_strdup(map->models[i]->name);
        }
    }

    ret = map->nmodels;

 cleanup:
    LoongArchMapFree(map);
    return ret;

 error:
    if (models) {
        virStringListFree(*models);
        *models = NULL;
    }
    goto cleanup;
}

struct cpuArchDriver cpuDriverLoongArch = {
    .name       = "LoongArch",
    .arch       = archs,
    .narch      = G_N_ELEMENTS(archs),
    .compare    = virCPULoongArchCompare,
    .decode     = LoongArchDriverDecode,
    .encode     = NULL,
    .dataFree   = virCPULoongArchDataFree,
    .getHost    = virCPULoongArchGetHost,
    .baseline   = LoongArchDriverBaseline,
    .update     = virCPULoongArchUpdate,
    .getModels  = virCPULoongArchDriverGetModels,
};
