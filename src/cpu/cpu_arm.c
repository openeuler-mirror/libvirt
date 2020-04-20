/*
 * cpu_arm.c: CPU driver for arm CPUs
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) Canonical Ltd. 2012
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

#include "virlog.h"
#include "viralloc.h"
#include "cpu.h"
#include "cpu_map.h"
#include "virstring.h"
#include "virxml.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu_arm");

static const char *sysinfoCpuinfo = "/proc/cpuinfo";

#define CPUINFO sysinfoCpuinfo
#define CPUINFO_FILE_LEN (1024*1024)   /* 1MB limit for /proc/cpuinfo file */

static const virArch archs[] = {
    VIR_ARCH_ARMV6L,
    VIR_ARCH_ARMV7B,
    VIR_ARCH_ARMV7L,
    VIR_ARCH_AARCH64,
};

typedef struct _virCPUarmFeature virCPUarmFeature;
typedef virCPUarmFeature *virCPUarmFeaturePtr;
struct _virCPUarmFeature {
    char *name;
};

static virCPUarmFeaturePtr
virCPUarmFeatureNew(void)
{
    return g_new0(virCPUarmFeature, 1);
}

static void
virCPUarmFeatureFree(virCPUarmFeaturePtr feature)
{
    if (!feature)
        return;

    g_free(feature->name);
    g_free(feature);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmFeature, virCPUarmFeatureFree);

static void
virCPUarmDataClear(virCPUarmData *data)
{
    if (!data)
        return;

    g_free(data->features);
}

static void
virCPUarmDataFree(virCPUDataPtr cpuData)
{
    if (!cpuData)
        return;

    virCPUarmDataClear(&cpuData->data.arm);
    g_free(cpuData);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUData, virCPUarmDataFree);

typedef struct _virCPUarmVendor virCPUarmVendor;
typedef virCPUarmVendor *virCPUarmVendorPtr;
struct _virCPUarmVendor {
    char *name;
    unsigned long value;
};

static virCPUarmVendorPtr
virCPUarmVendorNew(void)
{
    return g_new0(virCPUarmVendor, 1);
}

static void
virCPUarmVendorFree(virCPUarmVendorPtr vendor)
{
    if (!vendor)
        return;

    g_free(vendor->name);
    VIR_FREE(vendor);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmVendor, virCPUarmVendorFree);

typedef struct _virCPUarmModel virCPUarmModel;
typedef virCPUarmModel *virCPUarmModelPtr;
struct _virCPUarmModel {
    char *name;
    virCPUarmVendorPtr vendor;
    virCPUarmData data;
};

static virCPUarmModelPtr
virCPUarmModelNew(void)
{
    return g_new0(virCPUarmModel, 1);
}

static void
virCPUarmModelFree(virCPUarmModelPtr model)
{
    if (!model)
        return;

    virCPUarmDataClear(&model->data);
    g_free(model->name);
    g_free(model);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmModel, virCPUarmModelFree);

typedef struct _virCPUarmMap virCPUarmMap;
typedef virCPUarmMap *virCPUarmMapPtr;
struct _virCPUarmMap {
    GPtrArray *vendors;
    GPtrArray *models;
    GPtrArray *features;
};

static virCPUarmMapPtr
virCPUarmMapNew(void)
{
    virCPUarmMapPtr map;

    map = g_new0(virCPUarmMap, 1);

    map->vendors = g_ptr_array_new();
    g_ptr_array_set_free_func(map->vendors,
                              (GDestroyNotify) virCPUarmVendorFree);

    map->models = g_ptr_array_new();
    g_ptr_array_set_free_func(map->models,
                              (GDestroyNotify) virCPUarmModelFree);

    map->features = g_ptr_array_new();
    g_ptr_array_set_free_func(map->features,
                              (GDestroyNotify) virCPUarmFeatureFree);

    return map;
}

static void
virCPUarmMapFree(virCPUarmMapPtr map)
{
    if (!map)
        return;

    g_ptr_array_free(map->vendors, TRUE);
    g_ptr_array_free(map->models, TRUE);
    g_ptr_array_free(map->features, TRUE);

    g_free(map);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmMap, virCPUarmMapFree);

static virCPUarmVendorPtr
virCPUarmVendorFindByID(virCPUarmMapPtr map,
                        unsigned long vendor_id)
{
    size_t i;

    for (i = 0; i < map->vendors->len; i++) {
        virCPUarmVendorPtr vendor = g_ptr_array_index(map->vendors, i);

        if (vendor->value == vendor_id)
            return vendor;
    }

    return NULL;
}

static virCPUarmVendorPtr
virCPUarmVendorFindByName(virCPUarmMapPtr map,
                          const char *name)
{
    size_t i;

    for (i = 0; i < map->vendors->len; i++) {
        virCPUarmVendorPtr vendor = g_ptr_array_index(map->vendors, i);

        if (STREQ(vendor->name, name))
            return vendor;
    }

    return NULL;
}

static virCPUarmFeaturePtr
virCPUarmMapFeatureFind(virCPUarmMapPtr map,
                        const char *name)
{
    size_t i;

    for (i = 0; i < map->features->len; i++) {
        virCPUarmFeaturePtr feature = g_ptr_array_index(map->features, i);

        if (STREQ(feature->name, name))
            return feature;
    }

    return NULL;
}

static int
virCPUarmMapFeatureParse(xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                         const char *name,
                         void *data)
{
    g_autoptr(virCPUarmFeature) feature = NULL;
    virCPUarmMapPtr map = data;

    if (virCPUarmMapFeatureFind(map, name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU feature %s already defined"), name);
        return -1;
    }

    feature = virCPUarmFeatureNew();
    feature->name = g_strdup(name);

    g_ptr_array_add(map->features, g_steal_pointer(&feature));

    return 0;
}

static int
armCpuDataParseFeatures(virCPUDefPtr cpu,
                        const virCPUarmData *cpuData)
{
    int ret = -1;
    size_t i;
    char **features;

    if (!cpu || !cpuData)
        return ret;

    if (!(features = virStringSplitCount(cpuData->features, " ",
                                         0, &cpu->nfeatures)))
        return ret;

    if (cpu->nfeatures) {
        if (VIR_ALLOC_N(cpu->features, cpu->nfeatures) < 0)
            goto error;

        for (i = 0; i < cpu->nfeatures; i++) {
            cpu->features[i].policy = VIR_CPU_FEATURE_REQUIRE;
            cpu->features[i].name = g_strdup(features[i]);
        }
    }

    ret = 0;

cleanup:
    virStringListFree(features);
    return ret;

error:
    for (i = 0; i < cpu->nfeatures; i++)
        VIR_FREE(cpu->features[i].name);
    VIR_FREE(cpu->features);
    cpu->nfeatures = 0;
    goto cleanup;
}

static int
virCPUarmVendorParse(xmlXPathContextPtr ctxt,
                     const char *name,
                     void *data)
{
    virCPUarmMapPtr map = (virCPUarmMapPtr)data;
    g_autoptr(virCPUarmVendor) vendor = NULL;

    if (virCPUarmVendorFindByName(map, name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor %s already defined"), name);
        return -1;
    }

    vendor = virCPUarmVendorNew();
    vendor->name = g_strdup(name);

    if (virXPathULongHex("string(@value)", ctxt, &vendor->value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU vendor value"));
        return -1;
    }

    if (virCPUarmVendorFindByID(map, vendor->value)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor value 0x%2lx already defined"), vendor->value);
        return -1;
    }

    g_ptr_array_add(map->vendors, g_steal_pointer(&vendor));

    return 0;
}

static virCPUarmModelPtr
virCPUarmModelFindByPVR(virCPUarmMapPtr map,
                        unsigned long pvr)
{
    size_t i;

    for (i = 0; i < map->models->len; i++) {
        virCPUarmModelPtr model = g_ptr_array_index(map->models, i);

        if (model->data.pvr == pvr)
            return model;
    }

    return NULL;

}

static virCPUarmModelPtr
virCPUarmModelFindByName(virCPUarmMapPtr map,
                         const char *name)
{
    size_t i;

    for (i = 0; i < map->models->len; i++) {
        virCPUarmModelPtr model = g_ptr_array_index(map->models, i);

        if (STREQ(model->name, name))
            return model;
    }

    return NULL;
}

static int
virCPUarmModelParse(xmlXPathContextPtr ctxt,
                    const char *name,
                    void *data)
{
    virCPUarmMapPtr map = (virCPUarmMapPtr)data;
    g_autoptr(virCPUarmModel) model = NULL;
    char *vendor = NULL;

    if (virCPUarmModelFindByName(map, name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %s already defined"), name);
        return -1;
    }

    model = virCPUarmModelNew();
    model->name = g_strdup(name);

    if (virXPathBoolean("boolean(./vendor)", ctxt)) {
        vendor = virXPathString("string(./vendor/@name)", ctxt);
        if (!vendor) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid vendor element in CPU model %s"),
                           name);
            return -1;
        }

        if (!(model->vendor = virCPUarmVendorFindByName(map, vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown vendor %s referenced by CPU model %s"),
                           vendor, model->name);
            return -1;
        }
    }

    if (!virXPathBoolean("boolean(./pvr)", ctxt)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing PVR information for CPU model %s"),
                       model->name);
        return -1;
    }

    if (virXPathULongHex("string(./pvr/@value)", ctxt, &model->data.pvr) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing or invalid PVR value in CPU model %s"),
                       model->name);
        return -1;
    }

    g_ptr_array_add(map->models, g_steal_pointer(&model));

    return 0;
}

static virCPUarmMapPtr
virCPUarmLoadMap(void)
{
    g_autoptr(virCPUarmMap) map = NULL;

    map = virCPUarmMapNew();

    if (cpuMapLoad("arm", virCPUarmVendorParse, virCPUarmMapFeatureParse, virCPUarmModelParse, map) < 0)
        return NULL;

    return g_steal_pointer(&map);
}

static virCPUarmMapPtr cpuMap;

int virCPUarmDriverOnceInit(void);
VIR_ONCE_GLOBAL_INIT(virCPUarmDriver);

int
virCPUarmDriverOnceInit(void)
{
    if (!(cpuMap = virCPUarmLoadMap()))
        return -1;

    return 0;
}

static virCPUarmMapPtr
virCPUarmGetMap(void)
{
    if (virCPUarmDriverInitialize() < 0)
        return NULL;

    return cpuMap;
}

static int
virCPUarmDecode(virCPUDefPtr cpu,
                const virCPUarmData *cpuData,
                virDomainCapsCPUModelsPtr models)
{
    virCPUarmMapPtr map;
    virCPUarmModelPtr model;
    virCPUarmVendorPtr vendor = NULL;

    if (!cpuData || !(map = virCPUarmGetMap()))
        return -1;

    if (!(model = virCPUarmModelFindByPVR(map, cpuData->pvr))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Cannot find CPU model with PVR 0x%03lx"),
                       cpuData->pvr);
        return -1;
    }

    if (!virCPUModelIsAllowed(model->name, models)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU model %s is not supported by hypervisor"),
                       model->name);
        return -1;
    }

    cpu->model = g_strdup(model->name);

    if (cpuData->vendor_id &&
        !(vendor = virCPUarmVendorFindByID(map, cpuData->vendor_id))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Cannot find CPU vendor with vendor id 0x%02lx"),
                       cpuData->vendor_id);
        return -1;
    }

    if (vendor)
        cpu->vendor = g_strdup(vendor->name);

    if (cpuData->features &&
        armCpuDataParseFeatures(cpu, cpuData) < 0)
        return -1;

    return 0;
}

static int
virCPUarmDecodeCPUData(virCPUDefPtr cpu,
                       const virCPUData *data,
                       virDomainCapsCPUModelsPtr models)
{
    return virCPUarmDecode(cpu, &data->data.arm, models);
}

static int
virCPUarmUpdate(virCPUDefPtr guest,
                const virCPUDef *host)
{
    int ret = -1;
    virCPUDefPtr updated = NULL;

    if (guest->mode != VIR_CPU_MODE_HOST_MODEL)
        return 0;

    if (!host) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown host CPU model"));
        goto cleanup;
    }

    if (!(updated = virCPUDefCopyWithoutModel(guest)))
        goto cleanup;

    updated->mode = VIR_CPU_MODE_CUSTOM;
    if (virCPUDefCopyModel(updated, host, true) < 0)
        goto cleanup;

    virCPUDefStealModel(guest, updated, false);
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;
    ret = 0;

cleanup:
    virCPUDefFree(updated);
    return ret;
}

static int
armCpuDataFromCpuInfo(virCPUarmData *data)
{
    g_autofree char *str_vendor = NULL;
    g_autofree char *str_pvr = NULL;
    g_autofree char *outbuf = NULL;
    char *eol = NULL;
    const char *cur;

    if (!data)
        return -1;

    if (virFileReadAll(CPUINFO, CPUINFO_FILE_LEN, &outbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), CPUINFO);
        return -1;
    }

    /* Account for format 'CPU implementer : XXXX' */
    if ((cur = strstr(outbuf, "CPU implementer")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("there is no \"CPU implementer\" info in %s"), CPUINFO);
        return -1;
    }

    cur = strchr(cur, ':') + 1;
    eol = strchr(cur, '\n');
    virSkipSpaces(&cur);
    if (!eol || !(str_vendor = g_strndup(cur, eol - cur)) ||
        virStrToLong_ul(str_vendor, NULL, 16, &data->vendor_id) < 0)
        return -1;

    /* Account for format 'CPU part : XXXX' */
    if ((cur = strstr(outbuf, "CPU part")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("there is no \"CPU part\" info in %s"), CPUINFO);
        return -1;
    }

    cur = strchr(cur, ':') + 1;
    eol = strchr(cur, '\n');
    virSkipSpaces(&cur);
    if (!eol || !(str_pvr = g_strndup(cur, eol - cur)) ||
        virStrToLong_ul(str_pvr, NULL, 16, &data->pvr) < 0)
        return -1;

    /* Account for format 'CPU Features : XXXX' */
    if ((cur = strstr(outbuf, "Features")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("there is no \"Features\" info in %s"), CPUINFO);
        return -1;
    }
    cur = strchr(cur, ':') + 1;
    eol = strchr(cur, '\n');
    virSkipSpaces(&cur);
    if (eol && !(data->features = g_strndup(cur, eol - cur)))
        return -1;

    return 0;
}

static int
virCPUarmGetHost(virCPUDefPtr cpu,
                 virDomainCapsCPUModelsPtr models)
{
    g_autoptr(virCPUData) cpuData = NULL;

    if (virCPUarmDriverInitialize() < 0)
        return -1;

    if (!(cpuData = virCPUDataNew(archs[0])))
        return -1;

    if (armCpuDataFromCpuInfo(&cpuData->data.arm) < 0)
        return -1;

    return virCPUarmDecodeCPUData(cpu, cpuData, models);
}

static void
virCPUarmDataIntersect(virCPUarmData *data1,
                       const virCPUarmData *data2)
{
    char **features = NULL;
    char **features1 = NULL;
    char **features2 = NULL;
    size_t count = 0;
    size_t i;

    if (!data1 || !data2)
        return;

    data1->pvr = MIN(data1->pvr, data2->pvr);

    if (virStringIsEmpty(data1->features) ||
        virStringIsEmpty(data2->features)) {
        VIR_FREE(data1->features);
        return;
    }

    if (STREQ_NULLABLE(data1->features, data2->features))
        return;

    if (!(features = virStringSplitCount(data1->features, " ", 0, &count)) ||
        !(features1 = virStringSplitCount(data1->features, " ", 0, &count)) ||
        !(features2 = virStringSplit(data2->features, " ", 0)))
        goto cleanup;

    for (i = 0; i < count; i++) {
        if (!virStringListHasString((const char**)features2, features1[i]))
            virStringListRemove(&features, features1[i]);
    }

    VIR_FREE(data1->features);
    if (features)
        data1->features = virStringListJoin((const char**)features, " ");

cleanup:
    virStringListFree(features);
    virStringListFree(features1);
    virStringListFree(features2);
    return;
}

static void
virCPUarmDataCopy(virCPUarmData *dst, const virCPUarmData *src)
{
    dst->features = g_strdup(src->features);
    dst->vendor_id = src->vendor_id;
    dst->pvr = src->pvr;
}

static virCPUarmModelPtr
virCPUarmModelCopy(virCPUarmModelPtr model)
{
    g_autoptr(virCPUarmModel) copy = NULL;

    copy = virCPUarmModelNew();

    virCPUarmDataCopy(&copy->data, &model->data);
    copy->name = g_strdup(model->name);
    copy->vendor = model->vendor;

    return g_steal_pointer(&copy);
}

static virCPUarmModelPtr
virCPUarmModelFromCPU(const virCPUDef *cpu,
                      virCPUarmMapPtr map)
{
    g_autoptr(virCPUarmModel) model = NULL;
    virCPUarmVendorPtr vendor = NULL;
    char **features = NULL;
    size_t i;

    if (!cpu->model) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("no CPU model specified"));
        return NULL;
    }

    if (!(model = virCPUarmModelFindByName(map, cpu->model))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU model %s"), cpu->model);
        return NULL;
    }

    if (!(model = virCPUarmModelCopy(model)))
        return NULL;

    if (cpu->vendor) {
        if (!(vendor = virCPUarmVendorFindByName(map, cpu->vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU vendor %s"), cpu->vendor);
            return NULL;
        }
        model->data.vendor_id = vendor->value;
    }

    if (cpu->nfeatures) {
        if (VIR_REALLOC_N(features, cpu->nfeatures + 1) < 0)
            return model;

        features[cpu->nfeatures] = NULL;
        for (i = 0; i < cpu->nfeatures; i++)
            features[i] = g_strdup(cpu->features[i].name);
        VIR_FREE(model->data.features);
        model->data.features = virStringListJoin((const char **)features, " ");
    }

    virStringListFree(features);
    return g_steal_pointer(&model);
}

static virCPUDefPtr
virCPUarmBaseline(virCPUDefPtr *cpus,
                  unsigned int ncpus,
                  virDomainCapsCPUModelsPtr models,
                  const char **features G_GNUC_UNUSED,
                  bool migratable G_GNUC_UNUSED)
{
    virCPUarmMapPtr map = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    g_autoptr(virCPUarmModel) model = NULL;
    g_autoptr(virCPUarmModel) baseModel = NULL;
    virCPUarmVendorPtr vendor = NULL;
    bool outputVendor = true;
    size_t i;

    cpu = virCPUDefNew();

    cpu->model = g_strdup(cpus[0]->model);

    cpu->arch = cpus[0]->arch;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_FORBID;

    if (!(map = virCPUarmGetMap()))
        return NULL;

    if (!(baseModel = virCPUarmModelFromCPU(cpus[0], map)))
        return NULL;

    if (!cpus[0]->vendor) {
        outputVendor = false;
    } else if (!(vendor = virCPUarmVendorFindByName(map, cpus[0]->vendor))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unknown CPU vendor %s"), cpus[0]->vendor);
        return NULL;
    }

    for (i = 0; i < ncpus; i++) {
        const char *vn = NULL;
        if (!(model = virCPUarmModelFromCPU(cpus[i], map)))
            return NULL;

        if (cpus[i]->vendor) {
            vn = cpus[i]->vendor;
        } else {
            outputVendor = false;
        }

        if (vn) {
            if (!vendor) {
                if (!(vendor = virCPUarmVendorFindByName(map, vn))) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("Unknown CPU vendor %s"), vn);
                    return NULL;
                }
            } else if (STRNEQ(vendor->name, vn)) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("CPU vendors do not match"));
                return NULL;
            }

            virCPUarmDataIntersect(&baseModel->data, &model->data);
        }
    }

    if (virCPUarmDecode(cpu, &baseModel->data, models) < 0)
        return NULL;

    if (!outputVendor)
        g_free(cpu->vendor);

    return g_steal_pointer(&cpu);
}

static bool
virCPUarmFeaturesIsSub(char *subFeatures,
                       char *fullFeatures)
{
    bool ret = false;
    char **sub = NULL;
    char **full = NULL;
    size_t subCount = 0;
    size_t fullCount = 0;
    size_t i;

    if (virStringIsEmpty(subFeatures))
        return true;

    if (virStringIsEmpty(fullFeatures))
        return ret;

    if (STREQ(subFeatures, fullFeatures))
        return true;

    if (!(sub = virStringSplitCount(subFeatures, " ", 0, &subCount)) ||
        !(full = virStringSplitCount(fullFeatures, " ", 0, &fullCount)) ||
        subCount > fullCount)
        goto cleanup;

    for (i = 0; i < subCount; i++) {
        if (!virStringListHasString((const char**)full, sub[i]))
            goto cleanup;
    }

    ret = true;

 cleanup:
    virStringListFree(sub);
    virStringListFree(full);
    return ret;
}

static virCPUDataPtr
armMakeCPUData(virArch arch,
               virCPUarmData *data)
{
    virCPUDataPtr cpuData;

    if (!(cpuData = virCPUDataNew(arch)))
        return NULL;

    virCPUarmDataCopy(&cpuData->data.arm, data);

    return cpuData;
}

static virCPUCompareResult
armCompute(virCPUDefPtr host,
           virCPUDefPtr cpu,
           virCPUDataPtr *guestData,
           char **message)
{
    virCPUarmMapPtr map = NULL;
    g_autoptr(virCPUarmModel) hostModel = NULL;
    g_autoptr(virCPUarmModel) guestModel = NULL;
    virArch arch;
    size_t i;

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
            if (message)
                *message = g_strdup_printf(_("CPU arch %s does not match host arch"),
                                           virArchToString(cpu->arch));

            return VIR_CPU_COMPARE_INCOMPATIBLE;
        }
        arch = cpu->arch;
    } else {
        arch = host->arch;
    }

    if (cpu->vendor &&
        (!host->vendor || STRNEQ(cpu->vendor, host->vendor))) {
        VIR_DEBUG("host CPU vendor does not match required CPU vendor %s",
                  cpu->vendor);
        if (message)
            *message = g_strdup_printf(_("host CPU vendor does not match required "
                                       "CPU vendor %s"),
                        cpu->vendor);

        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    if (!(map = virCPUarmGetMap()))
        return VIR_CPU_COMPARE_ERROR;

    /* Host CPU information */
    if (!(hostModel = virCPUarmModelFromCPU(host, map)))
        return VIR_CPU_COMPARE_ERROR;

    if (cpu->type == VIR_CPU_TYPE_GUEST) {
        /* Guest CPU information */
        switch (cpu->mode) {
            case VIR_CPU_MODE_HOST_MODEL:
            case VIR_CPU_MODE_HOST_PASSTHROUGH:
                /* host-model and host-passthrough:
                 * the guest CPU is the same as the host */
                guestModel = virCPUarmModelCopy(hostModel);
                break;

            case VIR_CPU_MODE_CUSTOM:
                /* custom:
                 * look up guest CPU information */
                guestModel = virCPUarmModelFromCPU(cpu, map);
                break;
        }
    } else {
        /* Other host CPU information */
        guestModel = virCPUarmModelFromCPU(cpu, map);
    }

    if (!guestModel)
        return VIR_CPU_COMPARE_ERROR;

    if (STRNEQ(guestModel->name, hostModel->name)) {
        VIR_DEBUG("host CPU model %s does not match required CPU model %s",
                  hostModel->name, guestModel->name);
        if (message)
            *message = g_strdup_printf(_("host CPU model %s does not match required "
                                       "CPU model %s"),
                                       hostModel->name, guestModel->name);

        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    if (!virCPUarmFeaturesIsSub(guestModel->data.features, hostModel->data.features)) {
        VIR_DEBUG("guest CPU features '%s' is not subset of "
                  "host CPU features '%s'",
                  guestModel->data.features, hostModel->data.features);
        if (message)
            *message = g_strdup_printf(_("guest CPU features '%s' is not subset of "
                                       "host CPU features '%s'"),
                                       guestModel->data.features,
                                       hostModel->data.features);

        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    if (guestData &&
        !(*guestData = armMakeCPUData(arch, &guestModel->data)))
        return VIR_CPU_COMPARE_ERROR;

    return VIR_CPU_COMPARE_IDENTICAL;
}

static virCPUCompareResult
virCPUarmCompare(virCPUDefPtr host,
                 virCPUDefPtr cpu,
                 bool failMessages)
{
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;
    g_autofree char *message = NULL;

    if (!host || !host->model) {
        if (failMessages) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("unknown host CPU"));
        } else {
            VIR_WARN("unknown host CPU");
            return VIR_CPU_COMPARE_INCOMPATIBLE;
        }
        return VIR_CPU_COMPARE_ERROR;
    }

    ret = armCompute(host, cpu, NULL, &message);

    if (failMessages && ret == VIR_CPU_COMPARE_INCOMPATIBLE) {
        if (message) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s", message);
        } else {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, NULL);
        }
        return VIR_CPU_COMPARE_ERROR;
    }

    return ret;
}

static int
virCPUarmValidateFeatures(virCPUDefPtr cpu)
{
    virCPUarmMapPtr map;
    size_t i;

    if (!(map = virCPUarmGetMap()))
        return -1;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUFeatureDefPtr feature = &cpu->features[i];

        if (!virCPUarmMapFeatureFind(map, feature->name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown CPU feature: %s"),
                           feature->name);
            return -1;
        }
    }

    return 0;
}

struct cpuArchDriver cpuDriverArm = {
    .name = "arm",
    .arch = archs,
    .narch = G_N_ELEMENTS(archs),
    .compare = virCPUarmCompare,
    .decode = virCPUarmDecodeCPUData,
    .encode = NULL,
    .dataFree = virCPUarmDataFree,
    .getHost = virCPUarmGetHost,
    .baseline = virCPUarmBaseline,
    .update = virCPUarmUpdate,
    .validateFeatures = virCPUarmValidateFeatures,
};
