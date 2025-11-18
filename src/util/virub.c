/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2024. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include "virlog.h"
#include "virerror.h"
#include "virub.h"
#include "virfile.h"

VIR_LOG_INIT("util.ub");

#define VIR_FROM_THIS VIR_FROM_NONE

int virUBDeviceGetGuidFromStr(UBGuid *guid, char *guidStr)
{
    unsigned long seqNum;
    unsigned int deviceId;
    unsigned int version;
    unsigned int type;
    unsigned int vendorId;
    unsigned int rsv;
    int ret;

    if (strlen(guidStr) != UB_DEV_GUID_STRING_LENGTH) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expect guid len is %d, but current guid len is %ld\n",
                       UB_DEV_GUID_STRING_LENGTH, strlen(guidStr));
        return -1;
    }

    ret = sscanf(guidStr, "%04x-%04x-%01x-%01x-%06x-%016lx",
                 &vendorId, &deviceId, &version, &type, &rsv, &seqNum);
    if (ret != UB_GUID_ELEMENT_NUM) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "guid(%s) format is incorrect, example: " GUID_STR_EXAMPLE "\n", guidStr);
        return -1;
    }
    guid->vendorId = vendorId & 0x0000FFFF;
    guid->type = type & 0x0F;
    guid->version = version & 0x0F;
    guid->deviceId = deviceId & 0xFFFF;
    guid->rsv = rsv & 0xFFFFFF;
    guid->seqNum = seqNum & 0xFFFFFFFFFFFFFFFF;

    return 0;
}

#define MAX_BUF_LENGTH 256
static uint32_t
virUBDeviceSysfsGetDevnumByGuid(char *guidStr)
{
    uint32_t id = UINT32_MAX;
    const char *ub_sysfs_devices = "/sys/bus/ub/devices";
    struct dirent *entry;
    DIR *dir = NULL;

    dir = opendir(ub_sysfs_devices);
    if (!dir) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("failed to opendir %s\n"), ub_sysfs_devices);
        return UINT32_MAX;
    }

    while ((entry = readdir(dir)) != NULL) {
        char file_path[MAX_BUF_LENGTH] = {0};   /* guid file path */
        char guid_buffer[MAX_BUF_LENGTH] = {0}; /* guid that read from file */
        FILE *file = NULL;
        size_t bytes_read;

        /* skip the stumbling blocks */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        snprintf(file_path, sizeof(file_path), "%s/%s/guid",
                 ub_sysfs_devices, entry->d_name);
        file = fopen(file_path, "r");
        if (file == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("failed to open %s\n"), file_path);
            closedir(dir);
            return UINT32_MAX;
        }

        bytes_read = fread(guid_buffer, 1, MAX_BUF_LENGTH - 1, file);
        fclose(file);
        guid_buffer[bytes_read] = '\0';
        /* discard annoying line breaks */
        if (bytes_read > 0 && guid_buffer[bytes_read - 1] == '\n') {
            guid_buffer[bytes_read - 1] = '\0';
        }

        /* check if it's a long-awaited true love */
        if (strcmp(guid_buffer, guidStr) == 0) {
            sscanf(entry->d_name, "%x", &id);
            closedir(dir);
            return id;
        }
    }
    closedir(dir);
    return id;
}

char *
virUBDeviceAddressGetIOMMUGroupDev(virUBDeviceAddress *addr)
{
    unsigned int devNum;
    g_autofree char *devPath = NULL;
    g_autofree char *groupPath = NULL;
    g_autofree char *groupFile = NULL;

    devNum = virUBDeviceSysfsGetDevnumByGuid(addr->guidStr);
    if (devNum == UINT32_MAX) {
        return NULL;
    }

    devPath = g_strdup_printf("/sys/bus/ub/devices/%05x/iommu_group", devNum);
    if (virFileIsLink(devPath) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid UB device %1$s iommu_group file %2$s is not a symlink"),
                       addr->guidStr, devPath);
        return NULL;
    }

    if (virFileResolveLink(devPath, &groupPath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %1$s iommu_group symlink %2$s"),
                       addr->guidStr, devPath);
        return NULL;
    }
    groupFile = g_path_get_basename(groupPath);

    return g_strdup_printf("/dev/vfio/%s", groupFile);
}

char *
virUBDeviceAddressGetIOMMUFDDev(virUBDeviceAddress *addr)
{
    unsigned int devNum;
    g_autofree char *devPath = NULL;
    g_autofree char *vfioDevPath = NULL;
    struct stat st;
    DIR *dir = NULL;
    struct dirent *dent;

    devNum = virUBDeviceSysfsGetDevnumByGuid(addr->guidStr);
    if (devNum == UINT32_MAX) {
        return NULL;
    }

    devPath = g_strdup_printf("/sys/bus/ub/devices/%05x/vfio-dev", devNum);
    if (stat(devPath, &st) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("ub device %1$s iommufd relate dir %2$s not exist"),
                       addr->guidStr, devPath);

        return NULL;
    }

    dir = opendir(devPath);
    if (!dir) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("ub device %1$s iommufd relate dir %2$s open failed"),
                       addr->guidStr, devPath);
        return NULL;
    }

    while ((dent = readdir(dir))) {
        if (!strncmp(dent->d_name, "vfio", 4)) {
            vfioDevPath = g_strdup_printf("/dev/vfio/devices/%s", dent->d_name);
            break;
        }
    }

    if (!vfioDevPath) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("%s"),
                       "failed to find vfio-dev/vfioX/dev");
        closedir(dir);
        return NULL;
    }

    closedir(dir);
    return g_steal_pointer(&vfioDevPath);
}

bool virUBDeviceAddressGuidIsEmpty(const virUBDeviceAddress *addr)
{
    const UBGuid *guid = &addr->guid;
    return !(guid->vendorId || guid->type || guid->version ||
             guid->deviceId || guid->seqNum);
}

bool virUBDeviceAddressEidIsEmpty(const virUBDeviceAddress *addr)
{
    return 0 == addr->eid;
}

virUBBitmapAllocator *
virUBBitmapAllocatorInit(uint32_t size, const char *name)
{
    virUBBitmapAllocator *allocator = NULL;

    allocator = g_malloc(sizeof(virUBBitmapAllocator));
    if (!allocator) {
        VIR_ERROR("failed to alloc ub bitmap allocator\n");
        return NULL;
    }

    allocator->bitmap = virBitmapNew(size);
    if (!allocator->bitmap) {
        VIR_ERROR("failed to alloc bitmap for ub bitmap allocator\n");
        g_free(allocator);
        return NULL;
    }

    allocator->size = size;
    snprintf(allocator->name, UB_BITMAP_ALLOCATOR_NAME_MAX_LEN, "%s", name);

    return g_steal_pointer(&allocator);
}

int
virUBBitmapAllocatorAcquire(virUBBitmapAllocator *allocator, uint32_t *idx)
{
    int i;

    if (!allocator) {
        return -1;
    }

    for (i = 0; i < allocator->size; i++) {
        if (virBitmapIsBitSet(allocator->bitmap, i)) {
            continue;
        }

        if (virBitmapSetBit(allocator->bitmap, i) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to reserve idx 0x%x for allocator %s"),
                           i, allocator->name);
            return -1;
        }

        *idx = i;
        return 0;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unable to find an unused idx in range [0x1, 0x%x]"),
                   allocator->size);
    return -1;
}

int
virUBBitmapAllocatorRelease(virUBBitmapAllocator *allocator, uint32_t idx)
{
    if (!allocator) {
        return -1;
    }

    if (!idx) {
        return 0;
    }

    ignore_value(virBitmapClearBit(allocator->bitmap, idx));

    return 0;
}

int
virUBBitmapAllocatorSetUsed(virUBBitmapAllocator *allocator, uint64_t idx)
{
    if (!allocator) {
        return -1;
    }

    if (idx >= allocator->size) {
        return 0;
    }

    if (virBitmapSetBit(allocator->bitmap, idx) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to reserve idx 0x%lx for allocator %s"),
                       idx, allocator->name);
        return -1;
    }

    return 0;
}

void
virUBBitmapAllocatorFree(virUBBitmapAllocator *allocator)
{
    if (!allocator) {
        return;
    }

    virBitmapFree(allocator->bitmap);
    g_free(allocator);
}
