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
#include "viralloc.h"
#include "virstring.h"
#include "virkmod.h"

VIR_LOG_INIT("util.ub");

#define VIR_FROM_THIS VIR_FROM_NONE
#define UB_SYSFS "/sys/bus/ub/"

static virClass *virUBDeviceListClass;
static void virUBDeviceListDispose(void *obj);

VIR_ENUM_IMPL(virUBStubDriver,
              VIR_UB_STUB_DRIVER_LAST,
              "none",
              "vfio-ub", /* VFIO */
);

static int virUBOnceInit(void)
{
    if (!VIR_CLASS_NEW(virUBDeviceList, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virUB);

char *
virUBFile(const unsigned int devNum, const char *file)
{
    return g_strdup_printf(UB_SYSFS "devices/%05x/%s", devNum, file);
}

static void
virUBDeviceListDispose(void *obj)
{
    virUBDeviceList *list = obj;
    size_t i;

    for (i = 0; i < list->count; i++) {
        g_clear_pointer(&list->devs[i], virUBDeviceFree);
    }

    list->count = 0;
    g_free(list->devs);
}

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
uint32_t
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

virUBDeviceList *
virUBDeviceListNew(void)
{
    virUBDeviceList *list;

    if (virUBInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virUBDeviceListClass)))
        return NULL;

    return list;
}

int
virUBDeviceSetUsedBy(virUBDevice *dev,
                     const char *drv_name,
                     const char *dom_name)
{
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    dev->used_by_drvname = g_strdup(drv_name);
    dev->used_by_domname = g_strdup(dom_name);

    return 0;
}

virUBDevice *
virUBDeviceListFind(virUBDeviceList *list, virUBDeviceAddress *devAddr)
{
    VIR_DEBUG("list size: %lu, find guid: %s", list->count, devAddr->guidStr);
    return 0;
}

int
virUBDeviceListAdd(virUBDeviceList *list,
                   virUBDevice *dev)
{
    if (virUBDeviceListFind(list, &dev->address)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %1$s is already in use"), dev->address.guidStr);
        return -1;
    }
    VIR_APPEND_ELEMENT(list->devs, list->count, dev);

    return 0;
}

void
virUBDeviceFree(virUBDevice *dev)
{
    if (!dev)
        return;
    VIR_DEBUG("%s: freeing", dev->address.guidStr);
    g_free(dev->address.guidStr);
    g_free(dev->used_by_domname);
    g_free(dev->used_by_drvname);
    g_free(dev->orig_used_drvname);
    g_free(dev->stub_driver_name);
    g_free(dev->path);
    g_free(dev);
}

bool
virUBDeviceExists(const virUBDeviceAddress *addr)
{
    unsigned int devNum;
    g_autofree char *devPath = NULL;

    devNum = virUBDeviceSysfsGetDevnumByGuid(addr->guidStr);
    if (devNum == UINT32_MAX) {
        return false;
    }

    devPath = g_strdup_printf(UB_SYSFS "devices/%05x/config",
                              devNum);

    return virFileExists(devPath);
}

void virUBDeviceAddressCopy(virUBDeviceAddress *dst,
                            const virUBDeviceAddress *src)
{
    memcpy(&dst->guid, &src->guid, sizeof(UBGuid));
    dst->eid = src->eid;
    if (dst->guidStr != NULL) {
        g_free(dst->guidStr);
    }
    dst->guidStr = g_strdup(src->guidStr);
}

void virUBDeviceSetManaged(virUBDevice *dev, bool managed)
{
    dev->managed = managed;
}

void
virUBDeviceSetStubDriverName(virUBDevice *dev, char* driverName)
{
    g_free(dev->stub_driver_name);
    dev->stub_driver_name = g_strdup(driverName);
}

bool virUBDeviceGetManaged(virUBDevice *dev)
{
    return dev->managed;
}

void
virUBDeviceSetStubDriverType(virUBDevice *dev, virUBStubDriver driverType)
{
    dev->stub_driver_type = driverType;
}

virUBDevice *
virUBDeviceNew(const virUBDeviceAddress *address)
{
    g_autoptr(virUBDevice) dev = NULL;
    unsigned int devNum;

    devNum = virUBDeviceSysfsGetDevnumByGuid(address->guidStr);
    if (devNum == UINT32_MAX) {
        VIR_ERROR("can not find ub dev %s", address->guidStr);
        return NULL;
    }

    dev = g_new0(virUBDevice, 1);
    virUBDeviceAddressCopy(&dev->address, address);
    dev->path = g_strdup_printf(UB_SYSFS "devices/%05x/config", devNum);
    if (!virFileExists(dev->path)) {
        virReportSystemError(errno,
                             _("Device %1$s not found: could not access %2$s"),
                             address->guidStr, dev->path);
        return NULL;
    }

    VIR_DEBUG("%s: initialized", dev->address.guidStr);

    return g_steal_pointer(&dev);
}

int
virUBDeviceListFindIndex(virUBDeviceList *list,
                         virUBDeviceAddress *devAddr)
{
    virUBDevice *checkdev;

    for (int i = 0; i < list->count; i++) {
        checkdev = list->devs[i];
        if (checkdev->address.guid.deviceId == devAddr->guid.deviceId &&
            checkdev->address.guid.rsv      == devAddr->guid.rsv      &&
            checkdev->address.guid.seqNum   == devAddr->guid.seqNum   &&
            checkdev->address.guid.type     == devAddr->guid.type     &&
            checkdev->address.guid.vendorId == devAddr->guid.vendorId &&
            checkdev->address.guid.version  == devAddr->guid.version)
            return i;
    }
    return -1;
}

virUBDevice *
virUBDeviceListStealIndex(virUBDeviceList *list,
                          int idx)
{
    virUBDevice *ret;

    if (idx < 0 || idx >= list->count)
        return NULL;

    ret = list->devs[idx];
    VIR_DELETE_ELEMENT(list->devs, idx, list->count);
    return ret;
}

virUBDevice *
virUBDeviceListSteal(virUBDeviceList *list,
                     virUBDeviceAddress *devAddr)
{
    return virUBDeviceListStealIndex(list, virUBDeviceListFindIndex(list, devAddr));
}

void
virUBDeviceListDel(virUBDeviceList *list,
                   virUBDeviceAddress *devAddr)
{
    virUBDeviceFree(virUBDeviceListSteal(list, devAddr));
}

static virUBDevice *
virUBDeviceCopy(virUBDevice *dev)
{
    VIR_DEBUG("dev guid: %s", dev->address.guidStr);
    return 0;
}

bool
virUBDeviceListAddCopy(virUBDeviceList *list, virUBDevice *dev)
{
    g_autoptr(virUBDevice) copy = virUBDeviceCopy(dev);

    if (!copy)
        return false;
    if (virUBDeviceListAdd(list, copy) < 0)
        return false;

    copy = NULL;
    return true;
}

virUBDeviceAddress *virUBDeviceSysfsGetAddrByDevnum(unsigned int devNum)
{
    virUBDeviceAddress *addr = NULL;
    g_autofree char *filePath = NULL;

    addr = g_new0(virUBDeviceAddress, 1);
    /* include '\n\0' at the end, len is UB_DEV_GUID_STRING_LENGTH + 2*/
    addr->guidStr = g_new0(char, UB_DEV_GUID_STRING_LENGTH + 2);

    filePath = virUBFile(devNum, "guid");
    if (virFileReadAll(filePath, UB_DEV_GUID_STRING_LENGTH + 1, &addr->guidStr) < 0) {
        g_free(addr->guidStr);
        g_free(addr);
        return NULL;
    }

    if (addr->guidStr[UB_DEV_GUID_STRING_LENGTH] == '\n')
        addr->guidStr[UB_DEV_GUID_STRING_LENGTH] = '\0';

    if (virUBDeviceGetGuidFromStr(&addr->guid, addr->guidStr) < 0) {
        VIR_ERROR("failed to convert the string: %s to guid\n", addr->guidStr);
        g_free(addr->guidStr);
        g_free(addr);
        return NULL;
    }

    return addr;
}

int
virUBDeviceGetCurrentDriverName(virUBDevice *dev, char **name)
{
    *name = dev->address.guidStr;
    VIR_DEBUG("dev: %s", dev->address.guidStr);
    return 0;
}

static char *
virUBDriverDir(const char *driver)
{
    return g_strdup_printf(UB_SYSFS "drivers/%s", driver);
}

static int
virUBProbeDriver(const char *driverName)
{
    g_autofree char *drvpath = NULL;
    g_autofree char *errbuf = NULL;

    drvpath = virUBDriverDir(driverName);
    if (virFileExists(drvpath))
        return 0;

    if ((errbuf = virKModLoad(driverName))) {
        VIR_WARN("failed to load driver %s: %s", driverName, errbuf);
        goto err;
    }

    if (!virFileExists(drvpath))
        goto err;

    return 0;

 err:
    if (virKModIsProhibited(driverName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load UB driver module %1$s: administratively prohibited"),
                       driverName);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load UB driver module %1$s"),
                       driverName);
    }

    return -1;
}

static char *
virUBDeviceSysfsGetDevnumstrByGuid(virUBDevice *dev)
{
    VIR_DEBUG("dev guid: %s", dev->address.guidStr);
    return 0;
}

int
virUBDeviceUnbind(virUBDevice *dev)
{
    VIR_DEBUG("dev: %s", dev->address.guidStr);
    return 0;
}

static int
virUBDeviceRebind(virUBDevice *dev)
{
    g_autofree char *devNumStr = NULL;

    if (virUBDeviceUnbind(dev) < 0)
        return -1;

    devNumStr = virUBDeviceSysfsGetDevnumstrByGuid(dev);
    if (!devNumStr) {
        return -1;
    }

    if (virFileWriteStr(UB_SYSFS "drivers_probe", devNumStr, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to trigger a probe for UB device '%1$s'"),
                             dev->address.guidStr);
        return -1;
    }

    return 0;
}

static int
virUBDeviceBindWithDriverOverride(virUBDevice *dev,
                                  const char *driverName)
{
    g_autofree char *path = NULL;
    unsigned int devNum;

    devNum = virUBDeviceSysfsGetDevnumByGuid(dev->address.guidStr);
    if (devNum == UINT32_MAX) {
        return -1;
    }

    path = virUBFile(devNum, "driver_override");
    if (virFileWriteStr(path, driverName, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to add driver '%1$s' to driver_override interface of UB device '%2$s'"),
                             driverName, dev->address.guidStr);
        return -1;
    }

    if (virUBDeviceRebind(dev) < 0)
        return -1;

    return 0;
}

static int
virUBDeviceBindToStub(virUBDevice *dev)
{
    const char *stub_driver_name = dev->stub_driver_name;
    g_autofree char *stubDriverPath = NULL;
    g_autofree char *driverLink = NULL;
    unsigned int devNum;

    if (dev->stub_driver_type == VIR_UB_STUB_DRIVER_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No stub driver configured for UB device %1$s"),
                       dev->address.guidStr);
        return -1;
    }

    if (!stub_driver_name &&
        !(stub_driver_name = virUBStubDriverTypeToString(dev->stub_driver_type))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown stub driver configured for UB device %1$s"),
                       dev->address.guidStr);
        return -1;
    }

    if (virUBProbeDriver(stub_driver_name) < 0)
        return -1;

    devNum = virUBDeviceSysfsGetDevnumByGuid(dev->address.guidStr);
    if (devNum == UINT32_MAX) {
        return -1;
    }
    stubDriverPath = virUBDriverDir(stub_driver_name);
    driverLink = virUBFile(devNum, "driver");
    if (virFileExists(driverLink)) {
        if (virFileLinkPointsTo(driverLink, stubDriverPath)) {
            /* The device is already bound to the correct driver */
            VIR_DEBUG("Device %s is already bound to %s",
                      dev->address.guidStr, stub_driver_name);
            return 0;
        }
    }

    if (virUBDeviceBindWithDriverOverride(dev, stub_driver_name) < 0)
        return -1;

    dev->unbind_from_stub = true;
    return 0;
}

int
virUBDeviceDetach(virUBDevice *dev,
                  virUBDeviceList *activeDevs,
                  virUBDeviceList *inactiveDevs)
{
    if (activeDevs && virUBDeviceListFind(activeDevs, &dev->address)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not detaching active device %1$s"), dev->address.guidStr);
        return -1;
    }

    if (virUBDeviceGetCurrentDriverName(dev, &dev->orig_used_drvname) < 0) {
        VIR_DEBUG("UB device %s do not bind any driver now", dev->address.guidStr);
    } else {
        VIR_DEBUG("UB device %s originally bind driver %s", dev->address.guidStr, dev->orig_used_drvname);
    }

    if (virUBDeviceBindToStub(dev) < 0)
        return -1;

    /* Add *a copy of* the dev into list inactiveDevs, if
     * it's not already there.
     */
    if (inactiveDevs && !virUBDeviceListFind(inactiveDevs, &dev->address)) {
        VIR_DEBUG("Adding UB device %s to inactive list", dev->address.guidStr);
        if (!virUBDeviceListAddCopy(inactiveDevs, dev))
            return -1;
    }

    return 0;
}

bool
virUBDeviceGetCurrentDriverNameAndType(virUBDevice *dev,
                                       char **drvName,
                                       virUBStubDriver *drvType)
{
    VIR_DEBUG("dev: %s, drv name: %s, stub type %u", dev->address.guidStr, *drvName, *drvType);
    return false;
}
