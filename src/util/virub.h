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

#pragma once
#include "virbitmap.h"
#include "virenum.h"
#include "virobject.h"

#define GUID_STR_EXAMPLE "cc08-a000-0-2-000000-0000000000000001" \
          "(VendorID-DeviceId-Version-Type-RSV-SequenceNumber)"
#define UB_DEV_GUID_STRING_LENGTH   37
#define UB_GUID_ELEMENT_NUM 6
#define UB_GUID_SEQ_AUTO_ALLOC_NUM 256
#define UB_EID_AUTO_ALLOC_NUM      256

typedef struct _UBGuid UBGuid;
struct __attribute__ ((__packed__)) _UBGuid {
    unsigned long long seqNum : 64;
    unsigned long long rsv : 24;
    unsigned int type : 4;
    unsigned int version : 4;
    unsigned int deviceId : 16;
    unsigned int vendorId : 16;
};

typedef struct _virUBDeviceAddress virUBDeviceAddress;
struct _virUBDeviceAddress {
    UBGuid guid;
    char *guidStr;
    unsigned int eid;
};

typedef enum _virUBDevicePortStatus virUBDevicePortStatus;
enum _virUBDevicePortStatus {
    UB_DEVICE_PORT_STATUS_LINK_DOWN,
    UB_DEVICE_PORT_STATUS_LINK_UP,
};

typedef enum {
    VIR_UB_STUB_DRIVER_NONE = 0,
    VIR_UB_STUB_DRIVER_VFIO,
    VIR_UB_STUB_DRIVER_LAST
} virUBStubDriver;

VIR_ENUM_DECL(virUBStubDriver);

typedef struct _virUBDevice virUBDevice;
struct _virUBDevice {
    virUBDeviceAddress address;
    char            *path;

    /* The driver:domain which uses the device */
    char            *used_by_drvname;
    char            *used_by_domname;

    virUBStubDriver stub_driver_type;
    char            *stub_driver_name; /* if blank, use default for type */

    /* the origin driver before manage */
    char            *orig_used_drvname;

    bool            managed;
    bool            unbind_from_stub;
};

typedef struct _virUBDeviceList virUBDeviceList;
struct _virUBDeviceList {
    virObjectLockable parent;
    size_t count;
    virUBDevice **devs;
};

#define UB_DEVICE_MAX_PORT_NUM 256
#define UB_CONTROLLER_DEFAULT_PORT_NUM 128
#define UB_DEVICE_DEFAULT_PORT_NUM 1
typedef struct _virUBDevicePortInfo virUBDevicePortInfo;
struct _virUBDevicePortInfo {
    virUBDevicePortStatus status;
    unsigned int teid;
    unsigned int tport;
    char *port;
    char *target;
};

#define UB_BITMAP_ALLOCATOR_NAME_MAX_LEN 32
typedef struct _virUBBitmapAllocator virUBBitmapAllocator;
struct _virUBBitmapAllocator {
    char name[UB_BITMAP_ALLOCATOR_NAME_MAX_LEN];
    uint32_t size;
    virBitmap *bitmap;
};

typedef struct _virUBDevicePort virUBDevicePort;
struct _virUBDevicePort {
    unsigned int num;
    virUBBitmapAllocator *idx_allocator;
    virUBDevicePortInfo *ports;
};

typedef struct _virUBBusInstance virUBBusInstance;
struct _virUBBusInstance {
    UBGuid guid;
    char *guidStr;
    bool cluster;
};

int virUBDeviceGetGuidFromStr(UBGuid *guid, char *guidStr);
char *virUBDeviceAddressGetIOMMUGroupDev(virUBDeviceAddress *addr);
char *virUBDeviceAddressGetIOMMUFDDev(virUBDeviceAddress *addr);
bool virUBDeviceAddressGuidIsEmpty(const virUBDeviceAddress *addr);
bool virUBDeviceAddressEidIsEmpty(const virUBDeviceAddress *addr);
virUBBitmapAllocator *
virUBBitmapAllocatorInit(uint32_t size, const char *name);
int
virUBBitmapAllocatorAcquire(virUBBitmapAllocator *allocator, uint32_t *idx);
int
virUBBitmapAllocatorRelease(virUBBitmapAllocator *allocator, uint32_t idx);
int
virUBBitmapAllocatorSetUsed(virUBBitmapAllocator *allocator, uint64_t idx);
void
virUBBitmapAllocatorFree(virUBBitmapAllocator *allocator);
void
virUBDeviceFree(virUBDevice *dev);
virUBDeviceList *
virUBDeviceListNew(void);
int
virUBDeviceSetUsedBy(virUBDevice *dev, const char *drv_name, const char *dom_name);
virUBDevice *
virUBDeviceListFind(virUBDeviceList *list, virUBDeviceAddress *devAddr);
int
virUBDeviceListAdd(virUBDeviceList *list, virUBDevice *dev);
bool
virUBDeviceExists(const virUBDeviceAddress *addr);
void
virUBDeviceAddressCopy(virUBDeviceAddress *dst, const virUBDeviceAddress *src);
void
virUBDeviceSetManaged(virUBDevice *dev, bool managed);
void
virUBDeviceSetStubDriverType(virUBDevice *dev, virUBStubDriver driverType);
virUBDevice *
virUBDeviceNew(const virUBDeviceAddress *address);
int
virUBDeviceListFindIndex(virUBDeviceList *list, virUBDeviceAddress *devAddr);
virUBDevice *
virUBDeviceListStealIndex(virUBDeviceList *list, int idx);
virUBDevice *
virUBDeviceListSteal(virUBDeviceList *list, virUBDeviceAddress *devAddr);
void
virUBDeviceListDel(virUBDeviceList *list, virUBDeviceAddress *devAddr);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virUBDevice, virUBDeviceFree);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virUBDeviceList, virObjectUnref);