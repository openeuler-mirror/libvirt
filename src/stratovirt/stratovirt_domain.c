/*
 * huawei_stratovirt_domain.c: huawei stratovirt domain functions
 * Manage domain state.
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

#include <fcntl.h>

#include "stratovirt_domain.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STRATOVIRT

VIR_LOG_INIT("stratovirt.stratovirt_domain");


static int virStratoVirtDomainPostParseBasic(virDomainDefPtr def,
                                             void * opaque G_GNUC_UNUSED)
{
    if (!def->emulator) {
        if (!(def->emulator = g_find_program_in_path(STRATOVIRT_CMD))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("No emulator found for stratovirt"));
            return 1;
        }
    }
    return 0;
}

static void stratovirtDomainNVRAMPathGenerate(virStratoVirtDriverConfigPtr cfg,
                                              virDomainDefPtr def)
{
    if (virDomainDefHasOldStyleROUEFI(def) && !def->os.loader->nvram)
        def->os.loader->nvram = g_strdup_printf("%s/%s_VARS.fd", cfg->nvramDir, def->name);
}

static int virStratoVirtDomainPostParse(virDomainDefPtr def,
                                        unsigned int parseFlags G_GNUC_UNUSED,
                                        void * opaque,
                                        void *parseOpaue G_GNUC_UNUSED)
{
    virStratoVirtDriverPtr driver = opaque;
    g_autoptr(virStratoVirtDriverConfig) cfg = virStratoVirtDriverGetConfig(driver);
    g_autoptr(virCaps) caps = virStratoVirtDriverGetCapabilities(driver, false);

    if (!caps)
        return -1;

    stratovirtDomainNVRAMPathGenerate(cfg, def);

    if (!virCapabilitiesDomainSupported(caps, def->os.type,
                                        def->os.arch,
                                        def->virtType))
        return -1;

    return 0;
}

static int virStratoVirtDomainDefAssignAddresses(virDomainDef *def,
                                                 unsigned int parseFlags G_GNUC_UNUSED,
                                                 void *opaque,
                                                 void *parseOpaque)
{
    virStratoVirtDriverPtr driver = opaque;
    virStratoVirtCapsPtr stratovirtCaps = parseOpaque;
    bool newDomain = parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;

    if (!stratovirtCaps)
        return 1;

    return stratovirtDom.stratovirtDomainAssignAddresses(def, stratovirtCaps, driver, NULL, newDomain);
}

static int virStratoVirtDomainPostParseDataAlloc(const virDomainDef *def,
                                                 unsigned int parseFlags G_GNUC_UNUSED,
                                                 void *opaque,
                                                 void **parseOpaque)
{
    virStratoVirtDriverPtr driver = opaque;

    if (!(*parseOpaque = stratovirtconf.virStratoVirtCapsCacheLookup(driver->qemuCapsCache,
                                                                     def->emulator)))
        return 1;

    return 0;
}

static void virStratoVirtDomainPostParseDataFree(void *parseOpaque)
{
    virStratoVirtCapsPtr stratovirtCaps = parseOpaque;

    virObjectUnref(stratovirtCaps);
}

static int virStratoVirtValidateDeviceDef(const virDomainDeviceDef* dev,
                                          const virDomainDef *def G_GNUC_UNUSED,
                                          void *opaque G_GNUC_UNUSED)
{
    switch ((virDomainDeviceType)dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
    default:
        virReportEnumRangeError(virDomainDeviceType, dev->type);
        return -1;
    }
    return 0;
}

virDomainDefParserConfig virStratoVirtDriverDomainDefParserConfig = {
    .domainPostParseBasicCallback = virStratoVirtDomainPostParseBasic,
    .domainPostParseCallback = virStratoVirtDomainPostParse,
    .deviceValidateCallback = virStratoVirtValidateDeviceDef,
    .domainPostParseDataAlloc = virStratoVirtDomainPostParseDataAlloc,
    .domainPostParseDataFree = virStratoVirtDomainPostParseDataFree,
    .assignAddressesCallback = virStratoVirtDomainDefAssignAddresses,
};

void stratovirtProcessEventFree(stratovirtProcessEventPtr event)
{
    if (!event)
        return;

    switch (event->eventType) {
    case STRATOVIRT_PROCESS_EVENT_GUESTPANIC:
    case STRATOVIRT_PROCESS_EVENT_RDMA_GID_STATUS_CHANGED:
        break;
    case STRATOVIRT_PROCESS_EVENT_WATCHDOG:
    case STRATOVIRT_PROCESS_EVENT_DEVICE_DELETED:
    case STRATOVIRT_PROCESS_EVENT_NIC_RX_FILTER_CHANGED:
    case STRATOVIRT_PROCESS_EVENT_SERIAL_CHANGED:
    case STRATOVIRT_PROCESS_EVENT_BLOCK_JOB:
    case STRATOVIRT_PROCESS_EVENT_MONITOR_EOF:
    case STRATOVIRT_PROCESS_EVENT_GUEST_CRASHLOADED:
        VIR_FREE(event->data);
        break;
    case STRATOVIRT_PROCESS_EVENT_JOB_STATUS_CHANGE:
        virObjectUnref(event->data);
        break;
    case STRATOVIRT_PROCESS_EVENT_PR_DISCONNECT:
    case STRATOVIRT_PROCESS_EVENT_LAST:
        break;
    }
    VIR_FREE(event);
}

virDomainObjPtr stratovirtDomainObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    virStratoVirtDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

void
stratovirtDomainUpdateCurrentMemorySize(virDomainObjPtr vm)
{
    if (!virDomainObjIsActive(vm))
        return;

    /* if no balloning is available, the current size equals to the current
     * full memory size */
    if (!virDomainDefHasMemballoon(vm->def))
        vm->def->mem.cur_balloon = virDomainDefGetMemoryTotal(vm->def);
}

virStratoVirtDomain stratovirtDom = {
    .stratovirtDomainNamespaceAvailable = qemuDomainNamespaceAvailable,
    .stratovirtDomainRemoveInactive = qemuDomainRemoveInactive,
    .stratovirtDomainObjEndJob = qemuDomainObjEndJob,
    .stratovirtDomainObjBeginJob = qemuDomainObjBeginJob,
    .stratovirtDomainObjEnterMonitor = qemuDomainObjEnterMonitor,
    .stratovirtDomainObjExitMonitor = qemuDomainObjExitMonitor,
    .stratovirtDomainSnapshotDiscardAllMetadata = qemuDomainSnapshotDiscardAllMetadata,
    .stratovirtDomainCheckpointDiscardAllMetadata = qemuCheckpointDiscardAllMetadata,
    .stratovirtDomainAssignAddresses = qemuDomainAssignAddresses,
};
