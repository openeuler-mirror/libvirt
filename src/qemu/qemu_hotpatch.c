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


#include <unistd.h>
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "vircommand.h"
#include "qemu/qemu_domain.h"
#include "qemu_hotpatch.h"

#define LIBCARE_CTL "libcare-ctl"
#define LIBCARE_ERROR_NUMBER 255
#define MAX_PATCHID_LEN 8

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu_hotpatch");

static int
qemuDomainHotpatchCheckPid(pid_t pid)
{
    if (pid <= 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("Invalid pid"));
        return -1;
    }

    return 0;
}

char *
qemuDomainHotpatchQuery(virDomainObjPtr vm)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *binary = NULL;
    char *output = NULL;
    pid_t pid = vm->pid;
    int ret = -1;

    if (!(binary = virFindFileInPath(LIBCARE_CTL))) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to find libcare-ctl command."));
        return NULL;
    }

    if (qemuDomainHotpatchCheckPid(pid) < 0)
        return NULL;

    cmd = virCommandNewArgList(binary, "info", "-p", NULL);
    virCommandAddArgFormat(cmd, "%d", pid);
    virCommandSetOutputBuffer(cmd, &output);

    VIR_DEBUG("Querying hotpatch for domain %s. (%s info -p %d)",
              vm->def->name, binary, pid);

    if (virCommandRun(cmd, &ret) < 0)
        goto error;

    if (ret == LIBCARE_ERROR_NUMBER) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to execute libcare-ctl command."));
        goto error;
    }
    return output;

 error:
    VIR_FREE(output);
    return NULL;
}

char *
qemuDomainHotpatchApply(virDomainObjPtr vm,
                        const char *patch)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *binary = NULL;
    char *output = NULL;
    pid_t pid = vm->pid;
    int ret = -1;

    if (!patch || !virFileExists(patch)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("Invalid hotpatch file."));
        return NULL;
    }

    if (!(binary = virFindFileInPath(LIBCARE_CTL))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("Failed to find libcare-ctl command."));
        return NULL;
    }

    if (qemuDomainHotpatchCheckPid(pid) < 0)
        return NULL;

    cmd = virCommandNewArgList(binary, "patch", "-p", NULL);
    virCommandAddArgFormat(cmd, "%d", pid);
    virCommandAddArgList(cmd, patch, NULL);
    virCommandSetOutputBuffer(cmd, &output);

    VIR_DEBUG("Applying hotpatch for domain %s. (%s patch -p %d %s)",
              vm->def->name, binary, pid, patch);

    if (virCommandRun(cmd, &ret) < 0)
        goto error;

    if (ret == LIBCARE_ERROR_NUMBER) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to execute libcare-ctl command."));
        goto error;
    }
    return output;

 error:
    VIR_FREE(output);
    return NULL;
}

static bool
qemuDomainHotpatchIsPatchidValid(const char *id)
{
    size_t len, i;

    if (!id)
        return false;

    len = strlen(id);
    if (len > MAX_PATCHID_LEN - 1)
        return false;

    for (i = 0; i < len; i++) {
        if (!g_ascii_isalnum(*(id + i)))
            return false;
    }

    return true;
}

char *
qemuDomainHotpatchUnapply(virDomainObjPtr vm,
                          const char *id)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *binary = NULL;
    char *output = NULL;
    pid_t pid = vm->pid;
    int ret = -1;

    if (!id || !qemuDomainHotpatchIsPatchidValid(id)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("Invalid hotpatch id."));
        return NULL;
    }

    if (!(binary = virFindFileInPath(LIBCARE_CTL))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("Failed to find libcare-ctl command."));
        return NULL;
    }

    if (qemuDomainHotpatchCheckPid(pid) < 0)
        return NULL;

    cmd = virCommandNewArgList(binary, "unpatch", "-p", NULL);
    virCommandAddArgFormat(cmd, "%d", pid);
    virCommandAddArgList(cmd, "-i", id, NULL);
    virCommandSetOutputBuffer(cmd, &output);

    VIR_DEBUG("Unapplying hotpatch for domain %s. (%s unpatch -p %d -i %s)",
              vm->def->name, binary, pid, id);

    if (virCommandRun(cmd, &ret) < 0)
        goto error;

    if (ret == LIBCARE_ERROR_NUMBER) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to execute libcare-ctl command."));
        goto error;
    }
    return output;

 error:
    VIR_FREE(output);
    return NULL;
}
