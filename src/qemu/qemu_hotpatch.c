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
#include "virbuffer.h"
#include "virstring.h"
#include "vircommand.h"
#include "qemu/qemu_domain.h"
#include "qemu_hotpatch.h"

#define LIBCARE_CTL "libcare-ctl"
#define LIBCARE_ERROR_NUMBER 255
#define MAX_PATCHID_LEN 8
#define MAX_FILE_SIZE (1024*1024)

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

char *
qemuDomainHotpatchAutoload(virDomainObjPtr vm, char *hotpatch_path)
{
    VIR_AUTOSTRINGLIST applied_patches = NULL;
    VIR_AUTOSTRINGLIST lines = NULL;
    g_autofree char *applied_patch = NULL;
    g_autofree char *patch_conf = NULL;
    g_autofree char *buf = NULL;
    char *ret = NULL;
    int i, j, len;

    if (hotpatch_path == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("Invalid hotpatch path."));
        return NULL;
    }

    /* get hotpatch info from Patch.conf */
    patch_conf = g_strdup_printf("%s/Patch.conf", hotpatch_path);
    if ((len = virFileReadAll(patch_conf, MAX_FILE_SIZE, &buf)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("Failed to read Patch.conf file."));
        return NULL;
    }
    if (len > 0)
        buf[len-1] = '\0';

    lines = virStringSplit(buf, "\n", 0);
    if (!lines)
        return NULL;

    /* get domain hotpatch infomation */
    applied_patch = qemuDomainHotpatchQuery(vm);
    if (!applied_patch)
        return NULL;

    applied_patches = virStringSplit(applied_patch, "\n", 0);
    if (!applied_patches)
        return NULL;

    /* load all hotpatch which are listed in Patch.conf one by one */
    for (i = 0; lines[i] != NULL; i++) {
        VIR_AUTOSTRINGLIST patch_info = NULL;
        g_autofree char *kpatch_dir = NULL;
        g_autofree char *file_path = NULL;
        struct dirent *de;
        DIR *dh;
        int direrr;

        if (!strstr(lines[i], "QEMU-"))
            continue;

        patch_info = virStringSplit(lines[i], " ", 0);
        if (!patch_info)
            continue;

        /* skip already applied patch */
        if (strstr(applied_patch, patch_info[2]))
            continue;

        /* get the kpatch file name */
        kpatch_dir = g_strdup_printf("%s/%s", hotpatch_path, patch_info[1]);
        if (!kpatch_dir || !virFileExists(kpatch_dir))
            return NULL;

        if (virDirOpen(&dh, kpatch_dir) < 0)
            return NULL;
        if ((direrr = virDirRead(dh, &de, kpatch_dir)) > 0) {
            GStatBuf sb;

            file_path = g_strdup_printf("%s/%s", kpatch_dir, de->d_name);
            if (g_lstat(file_path, &sb) < 0) {
                virReportSystemError(errno, _("Cannot access '%s'"),
                                    file_path);
                VIR_DIR_CLOSE(dh);
                return NULL;
            }
        }
        VIR_DIR_CLOSE(dh);

        if (qemuDomainHotpatchApply(vm, file_path) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("failed to apply the hotpatch."));
            return NULL;
        }
    }

    /* unload the hotpatch which are not listed in Patch.conf */
    for (i = 0; applied_patches[i] != NULL; i++) {
        const char *patch_id = NULL;
        bool is_need_unload = true;

        if (!strstr(applied_patches[i], "Patch id"))
            continue;

        patch_id = strstr(applied_patches[i], ":") + 1;
        virSkipSpaces(&patch_id);

        for (j = 0; lines[j] != NULL; j++) {
            if (!strstr(lines[j], "QEMU-"))
                continue;
            if (strstr(lines[j], patch_id)) {
                is_need_unload = false;
                break;
            }
        }
        if (is_need_unload == true)
            if (qemuDomainHotpatchUnapply(vm, patch_id) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("failed to unapply the hotpatch."));
                return NULL;
        }
    }

    ret = g_strdup_printf("Hotpatch autoload successfully.\n");
    return ret;
}
