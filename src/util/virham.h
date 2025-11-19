/*
 * virham.h: rack ipc functions for ham migration
 *
 * Copyright (C) 2025 Huawei Technologies Co., Ltd
 */

#pragma once
#define VIR_HAM_CANCELLED_TIMEOUT 1
#define VIR_HAM_RACK_IPC_TIMEOUT 3

typedef enum {
    VIR_HAM_CLEAR_ALL = 0,              /* Clear all resource */
    VIR_HAM_CLEAR_MIGRATE_SUCCESS,      /* Clear specific resource when ham migration succeed */
    VIR_HAM_CLEAR_MIGRATE_FAILURE,      /* Clear specific resource when ham migration failed */

    VIR_HAM_CLEAR_LAST
} virHamClearType;

char *virHamRackIpcSyncSendAndRecv(const char *req);

char *virHamGetClearReqInit(virHamClearType type, const char *hostname);

void virHamClearAll(const char *hostname);

unsigned long long virHamGetCancelledTimeout(void);

void virHamSetupTimeOut(unsigned long long cancelledTimeout, uint16_t rackIpcTimeout);
