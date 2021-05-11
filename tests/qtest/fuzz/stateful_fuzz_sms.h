/*
 * Generic Virtual-Device Fuzzing Target State Machines
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <qiangliu@zju.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef STATEFUL_FUZZ_SMS_H
#define STATEFUL_FUZZ_SMS_H

#include "exec/ioport.h"
#include "tests/qtest/libqos/pci-pc.h"
#include "tests/qtest/libqos/libqtest.h"
#include "fuzz.h"

typedef struct Node {
    uint8_t id;
    char name[32];
    uint8_t *(*get_data)(void);
    size_t (*get_size)(void);
} Node;

typedef struct StateMachine {
    uint8_t id;
    char name[32];
    Node nodes[64];
} StateMachine;

#define CALLBACK_MAXSIZE 0x2000

// ==== EST_WAITLISTHEAD ============================
size_t size_49_44 = 0;

static uint8_t *get_data_49_44() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t EHCIqh = stateful_malloc(0x3000, /*chained=*/false);
    uint64_t tmp_d4713d60c8 = EHCIqh;
    size_49_44 += serialize(Data, size_49_44, CALLBACK_MAXSIZE, 3, 0x16, 0x4, (uint8_t *)&tmp_d4713d60c8);
    return Data;
}

static size_t get_size_49_44() { return size_49_44;}

// ==== EST_FETCHENTRY ============================
size_t size_49_45 = 0;

static uint8_t *get_data_49_45() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_45() { return size_49_45;}

// ==== EST_FETCHQH ============================
size_t size_49_46 = 0;

static uint8_t *get_data_49_46() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t EHCIqh = stateful_require(48);
    uint64_t EHCIqtd = stateful_malloc(32, /*chained=*/false);
    uint32_t *tmp_4f65d4d925 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_4f65d4d925[i] = (uint32_t)EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 0, 0x4, (uint8_t *)tmp_4f65d4d925);
    free(tmp_4f65d4d925);
    uint32_t *tmp_af19922ad9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_af19922ad9[i] = (uint32_t)EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 4, 0x4, (uint8_t *)tmp_af19922ad9);
    free(tmp_af19922ad9);
    uint32_t *tmp_8f4ff31e78 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_8f4ff31e78[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 8, 0x4, (uint8_t *)tmp_8f4ff31e78);
    free(tmp_8f4ff31e78);
    uint32_t *tmp_6f25e2a25a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_6f25e2a25a[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 12, 0x4, (uint8_t *)tmp_6f25e2a25a);
    free(tmp_6f25e2a25a);
    uint32_t *tmp_42af9fc385 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_42af9fc385[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 16, 0x4, (uint8_t *)tmp_42af9fc385);
    free(tmp_42af9fc385);
    uint32_t *tmp_3983ca8ea7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_3983ca8ea7[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 20, 0x4, (uint8_t *)tmp_3983ca8ea7);
    free(tmp_3983ca8ea7);
    uint32_t *tmp_d71037d1b8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_d71037d1b8[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 24, 0x4, (uint8_t *)tmp_d71037d1b8);
    free(tmp_d71037d1b8);
    uint32_t *tmp_a0116be5ab = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_a0116be5ab[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 28, 0x4, (uint8_t *)tmp_a0116be5ab);
    free(tmp_a0116be5ab);
    uint32_t *tmp_55485822de = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_55485822de[i] = (uint32_t)EHCIqh;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 0, 0x4, (uint8_t *)tmp_55485822de);
    free(tmp_55485822de);
    uint32_t *tmp_101fbcccde = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_101fbcccde[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 4, 0x4, (uint8_t *)tmp_101fbcccde);
    free(tmp_101fbcccde);
    uint32_t *tmp_9148624fea = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_9148624fea[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 8, 0x4, (uint8_t *)tmp_9148624fea);
    free(tmp_9148624fea);
    uint32_t *tmp_1759edc372 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1759edc372[i] = (uint32_t)EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 12, 0x4, (uint8_t *)tmp_1759edc372);
    free(tmp_1759edc372);
    uint32_t *tmp_1beb37117d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1beb37117d[i] = (uint32_t)EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 16, 0x4, (uint8_t *)tmp_1beb37117d);
    free(tmp_1beb37117d);
    uint32_t *tmp_8c25166a1f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_8c25166a1f[i] = (uint32_t)EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 20, 0x4, (uint8_t *)tmp_8c25166a1f);
    free(tmp_8c25166a1f);
    uint32_t *tmp_71eacd0549 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_71eacd0549[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 24, 0x4, (uint8_t *)tmp_71eacd0549);
    free(tmp_71eacd0549);
    uint32_t *tmp_cc45782198 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_cc45782198[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 28, 0x4, (uint8_t *)tmp_cc45782198);
    free(tmp_cc45782198);
    uint32_t *tmp_935ddd7251 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_935ddd7251[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 32, 0x4, (uint8_t *)tmp_935ddd7251);
    free(tmp_935ddd7251);
    uint32_t *tmp_2f1205544a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_2f1205544a[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 36, 0x4, (uint8_t *)tmp_2f1205544a);
    free(tmp_2f1205544a);
    uint32_t *tmp_2fcd81b5d2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_2fcd81b5d2[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 40, 0x4, (uint8_t *)tmp_2fcd81b5d2);
    free(tmp_2fcd81b5d2);
    uint32_t *tmp_79fdef7c42 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_79fdef7c42[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 44, 0x4, (uint8_t *)tmp_79fdef7c42);
    free(tmp_79fdef7c42);
    return Data;
}

static size_t get_size_49_46() { return size_49_46;}

// ==== EST_FETCHITD ============================
size_t size_49_47 = 0;

static uint8_t *get_data_49_47() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t EHCIitd = stateful_require(64);
    uint32_t *tmp_864a7a50b4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_864a7a50b4[i] = (uint32_t)EHCIitd;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 0, 0x4, (uint8_t *)tmp_864a7a50b4);
    free(tmp_864a7a50b4);
    uint32_t *tmp_cfc6e62585 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_cfc6e62585[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 4, 0x4, (uint8_t *)tmp_cfc6e62585);
    free(tmp_cfc6e62585);
    uint32_t *tmp_73581a8146 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_73581a8146[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 8, 0x4, (uint8_t *)tmp_73581a8146);
    free(tmp_73581a8146);
    uint32_t *tmp_5b7c709acb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_5b7c709acb[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 12, 0x4, (uint8_t *)tmp_5b7c709acb);
    free(tmp_5b7c709acb);
    uint32_t *tmp_9cdf5a8653 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_9cdf5a8653[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 16, 0x4, (uint8_t *)tmp_9cdf5a8653);
    free(tmp_9cdf5a8653);
    uint32_t *tmp_d857010255 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_d857010255[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 20, 0x4, (uint8_t *)tmp_d857010255);
    free(tmp_d857010255);
    uint32_t *tmp_552116dd2b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_552116dd2b[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 24, 0x4, (uint8_t *)tmp_552116dd2b);
    free(tmp_552116dd2b);
    uint32_t *tmp_febd845d0d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_febd845d0d[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 28, 0x4, (uint8_t *)tmp_febd845d0d);
    free(tmp_febd845d0d);
    uint32_t *tmp_38018b47b2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_38018b47b2[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 32, 0x4, (uint8_t *)tmp_38018b47b2);
    free(tmp_38018b47b2);
    uint32_t *tmp_ae3b16ec9a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_ae3b16ec9a[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 36, 0x4, (uint8_t *)tmp_ae3b16ec9a);
    free(tmp_ae3b16ec9a);
    uint32_t *tmp_1ea45cd693 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1ea45cd693[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 40, 0x4, (uint8_t *)tmp_1ea45cd693);
    free(tmp_1ea45cd693);
    uint32_t *tmp_1db53334fb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1db53334fb[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 44, 0x4, (uint8_t *)tmp_1db53334fb);
    free(tmp_1db53334fb);
    uint32_t *tmp_589f8779b0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_589f8779b0[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 48, 0x4, (uint8_t *)tmp_589f8779b0);
    free(tmp_589f8779b0);
    uint32_t *tmp_f87f43fdf6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_f87f43fdf6[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 52, 0x4, (uint8_t *)tmp_f87f43fdf6);
    free(tmp_f87f43fdf6);
    uint32_t *tmp_1fb797fab7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1fb797fab7[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 56, 0x4, (uint8_t *)tmp_1fb797fab7);
    free(tmp_1fb797fab7);
    uint32_t *tmp_8b53031d05 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_8b53031d05[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 60, 0x4, (uint8_t *)tmp_8b53031d05);
    free(tmp_8b53031d05);
    return Data;
}

static size_t get_size_49_47() { return size_49_47;}

// ==== EST_FETCHSITD ============================
size_t size_49_48 = 0;

static uint8_t *get_data_49_48() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t EHCIsitd = stateful_require(28);
    uint32_t *tmp_a59cec9812 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_a59cec9812[i] = (uint32_t)EHCIsitd;
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 0, 0x4, (uint8_t *)tmp_a59cec9812);
    free(tmp_a59cec9812);
    uint32_t *tmp_6fa231e959 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_6fa231e959[i] = (uint32_t)get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 4, 0x4, (uint8_t *)tmp_6fa231e959);
    free(tmp_6fa231e959);
    uint32_t *tmp_80ee526e0f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_80ee526e0f[i] = (uint32_t)get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 8, 0x4, (uint8_t *)tmp_80ee526e0f);
    free(tmp_80ee526e0f);
    uint32_t *tmp_98b33c6e0a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_98b33c6e0a[i] = (uint32_t)get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 12, 0x4, (uint8_t *)tmp_98b33c6e0a);
    free(tmp_98b33c6e0a);
    uint32_t *tmp_fcfcfa81b3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_fcfcfa81b3[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 16, 0x4, (uint8_t *)tmp_fcfcfa81b3);
    free(tmp_fcfcfa81b3);
    uint32_t *tmp_429817c533 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_429817c533[i] = (uint32_t)stateful_malloc(0x100, /*chained=*/false);
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 20, 0x4, (uint8_t *)tmp_429817c533);
    free(tmp_429817c533);
    uint32_t *tmp_bb4a06cbe7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_bb4a06cbe7[i] = (uint32_t)EHCIsitd;
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, 24, 0x4, (uint8_t *)tmp_bb4a06cbe7);
    free(tmp_bb4a06cbe7);
    return Data;
}

static size_t get_size_49_48() { return size_49_48;}

// ==== EST_ADVANCEQUEUE ============================
size_t size_49_49 = 0;

static uint8_t *get_data_49_49() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_49() { return size_49_49;}

// ==== EST_FETCHQTD ============================
size_t size_49_50 = 0;

static uint8_t *get_data_49_50() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_50() { return size_49_50;}

// ==== EST_HORIZONTALQH ============================
size_t size_49_53 = 0;

static uint8_t *get_data_49_53() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_53() { return size_49_53;}

// ==== EST_EXECUTE ============================
size_t size_49_51 = 0;

static uint8_t *get_data_49_51() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_51() { return size_49_51;}

// ==== EST_EXECUTING ============================
size_t size_49_42 = 0;

static uint8_t *get_data_49_42() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_42() { return size_49_42;}

// ==== EST_WRITEBACK ============================
size_t size_49_52 = 0;

static uint8_t *get_data_49_52() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_52() { return size_49_52;}

// ==== EST_INACTIVE ============================
size_t size_49_40 = 0;

static uint8_t *get_data_49_40() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_40() { return size_49_40;}

// ==== EST_ACTIVE ============================
size_t size_49_41 = 0;

static uint8_t *get_data_49_41() {
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t base = stateful_malloc(0x3000, /*chained=*/true);
    stateful_lock(base, 0x2000 >> 1);
    uint64_t entry = stateful_require(0x1000);
    uint32_t *tmp_bdd7d19b75 = (uint32_t *)malloc(0x2000 >> 1);
    for (int i = 0; i < (0x2000 >> 1) / 4; i++)
        tmp_bdd7d19b75[i] = (uint32_t)entry;
    size_49_41 += serialize(Data, size_49_41, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, base, 0x2000 >> 1, (uint8_t *)tmp_bdd7d19b75);
    free(tmp_bdd7d19b75);
    uint64_t tmp_bd30291a55 = base;
    size_49_41 += serialize(Data, size_49_41, CALLBACK_MAXSIZE, 3, 0x16, 0x4, (uint8_t *)&tmp_bd30291a55);
    return Data;
}

static size_t get_size_49_41() { return size_49_41;}

static StateMachine state_machines[] = {
    [49] = {
        .id = 49,
        .name = "pstate",
        .nodes = {
            [44] = {
                .id = 44,
                .get_data = get_data_49_44,
                .get_size = get_size_49_44,
            }, [45] = {
                .id = 45,
                .get_data = get_data_49_45,
                .get_size = get_size_49_45,
            }, [46] = {
                .id = 46,
                .get_data = get_data_49_46,
                .get_size = get_size_49_46,
            }, [47] = {
                .id = 47,
                .get_data = get_data_49_47,
                .get_size = get_size_49_47,
            }, [48] = {
                .id = 48,
                .get_data = get_data_49_48,
                .get_size = get_size_49_48,
            }, [49] = {
                .id = 49,
                .get_data = get_data_49_49,
                .get_size = get_size_49_49,
            }, [50] = {
                .id = 50,
                .get_data = get_data_49_50,
                .get_size = get_size_49_50,
            }, [53] = {
                .id = 53,
                .get_data = get_data_49_53,
                .get_size = get_size_49_53,
            }, [51] = {
                .id = 51,
                .get_data = get_data_49_51,
                .get_size = get_size_49_51,
            }, [42] = {
                .id = 42,
                .get_data = get_data_49_42,
                .get_size = get_size_49_42,
            }, [52] = {
                .id = 52,
                .get_data = get_data_49_52,
                .get_size = get_size_49_52,
            }, [40] = {
                .id = 40,
                .get_data = get_data_49_40,
                .get_size = get_size_49_40,
            }, [41] = {
                .id = 41,
                .get_data = get_data_49_41,
                .get_size = get_size_49_41,
            }, 
        }
    },
}; 

#endif /* STATEFUL_FUZZ_SMS_H */
