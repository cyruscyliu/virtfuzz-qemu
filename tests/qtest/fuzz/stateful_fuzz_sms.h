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

static uint32_t tags[4] = { 
    1 << 1,
    2 << 1,
    0 << 1,
    0,
};

typedef struct StateMachine {
    uint8_t id;
    char name[32];
    Node nodes[64];
} StateMachine;

#define CALLBACK_MAXSIZE 0x2000

// ==== EST_WAITLISTHEAD ============================
size_t size_49_44 = 0;

static uint64_t tmp_EHCIqh = 0;

static uint8_t *get_data_49_44() {
    size_49_44 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    stateful_free(tmp_EHCIqh);
    tmp_EHCIqh = stateful_malloc(0x3000, /*chained=*/false);
    uint64_t tmp_935ddd7251 = tmp_EHCIqh | (1 << 1);
    size_49_44 += serialize(Data, size_49_44, CALLBACK_MAXSIZE, 3, 0x16, 0x4, (uint8_t *)&tmp_935ddd7251);
    return Data;
}

static size_t get_size_49_44() { return size_49_44;}

// ==== EST_FETCHENTRY ============================
size_t size_49_45 = 0;


static uint8_t *get_data_49_45() {
    size_49_45 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_45() { return size_49_45;}

// ==== EST_FETCHQH ============================
size_t size_49_46 = 0;

static uint64_t tmp_EHCIqtd = 0;
static uint64_t tmp_6baa9455e3 = 0;
static uint64_t tmp_d4713d60c8 = 0;
static uint64_t tmp_7a024204f7 = 0;
static uint64_t tmp_8133287637 = 0;
static uint64_t tmp_4f65d4d925 = 0;
static uint64_t tmp_af19922ad9 = 0;
static uint64_t tmp_8f4ff31e78 = 0;
static uint64_t tmp_6f25e2a25a = 0;
static uint64_t tmp_42af9fc385 = 0;
static uint64_t tmp_3983ca8ea7 = 0;

static uint8_t *get_data_49_46() {
    size_49_46 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t tmp_EHCIqh = stateful_require(48);
    stateful_free(tmp_EHCIqtd);
    tmp_EHCIqtd = stateful_malloc(32, /*chained=*/false);
    uint32_t *tmp_79fdef7c42 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_79fdef7c42[i] = (uint32_t)tmp_EHCIqtd | 0;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 0, 0x4, (uint8_t *)tmp_79fdef7c42);
    free(tmp_79fdef7c42);
    uint32_t *tmp_e07405eb21 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_e07405eb21[i] = (uint32_t)tmp_EHCIqtd | 0;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 4, 0x4, (uint8_t *)tmp_e07405eb21);
    free(tmp_e07405eb21);
    uint32_t *tmp_864a7a50b4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_864a7a50b4[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 8, 0x4, (uint8_t *)tmp_864a7a50b4);
    free(tmp_864a7a50b4);
    stateful_free(tmp_6baa9455e3);
    tmp_6baa9455e3 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_73581a8146 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_73581a8146[i] = (uint32_t)tmp_6baa9455e3;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 12, 0x4, (uint8_t *)tmp_73581a8146);
    free(tmp_73581a8146);
    stateful_free(tmp_d4713d60c8);
    tmp_d4713d60c8 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_9cdf5a8653 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_9cdf5a8653[i] = (uint32_t)tmp_d4713d60c8;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 16, 0x4, (uint8_t *)tmp_9cdf5a8653);
    free(tmp_9cdf5a8653);
    stateful_free(tmp_7a024204f7);
    tmp_7a024204f7 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_552116dd2b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_552116dd2b[i] = (uint32_t)tmp_7a024204f7;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 20, 0x4, (uint8_t *)tmp_552116dd2b);
    free(tmp_552116dd2b);
    stateful_free(tmp_8133287637);
    tmp_8133287637 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_38018b47b2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_38018b47b2[i] = (uint32_t)tmp_8133287637;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 24, 0x4, (uint8_t *)tmp_38018b47b2);
    free(tmp_38018b47b2);
    stateful_free(tmp_4f65d4d925);
    tmp_4f65d4d925 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_1ea45cd693 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1ea45cd693[i] = (uint32_t)tmp_4f65d4d925;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqtd + 28, 0x4, (uint8_t *)tmp_1ea45cd693);
    free(tmp_1ea45cd693);
    uint32_t *tmp_1db53334fb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1db53334fb[i] = (uint32_t)tmp_EHCIqh | (1 << 1);
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 0, 0x4, (uint8_t *)tmp_1db53334fb);
    free(tmp_1db53334fb);
    uint32_t *tmp_589f8779b0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_589f8779b0[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 4, 0x4, (uint8_t *)tmp_589f8779b0);
    free(tmp_589f8779b0);
    uint32_t *tmp_f87f43fdf6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_f87f43fdf6[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 8, 0x4, (uint8_t *)tmp_f87f43fdf6);
    free(tmp_f87f43fdf6);
    uint32_t *tmp_1fb797fab7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_1fb797fab7[i] = (uint32_t)tmp_EHCIqtd | 0;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 12, 0x4, (uint8_t *)tmp_1fb797fab7);
    free(tmp_1fb797fab7);
    uint32_t *tmp_8b53031d05 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_8b53031d05[i] = (uint32_t)tmp_EHCIqtd | 0;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 16, 0x4, (uint8_t *)tmp_8b53031d05);
    free(tmp_8b53031d05);
    uint32_t *tmp_11ebcd4942 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_11ebcd4942[i] = (uint32_t)tmp_EHCIqtd | 0;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 20, 0x4, (uint8_t *)tmp_11ebcd4942);
    free(tmp_11ebcd4942);
    uint32_t *tmp_a59cec9812 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_a59cec9812[i] = (uint32_t)get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 24, 0x4, (uint8_t *)tmp_a59cec9812);
    free(tmp_a59cec9812);
    stateful_free(tmp_af19922ad9);
    tmp_af19922ad9 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_80ee526e0f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_80ee526e0f[i] = (uint32_t)tmp_af19922ad9;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 28, 0x4, (uint8_t *)tmp_80ee526e0f);
    free(tmp_80ee526e0f);
    stateful_free(tmp_8f4ff31e78);
    tmp_8f4ff31e78 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_fcfcfa81b3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_fcfcfa81b3[i] = (uint32_t)tmp_8f4ff31e78;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 32, 0x4, (uint8_t *)tmp_fcfcfa81b3);
    free(tmp_fcfcfa81b3);
    stateful_free(tmp_6f25e2a25a);
    tmp_6f25e2a25a = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_bb4a06cbe7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_bb4a06cbe7[i] = (uint32_t)tmp_6f25e2a25a;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 36, 0x4, (uint8_t *)tmp_bb4a06cbe7);
    free(tmp_bb4a06cbe7);
    stateful_free(tmp_42af9fc385);
    tmp_42af9fc385 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_403d1f83a8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_403d1f83a8[i] = (uint32_t)tmp_42af9fc385;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 40, 0x4, (uint8_t *)tmp_403d1f83a8);
    free(tmp_403d1f83a8);
    stateful_free(tmp_3983ca8ea7);
    tmp_3983ca8ea7 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_bdd7d19b75 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_bdd7d19b75[i] = (uint32_t)tmp_3983ca8ea7;
    size_49_46 += serialize(Data, size_49_46, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIqh + 44, 0x4, (uint8_t *)tmp_bdd7d19b75);
    free(tmp_bdd7d19b75);
    return Data;
}

static size_t get_size_49_46() { return size_49_46;}

// ==== EST_FETCHITD ============================
size_t size_49_47 = 0;

static uint64_t tmp_55485822de = 0;
static uint64_t tmp_101fbcccde = 0;
static uint64_t tmp_9148624fea = 0;
static uint64_t tmp_1759edc372 = 0;
static uint64_t tmp_1beb37117d = 0;
static uint64_t tmp_8c25166a1f = 0;
static uint64_t tmp_71eacd0549 = 0;

static uint8_t *get_data_49_47() {
    size_49_47 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t tmp_EHCIitd = stateful_require(64);
    uint32_t *tmp_47e7f5938b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_47e7f5938b[i] = (uint32_t)tmp_EHCIitd | (0 << 1);
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 0, 0x4, (uint8_t *)tmp_47e7f5938b);
    free(tmp_47e7f5938b);
    uint32_t *tmp_ac642b4c49 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_ac642b4c49[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 4, 0x4, (uint8_t *)tmp_ac642b4c49);
    free(tmp_ac642b4c49);
    uint32_t *tmp_b732d46f21 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_b732d46f21[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 8, 0x4, (uint8_t *)tmp_b732d46f21);
    free(tmp_b732d46f21);
    uint32_t *tmp_bf9cc54563 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_bf9cc54563[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 12, 0x4, (uint8_t *)tmp_bf9cc54563);
    free(tmp_bf9cc54563);
    uint32_t *tmp_a69cfb85d4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_a69cfb85d4[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 16, 0x4, (uint8_t *)tmp_a69cfb85d4);
    free(tmp_a69cfb85d4);
    uint32_t *tmp_9836318900 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_9836318900[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 20, 0x4, (uint8_t *)tmp_9836318900);
    free(tmp_9836318900);
    uint32_t *tmp_559b5975b2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_559b5975b2[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 24, 0x4, (uint8_t *)tmp_559b5975b2);
    free(tmp_559b5975b2);
    uint32_t *tmp_6a1689addf = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_6a1689addf[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 28, 0x4, (uint8_t *)tmp_6a1689addf);
    free(tmp_6a1689addf);
    uint32_t *tmp_b5816b74a9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_b5816b74a9[i] = (uint32_t)get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 32, 0x4, (uint8_t *)tmp_b5816b74a9);
    free(tmp_b5816b74a9);
    stateful_free(tmp_55485822de);
    tmp_55485822de = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_b396905742 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_b396905742[i] = (uint32_t)tmp_55485822de;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 36, 0x4, (uint8_t *)tmp_b396905742);
    free(tmp_b396905742);
    stateful_free(tmp_101fbcccde);
    tmp_101fbcccde = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_9f6048fe24 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_9f6048fe24[i] = (uint32_t)tmp_101fbcccde;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 40, 0x4, (uint8_t *)tmp_9f6048fe24);
    free(tmp_9f6048fe24);
    stateful_free(tmp_9148624fea);
    tmp_9148624fea = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_fa83ada4a2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_fa83ada4a2[i] = (uint32_t)tmp_9148624fea;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 44, 0x4, (uint8_t *)tmp_fa83ada4a2);
    free(tmp_fa83ada4a2);
    stateful_free(tmp_1759edc372);
    tmp_1759edc372 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_3c54c71fca = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_3c54c71fca[i] = (uint32_t)tmp_1759edc372;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 48, 0x4, (uint8_t *)tmp_3c54c71fca);
    free(tmp_3c54c71fca);
    stateful_free(tmp_1beb37117d);
    tmp_1beb37117d = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_de59f550f0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_de59f550f0[i] = (uint32_t)tmp_1beb37117d;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 52, 0x4, (uint8_t *)tmp_de59f550f0);
    free(tmp_de59f550f0);
    stateful_free(tmp_8c25166a1f);
    tmp_8c25166a1f = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_a636425c9b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_a636425c9b[i] = (uint32_t)tmp_8c25166a1f;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 56, 0x4, (uint8_t *)tmp_a636425c9b);
    free(tmp_a636425c9b);
    stateful_free(tmp_71eacd0549);
    tmp_71eacd0549 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_fa7ff8bfb0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_fa7ff8bfb0[i] = (uint32_t)tmp_71eacd0549;
    size_49_47 += serialize(Data, size_49_47, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIitd + 60, 0x4, (uint8_t *)tmp_fa7ff8bfb0);
    free(tmp_fa7ff8bfb0);
    return Data;
}

static size_t get_size_49_47() { return size_49_47;}

// ==== EST_FETCHSITD ============================
size_t size_49_48 = 0;

static uint64_t tmp_d71037d1b8 = 0;
static uint64_t tmp_a0116be5ab = 0;

static uint8_t *get_data_49_48() {
    size_49_48 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    uint64_t tmp_EHCIsitd = stateful_require(28);
    uint32_t *tmp_58d87776a5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_58d87776a5[i] = (uint32_t)tmp_EHCIsitd | (2 << 1);
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIsitd + 0, 0x4, (uint8_t *)tmp_58d87776a5);
    free(tmp_58d87776a5);
    uint32_t *tmp_27896389df = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_27896389df[i] = (uint32_t)get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIsitd + 4, 0x4, (uint8_t *)tmp_27896389df);
    free(tmp_27896389df);
    uint32_t *tmp_4c14982d9e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_4c14982d9e[i] = (uint32_t)get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIsitd + 8, 0x4, (uint8_t *)tmp_4c14982d9e);
    free(tmp_4c14982d9e);
    uint32_t *tmp_8ef066d442 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_8ef066d442[i] = (uint32_t)get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIsitd + 12, 0x4, (uint8_t *)tmp_8ef066d442);
    free(tmp_8ef066d442);
    stateful_free(tmp_d71037d1b8);
    tmp_d71037d1b8 = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_6f790959a3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_6f790959a3[i] = (uint32_t)tmp_d71037d1b8;
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIsitd + 16, 0x4, (uint8_t *)tmp_6f790959a3);
    free(tmp_6f790959a3);
    stateful_free(tmp_a0116be5ab);
    tmp_a0116be5ab = stateful_malloc(0x4, /*chained=*/false);
    uint32_t *tmp_247145f4a8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_247145f4a8[i] = (uint32_t)tmp_a0116be5ab;
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIsitd + 20, 0x4, (uint8_t *)tmp_247145f4a8);
    free(tmp_247145f4a8);
    uint32_t *tmp_4578bab326 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        tmp_4578bab326[i] = (uint32_t)tmp_EHCIsitd | (2 << 1);
    size_49_48 += serialize(Data, size_49_48, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_EHCIsitd + 24, 0x4, (uint8_t *)tmp_4578bab326);
    free(tmp_4578bab326);
    return Data;
}

static size_t get_size_49_48() { return size_49_48;}

// ==== EST_ADVANCEQUEUE ============================
size_t size_49_49 = 0;


static uint8_t *get_data_49_49() {
    size_49_49 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_49() { return size_49_49;}

// ==== EST_FETCHQTD ============================
size_t size_49_50 = 0;


static uint8_t *get_data_49_50() {
    size_49_50 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_50() { return size_49_50;}

// ==== EST_HORIZONTALQH ============================
size_t size_49_53 = 0;


static uint8_t *get_data_49_53() {
    size_49_53 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_53() { return size_49_53;}

// ==== EST_EXECUTE ============================
size_t size_49_51 = 0;


static uint8_t *get_data_49_51() {
    size_49_51 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_51() { return size_49_51;}

// ==== EST_EXECUTING ============================
size_t size_49_42 = 0;


static uint8_t *get_data_49_42() {
    size_49_42 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_42() { return size_49_42;}

// ==== EST_WRITEBACK ============================
size_t size_49_52 = 0;


static uint8_t *get_data_49_52() {
    size_49_52 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_52() { return size_49_52;}

// ==== EST_INACTIVE ============================
size_t size_49_40 = 0;


static uint8_t *get_data_49_40() {
    size_49_40 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    return Data;
}

static size_t get_size_49_40() { return size_49_40;}

// ==== EST_ACTIVE ============================
size_t size_49_41 = 0;

static uint64_t tmp_base = 0;

static uint8_t *get_data_49_41() {
    size_49_41 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    stateful_free(tmp_base);
    tmp_base = stateful_malloc(0x3000, /*chained=*/true);
    stateful_lock(tmp_base, 0x2000 >> 1);
    uint64_t tmp_entry = stateful_require(0x1000);
    uint32_t *tmp_4505f4f60a = (uint32_t *)malloc(0x2000 >> 1);
    for (int i = 0; i < (0x2000 >> 1) / 4; i++)
        tmp_4505f4f60a[i] = (uint32_t)tmp_entry | tags[get_data_from_pool4() % (sizeof(tags) / 4)];
    size_49_41 += serialize(Data, size_49_41, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, tmp_base, 0x2000 >> 1, (uint8_t *)tmp_4505f4f60a);
    free(tmp_4505f4f60a);
    uint64_t tmp_5c6460364a = tmp_base | 0;
    size_49_41 += serialize(Data, size_49_41, CALLBACK_MAXSIZE, 3, 0x16, 0x4, (uint8_t *)&tmp_5c6460364a);
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
