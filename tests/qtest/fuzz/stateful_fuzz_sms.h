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


// ==== EST_WAITLISTHEAD ============================
size_t size_49_44 = 0;

static uint8_t *get_data_49_44() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    uint64_t EHCIqh = stateful_malloc(0x3000, /*chained=*/false);
    uint64_t tmp_d618070f = EHCIqh;
    size_49_44 += serialize(Data, size_49_44, 4096, 3, 0x16, 0x4, (uint8_t *)&tmp_d618070f);
    return Data;
}

static size_t get_size_49_44() { return size_49_44;}

// ==== EST_FETCHENTRY ============================
size_t size_49_45 = 0;

static uint8_t *get_data_49_45() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_45() { return size_49_45;}

// ==== EST_FETCHQH ============================
size_t size_49_46 = 0;

static uint8_t *get_data_49_46() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    uint64_t EHCIqh = stateful_require(48);
    uint64_t EHCIqtd = stateful_malloc(32, /*chained=*/false);
    uint64_t tmp_bd1925a8 = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 0, 0x4, (uint8_t *)&tmp_bd1925a8);
    uint64_t tmp_aa2e2d9c = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 4, 0x4, (uint8_t *)&tmp_aa2e2d9c);
    uint64_t tmp_23ff14a3 = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 8, 0x4, (uint8_t *)&tmp_23ff14a3);
    uint64_t tmp_bc34d3c6 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 12, 0x4, (uint8_t *)&tmp_bc34d3c6);
    uint64_t tmp_769a489b = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 16, 0x4, (uint8_t *)&tmp_769a489b);
    uint64_t tmp_e0e0f3c5 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 20, 0x4, (uint8_t *)&tmp_e0e0f3c5);
    uint64_t tmp_ab139311 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 24, 0x4, (uint8_t *)&tmp_ab139311);
    uint64_t tmp_b6586f98 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 28, 0x4, (uint8_t *)&tmp_b6586f98);
    uint64_t tmp_28637f76 = EHCIqh;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 0, 0x4, (uint8_t *)&tmp_28637f76);
    uint64_t tmp_4b1625b8 = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 4, 0x4, (uint8_t *)&tmp_4b1625b8);
    uint64_t tmp_b3ce4ba5 = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 8, 0x4, (uint8_t *)&tmp_b3ce4ba5);
    uint64_t tmp_05f52060 = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 12, 0x4, (uint8_t *)&tmp_05f52060);
    uint64_t tmp_4f761ad9 = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 16, 0x4, (uint8_t *)&tmp_4f761ad9);
    uint64_t tmp_2a619d2b = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 20, 0x4, (uint8_t *)&tmp_2a619d2b);
    uint64_t tmp_2997ba94 = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 24, 0x4, (uint8_t *)&tmp_2997ba94);
    uint64_t tmp_bc5ec3f0 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 28, 0x4, (uint8_t *)&tmp_bc5ec3f0);
    uint64_t tmp_fd14cd9b = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 32, 0x4, (uint8_t *)&tmp_fd14cd9b);
    uint64_t tmp_66ae5bbe = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 36, 0x4, (uint8_t *)&tmp_66ae5bbe);
    uint64_t tmp_454a2d30 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 40, 0x4, (uint8_t *)&tmp_454a2d30);
    uint64_t tmp_307fdfa0 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 44, 0x4, (uint8_t *)&tmp_307fdfa0);
    return Data;
}

static size_t get_size_49_46() { return size_49_46;}

// ==== EST_FETCHITD ============================
size_t size_49_47 = 0;

static uint8_t *get_data_49_47() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    uint64_t EHCIitd = stateful_require(64);
    uint64_t tmp_9e81dc57 = EHCIitd;
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 0, 0x4, (uint8_t *)&tmp_9e81dc57);
    uint64_t tmp_c8c41556 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 4, 0x4, (uint8_t *)&tmp_c8c41556);
    uint64_t tmp_24353a45 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 8, 0x4, (uint8_t *)&tmp_24353a45);
    uint64_t tmp_39895454 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 12, 0x4, (uint8_t *)&tmp_39895454);
    uint64_t tmp_efeab0a4 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 16, 0x4, (uint8_t *)&tmp_efeab0a4);
    uint64_t tmp_4f4821b0 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 20, 0x4, (uint8_t *)&tmp_4f4821b0);
    uint64_t tmp_8cd40c4d = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 24, 0x4, (uint8_t *)&tmp_8cd40c4d);
    uint64_t tmp_15b3814d = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 28, 0x4, (uint8_t *)&tmp_15b3814d);
    uint64_t tmp_6fe8492c = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 32, 0x4, (uint8_t *)&tmp_6fe8492c);
    uint64_t tmp_dadcd43d = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 36, 0x4, (uint8_t *)&tmp_dadcd43d);
    uint64_t tmp_0de47a60 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 40, 0x4, (uint8_t *)&tmp_0de47a60);
    uint64_t tmp_4d40e375 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 44, 0x4, (uint8_t *)&tmp_4d40e375);
    uint64_t tmp_677f19b0 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 48, 0x4, (uint8_t *)&tmp_677f19b0);
    uint64_t tmp_bd664659 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 52, 0x4, (uint8_t *)&tmp_bd664659);
    uint64_t tmp_8d872606 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 56, 0x4, (uint8_t *)&tmp_8d872606);
    uint64_t tmp_f0c970a8 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 60, 0x4, (uint8_t *)&tmp_f0c970a8);
    return Data;
}

static size_t get_size_49_47() { return size_49_47;}

// ==== EST_FETCHSITD ============================
size_t size_49_48 = 0;

static uint8_t *get_data_49_48() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    uint64_t EHCIsitd = stateful_require(28);
    uint64_t tmp_9cb74d1a = EHCIsitd;
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 0, 0x4, (uint8_t *)&tmp_9cb74d1a);
    uint64_t tmp_56f0b2dd = get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 4, 0x4, (uint8_t *)&tmp_56f0b2dd);
    uint64_t tmp_64aca647 = get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 8, 0x4, (uint8_t *)&tmp_64aca647);
    uint64_t tmp_006e1a98 = get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 12, 0x4, (uint8_t *)&tmp_006e1a98);
    uint64_t tmp_1d9bc542 = stateful_malloc(0x100, /*chained=*/false);
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 16, 0x4, (uint8_t *)&tmp_1d9bc542);
    uint64_t tmp_29c4109c = stateful_malloc(0x100, /*chained=*/false);
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 20, 0x4, (uint8_t *)&tmp_29c4109c);
    uint64_t tmp_24a936b9 = EHCIsitd;
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 24, 0x4, (uint8_t *)&tmp_24a936b9);
    return Data;
}

static size_t get_size_49_48() { return size_49_48;}

// ==== EST_ADVANCEQUEUE ============================
size_t size_49_49 = 0;

static uint8_t *get_data_49_49() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_49() { return size_49_49;}

// ==== EST_FETCHQTD ============================
size_t size_49_50 = 0;

static uint8_t *get_data_49_50() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_50() { return size_49_50;}

// ==== EST_HORIZONTALQH ============================
size_t size_49_53 = 0;

static uint8_t *get_data_49_53() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_53() { return size_49_53;}

// ==== EST_EXECUTE ============================
size_t size_49_51 = 0;

static uint8_t *get_data_49_51() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_51() { return size_49_51;}

// ==== EST_EXECUTING ============================
size_t size_49_42 = 0;

static uint8_t *get_data_49_42() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_42() { return size_49_42;}

// ==== EST_WRITEBACK ============================
size_t size_49_52 = 0;

static uint8_t *get_data_49_52() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_52() { return size_49_52;}

// ==== EST_INACTIVE ============================
size_t size_49_40 = 0;

static uint8_t *get_data_49_40() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    return Data;
}

static size_t get_size_49_40() { return size_49_40;}

// ==== EST_ACTIVE ============================
size_t size_49_41 = 0;

static uint8_t *get_data_49_41() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    uint64_t base = stateful_malloc(0x3000, /*chained=*/true);
    stateful_lock(base, 0x2000 >> 1);
    uint64_t entry = stateful_require(0x1000);
    uint8_t *tmp_8955864a = (uint8_t *)malloc(0x2000 >> 1);
    for (int i = 0; i < 0x2000 >> 1; i++)
        (uint32_t *)tmp_8955864a[i] = (uint32_t)entry;
    size_49_41 += serialize(Data, size_49_41, 4096, INTERFACE_MEM_WRITE, base, 0x2000 >> 1, (uint8_t *)&tmp_8955864a);
    free(tmp_8955864a);
    uint64_t tmp_98f76d3f = base;
    size_49_41 += serialize(Data, size_49_41, 4096, 2, 0x16, 0x4, (uint8_t *)&tmp_98f76d3f);
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
