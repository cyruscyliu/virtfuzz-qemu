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
    uint64_t tmp_8c4e7e65 = EHCIqh;
    size_49_44 += serialize(Data, size_49_44, 4096, 3, 0x16, 0x4, (uint8_t *)&tmp_8c4e7e65);
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
    uint64_t tmp_dfc68778 = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 0, 0x4, (uint8_t *)&tmp_dfc68778);
    uint64_t tmp_bc0e5404 = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 4, 0x4, (uint8_t *)&tmp_bc0e5404);
    uint64_t tmp_bc927bbb = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 8, 0x4, (uint8_t *)&tmp_bc927bbb);
    uint64_t tmp_b04997ab = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 12, 0x4, (uint8_t *)&tmp_b04997ab);
    uint64_t tmp_4fddbf10 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 16, 0x4, (uint8_t *)&tmp_4fddbf10);
    uint64_t tmp_091c7961 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 20, 0x4, (uint8_t *)&tmp_091c7961);
    uint64_t tmp_8730c5c6 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 24, 0x4, (uint8_t *)&tmp_8730c5c6);
    uint64_t tmp_18767a77 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 28, 0x4, (uint8_t *)&tmp_18767a77);
    uint64_t tmp_66c65947 = EHCIqh;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 0, 0x4, (uint8_t *)&tmp_66c65947);
    uint64_t tmp_3dfd8d84 = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 4, 0x4, (uint8_t *)&tmp_3dfd8d84);
    uint64_t tmp_cd68a23f = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 8, 0x4, (uint8_t *)&tmp_cd68a23f);
    uint64_t tmp_b1cacfed = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 12, 0x4, (uint8_t *)&tmp_b1cacfed);
    uint64_t tmp_afff9025 = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 16, 0x4, (uint8_t *)&tmp_afff9025);
    uint64_t tmp_ca52b4a8 = EHCIqtd;
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 20, 0x4, (uint8_t *)&tmp_ca52b4a8);
    uint64_t tmp_dc78e503 = get_data_from_pool4();
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 24, 0x4, (uint8_t *)&tmp_dc78e503);
    uint64_t tmp_58f326d3 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 28, 0x4, (uint8_t *)&tmp_58f326d3);
    uint64_t tmp_a1dfdf38 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 32, 0x4, (uint8_t *)&tmp_a1dfdf38);
    uint64_t tmp_d7596842 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 36, 0x4, (uint8_t *)&tmp_d7596842);
    uint64_t tmp_478a8c4e = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 40, 0x4, (uint8_t *)&tmp_478a8c4e);
    uint64_t tmp_beeab835 = stateful_malloc(0x100, /*chained=*/false);
    size_49_46 += serialize(Data, size_49_46, 4096, 2, 44, 0x4, (uint8_t *)&tmp_beeab835);
    return Data;
}

static size_t get_size_49_46() { return size_49_46;}

// ==== EST_FETCHITD ============================
size_t size_49_47 = 0;

static uint8_t *get_data_49_47() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    uint64_t EHCIitd = stateful_require(64);
    uint64_t tmp_2507b0bc = EHCIitd;
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 0, 0x4, (uint8_t *)&tmp_2507b0bc);
    uint64_t tmp_a050333d = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 4, 0x4, (uint8_t *)&tmp_a050333d);
    uint64_t tmp_ef3f0c7c = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 8, 0x4, (uint8_t *)&tmp_ef3f0c7c);
    uint64_t tmp_c56fc429 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 12, 0x4, (uint8_t *)&tmp_c56fc429);
    uint64_t tmp_587820af = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 16, 0x4, (uint8_t *)&tmp_587820af);
    uint64_t tmp_c639e6e7 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 20, 0x4, (uint8_t *)&tmp_c639e6e7);
    uint64_t tmp_9c7590df = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 24, 0x4, (uint8_t *)&tmp_9c7590df);
    uint64_t tmp_d911c263 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 28, 0x4, (uint8_t *)&tmp_d911c263);
    uint64_t tmp_73916f78 = get_data_from_pool4();
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 32, 0x4, (uint8_t *)&tmp_73916f78);
    uint64_t tmp_400829f3 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 36, 0x4, (uint8_t *)&tmp_400829f3);
    uint64_t tmp_e0b27b8b = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 40, 0x4, (uint8_t *)&tmp_e0b27b8b);
    uint64_t tmp_9d87c89f = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 44, 0x4, (uint8_t *)&tmp_9d87c89f);
    uint64_t tmp_d9ad74d9 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 48, 0x4, (uint8_t *)&tmp_d9ad74d9);
    uint64_t tmp_02fa6add = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 52, 0x4, (uint8_t *)&tmp_02fa6add);
    uint64_t tmp_93a51171 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 56, 0x4, (uint8_t *)&tmp_93a51171);
    uint64_t tmp_ec689432 = stateful_malloc(0x100, /*chained=*/false);
    size_49_47 += serialize(Data, size_49_47, 4096, 2, 60, 0x4, (uint8_t *)&tmp_ec689432);
    return Data;
}

static size_t get_size_49_47() { return size_49_47;}

// ==== EST_FETCHSITD ============================
size_t size_49_48 = 0;

static uint8_t *get_data_49_48() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    
    uint64_t EHCIsitd = stateful_require(28);
    uint64_t tmp_325613c8 = EHCIsitd;
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 0, 0x4, (uint8_t *)&tmp_325613c8);
    uint64_t tmp_784d242a = get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 4, 0x4, (uint8_t *)&tmp_784d242a);
    uint64_t tmp_80ca6887 = get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 8, 0x4, (uint8_t *)&tmp_80ca6887);
    uint64_t tmp_f8647642 = get_data_from_pool4();
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 12, 0x4, (uint8_t *)&tmp_f8647642);
    uint64_t tmp_ba58b12f = stateful_malloc(0x100, /*chained=*/false);
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 16, 0x4, (uint8_t *)&tmp_ba58b12f);
    uint64_t tmp_14d608ad = stateful_malloc(0x100, /*chained=*/false);
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 20, 0x4, (uint8_t *)&tmp_14d608ad);
    uint64_t tmp_e6e75806 = EHCIsitd;
    size_49_48 += serialize(Data, size_49_48, 4096, 2, 24, 0x4, (uint8_t *)&tmp_e6e75806);
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
    uint32_t *tmp_523b25c6 = (uint32_t *)malloc((0x2000 >> 1));
    for (int i = 0; i < (0x2000 >> 1) / 4; i++)
        tmp_523b25c6[i] = (uint32_t)entry;
    size_49_41 += serialize(Data, size_49_41, 4096, INTERFACE_MEM_WRITE, base, 0x2000 >> 1, (uint8_t *)&tmp_523b25c6);
    free(tmp_523b25c6);
    uint64_t tmp_ba0b4fee = base;
    size_49_41 += serialize(Data, size_49_41, 4096, 2, 0x16, 0x4, (uint8_t *)&tmp_ba0b4fee);
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
