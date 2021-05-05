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

uint32_t get_data_from_pool4(void);

// ==== EST_INACTIVE ============================
size_t size_185_40 = 0;

static uint8_t *get_data_185_40() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_40() { return size_185_40;}

// ==== EST_ACTIVE ============================
size_t size_185_41 = 0;

static uint8_t *get_data_185_41() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    uint64_t entry_addr = stateful_malloc(0x3000, /*chained=*/false);
    stateful_lock(entry_addr, 0x1FF8 >> 1);
    uint64_t chained_addr = stateful_malloc(0x3000, /*chained=*/true);
    stateful_commit(chained_addr);
    tmp = 0;
    size_185_41 += serialize(Data, size_185_41, 4096, 0, entry_addr, 0x3000, (uint8_t *)&tmp);
    tmp = chained_addr;
    size_185_41 += serialize(Data, size_185_41, 4096, 2, entry_addr, 0x1FF8 >> 1, (uint8_t *)&tmp);
    tmp = entry_addr;
    size_185_41 += serialize(Data, size_185_41, 4096, 5, 22, 4, (uint8_t *)&tmp);
    return Data;
}

static size_t get_size_185_41() { return size_185_41;}

// ==== EST_EXECUTING ============================
size_t size_185_42 = 0;

static uint8_t *get_data_185_42() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_42() { return size_185_42;}

// ==== EST_WAITLISTHEAD ============================
size_t size_185_44 = 0;

static uint8_t *get_data_185_44() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    uint64_t EHCIqh_addr = stateful_malloc(0x3000, /*chained=*/false);
    tmp = 0;
    size_185_44 += serialize(Data, size_185_44, 4096, 0, 0x100000, 0x3000, (uint8_t *)&tmp);
    tmp = EHCIqh_addr;
    size_185_44 += serialize(Data, size_185_44, 4096, 5, 22, 4, (uint8_t *)&tmp);
    return Data;
}

static size_t get_size_185_44() { return size_185_44;}

// ==== EST_FETCHENTRY ============================
size_t size_185_45 = 0;

static uint8_t *get_data_185_45() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_45() { return size_185_45;}

// ==== EST_FETCHQH ============================
size_t size_185_46 = 0;

static uint8_t *get_data_185_46() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    uint64_t EHCIqh_addr = stateful_malloc(48, /*chained=*/true);
    uint64_t EHCIqtd_addr = stateful_malloc(32, /*chained=*/false);
    tmp = EHCIqtd_addr;
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 0, 4, (uint8_t *)&tmp);
    tmp = EHCIqtd_addr;
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 4, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 8, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 12, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 16, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 20, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 24, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 28, 4, (uint8_t *)&tmp);
    tmp = EHCIqh_addr;
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 0, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 4, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 8, 4, (uint8_t *)&tmp);
    tmp = EHCIqtd_addr;
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 12, 4, (uint8_t *)&tmp);
    tmp = EHCIqtd_addr;
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 16, 4, (uint8_t *)&tmp);
    tmp = EHCIqtd_addr;
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 20, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 24, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 28, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 32, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 36, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 40, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_46 += serialize(Data, size_185_46, 4096, 2, 44, 4, (uint8_t *)&tmp);
    return Data;
}

static size_t get_size_185_46() { return size_185_46;}

// ==== EST_FETCHITD ============================
size_t size_185_47 = 0;

static uint8_t *get_data_185_47() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    uint64_t EHCIitd_addr = stateful_malloc(64, /*chained=*/true);
    tmp = EHCIitd_addr;
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 0, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 4, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 8, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 12, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 16, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 20, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 24, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 28, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 32, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 36, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 40, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 44, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 48, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 52, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 56, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_47 += serialize(Data, size_185_47, 4096, 2, 60, 4, (uint8_t *)&tmp);
    return Data;
}

static size_t get_size_185_47() { return size_185_47;}

// ==== EST_FETCHSITD ============================
size_t size_185_48 = 0;

static uint8_t *get_data_185_48() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    uint64_t EHCIsitd_addr = stateful_malloc(28, /*chained=*/true);
    tmp = EHCIsitd_addr;
    size_185_48 += serialize(Data, size_185_48, 4096, 2, 0, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_48 += serialize(Data, size_185_48, 4096, 2, 4, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_48 += serialize(Data, size_185_48, 4096, 2, 8, 4, (uint8_t *)&tmp);
    tmp = get_data_from_pool4();
    size_185_48 += serialize(Data, size_185_48, 4096, 2, 12, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_48 += serialize(Data, size_185_48, 4096, 2, 16, 4, (uint8_t *)&tmp);
    tmp = stateful_malloc(0x100, /*chained=*/false);
    size_185_48 += serialize(Data, size_185_48, 4096, 2, 20, 4, (uint8_t *)&tmp);
    tmp = EHCIsitd_addr;
    size_185_48 += serialize(Data, size_185_48, 4096, 2, 24, 4, (uint8_t *)&tmp);
    return Data;
}

static size_t get_size_185_48() { return size_185_48;}

// ==== EST_ADVANCEQUEUE ============================
size_t size_185_49 = 0;

static uint8_t *get_data_185_49() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_49() { return size_185_49;}

// ==== EST_FETCHQTD ============================
size_t size_185_50 = 0;

static uint8_t *get_data_185_50() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_50() { return size_185_50;}

// ==== EST_EXECUTE ============================
size_t size_185_51 = 0;

static uint8_t *get_data_185_51() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_51() { return size_185_51;}

// ==== EST_WRITEBACK ============================
size_t size_185_52 = 0;

static uint8_t *get_data_185_52() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_52() { return size_185_52;}

// ==== EST_HORIZONTALQH ============================
size_t size_185_53 = 0;

static uint8_t *get_data_185_53() {
    uint8_t *Data = (uint8_t *)malloc(4096);
    uint64_t tmp;
    
    return Data;
}

static size_t get_size_185_53() { return size_185_53;}

static StateMachine state_machines[] = {
    [185] = {
        .id = 185,
        .name = "pstate",
        .nodes = {
            [40] = {
                .id = 40,
                .get_data = get_data_185_40,
                .get_size = get_size_185_40,
            }, [41] = {
                .id = 41,
                .get_data = get_data_185_41,
                .get_size = get_size_185_41,
            }, [42] = {
                .id = 42,
                .get_data = get_data_185_42,
                .get_size = get_size_185_42,
            }, [44] = {
                .id = 44,
                .get_data = get_data_185_44,
                .get_size = get_size_185_44,
            }, [45] = {
                .id = 45,
                .get_data = get_data_185_45,
                .get_size = get_size_185_45,
            }, [46] = {
                .id = 46,
                .get_data = get_data_185_46,
                .get_size = get_size_185_46,
            }, [47] = {
                .id = 47,
                .get_data = get_data_185_47,
                .get_size = get_size_185_47,
            }, [48] = {
                .id = 48,
                .get_data = get_data_185_48,
                .get_size = get_size_185_48,
            }, [49] = {
                .id = 49,
                .get_data = get_data_185_49,
                .get_size = get_size_185_49,
            }, [50] = {
                .id = 50,
                .get_data = get_data_185_50,
                .get_size = get_size_185_50,
            }, [51] = {
                .id = 51,
                .get_data = get_data_185_51,
                .get_size = get_size_185_51,
            }, [52] = {
                .id = 52,
                .get_data = get_data_185_52,
                .get_size = get_size_185_52,
            }, [53] = {
                .id = 53,
                .get_data = get_data_185_53,
                .get_size = get_size_185_53,
            }, 
        }
    },
}; 

#endif /* STATEFUL_FUZZ_SMS_H */
