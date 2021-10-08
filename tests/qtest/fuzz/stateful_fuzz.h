/*
 * Stateful Virtual-Device Fuzzing Target
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef STATEFUL_FUZZ_H
#define STATEFUL_FUZZ_H

#include "qemu/osdep.h"
#include <wordexp.h>
#include "hw/core/cpu.h"
#include "tests/qtest/libqtest.h"
#include "fuzz.h"
#include "qos_fuzz.h"
#include "fork_fuzz.h"
#include "exec/address-spaces.h"
#include "string.h"
#include "exec/memory.h"
#include "exec/ramblock.h"
#include "exec/address-spaces.h"
#include "hw/qdev-core.h"
#include "hw/pci/pci.h"
#include "hw/boards.h"

bool StatefulFuzzer;
static bool qtest_log_enabled;
static void usage(void);

#define DEFAULT_TIMEOUT_US 100000
#define USEC_IN_SEC 1000000000
static useconds_t timeout = DEFAULT_TIMEOUT_US;

static inline void handle_timeout(int sig) {
    if (qtest_log_enabled) {
        fprintf(stderr, "[Timeout]\n");
        fflush(stderr);
    }
    _Exit(0);
}

static GHashTable *fuzzable_memoryregions;
static GPtrArray *fuzzable_pci_devices;
extern QTestState *get_qtest_state(void);

extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
extern size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed);
extern void TraceStateCallback(uint8_t id);

#define N_VALID_TYPES 6
typedef enum {                          //DMIP
    EVENT_TYPE_MMIO_READ = 0,           //***-
    EVENT_TYPE_MMIO_WRITE,              //***-
    EVENT_TYPE_PIO_READ,                //***-
    EVENT_TYPE_PIO_WRITE,               //***-
#define CLOCK_MAX_STEP 1000000
    EVENT_TYPE_CLOCK_STEP,              //-**-
#define SOCKET_WRITE_MAX_SIZE 100
    EVENT_TYPE_SOCKET_WRITE = 5,        //-**-
    EVENT_TYPE_INT,
    // these two events are only used
    // in the event injection, such that
    // the mutator does not know them
    EVENT_TYPE_MEM_READ = 8,            //--*-
    EVENT_TYPE_MEM_WRITE,               //--*-
    // this event is an extension
    // and it is never dispatched,
    // such that the mutator does not
    // know it either
    EVENT_TYPE_DATA_POOL = 11,          //---*
} EventType;

const char *EventTypeNames[12] = {
    "EVENT_TYPE_MMIO_READ", // 0
    "EVENT_TYPE_MMIO_WRITE",
    "EVENT_TYPE_PIO_READ", // 2
    "EVENT_TYPE_PIO_WRITE",
    "EVENT_TYPE_CLOCK_STEP",
    "EVENT_TYPE_SOCKET_WRITE", // 5
    "EVENT_TYPE_INT",
    "EVNET_NONE",
    "EVENT_TYPE_MEM_READ", // 8
    "EVENT_TYPE_MEM_WRITE",
    "EVENT_NONE",
    "EVENT_TYPE_DATA_POOL", // 11
};

typedef struct Event {
    uint8_t id; /* interface id */
    uint8_t type; /* event type */
    uint32_t event_size; /* event size */
    uint32_t offset; /* event offset in the input */
    uint64_t addr; /* event data */
    uint32_t size; /* event data */
    union {
        uint64_t val; /* event data */
        uint64_t pad; /* event data */
        uint8_t *data;/* event data */
    };
    struct Event *next; /* event linker */
} Event;

// +-----------------+
// +      input      +
// +-----------------+
typedef struct {
    size_t limit; /* input size */
    void *buf; /* input data */
    int index; /* input cursor */
    Event *events; /* corresponding events */
    int n_events; /* number of events */
} Input;

// +-----------------+
// +    interface    +
// +-----------------+
typedef struct {
    uint64_t addr;
    uint32_t size;
} InterfaceMemBlock;

typedef struct {
    EventType type;
    InterfaceMemBlock emb;
    char name[32];
    uint8_t min_access_size;
    uint8_t max_access_size;
} InterfaceDescription;

static uint32_t n_interfaces = 0;

#define INTERFACE_MAX 124
// predefined interfaces one-to-one mapped from
// the transparent events, these interfaces are
// also transparent to the fuzzer
#define INTERFACE_MEM_READ      INTERFACE_MAX + 0
#define INTERFACE_MEM_WRITE     INTERFACE_MAX + 1
#define INTERFACE_CLOCK_STEP    INTERFACE_MAX + 2
#define INTERFACE_DATA_POOL     INTERFACE_MAX + 3
#define INTERFACE_SOCKET_WRITE  INTERFACE_MAX + 4
#define INTERFACE_END           INTERFACE_MAX + 5

// n interface -> 1 event
// 1 interface -> 1 event
static InterfaceDescription Id_Description[INTERFACE_END] = {
    [INTERFACE_MEM_READ] = {
        .type = EVENT_TYPE_MEM_READ,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "memread",
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_MEM_WRITE] = {
        .type = EVENT_TYPE_MEM_WRITE,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "memwrite",
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_DATA_POOL] = {
        .type = EVENT_TYPE_DATA_POOL,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "guest_alloc",
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_CLOCK_STEP] = {
        .type = EVENT_TYPE_CLOCK_STEP,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "clock_step",
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }, [INTERFACE_SOCKET_WRITE] = {
        .type = EVENT_TYPE_SOCKET_WRITE,
        .emb = {.addr = 0xFFFFFFFF, .size = 0xFFFFFFFF},
        .name = "socket_write",
        .min_access_size = 0xFF, .max_access_size = 0xFF,
    }
};

#define DATA_POOL_MAXSIZE 4096
typedef struct DataPool {
    uint8_t Data[DATA_POOL_MAXSIZE];
    size_t Size;
    uint32_t index;
} DataPool;

static DataPool data_pool = {
    .Data = {0},
    .Size = 0,
    .index = 0,
};

static uint32_t get_data_from_pool(int size) {
    // make it a circle
    uint32_t ret = 0;
    for (int i = 0; i < size; i++) {
        ret |= data_pool.Data[(data_pool.index + i) % data_pool.Size] << (8 * i);
    }
    data_pool.index += size;
    return ret;
}

static uint32_t get_data_from_pool4(void) {
    return get_data_from_pool(4);
}

static uint16_t get_data_from_pool2(void) {
    return (uint16_t)get_data_from_pool(2);
}

static uint8_t get_data_from_pool1(void) {
    return (uint8_t)get_data_from_pool(1);
}

static void set_data_pool(Event *data_pool_event) {
    data_pool.index = 0;
    data_pool.Size = data_pool_event->size;
    memcpy(data_pool.Data, data_pool_event->data, data_pool_event->size);
}

static void reset_data_pool(void) {
    memset(data_pool.Data, 0, DATA_POOL_MAXSIZE);
    data_pool.Size = 0;
    data_pool.index = 0;
}

// P.S. "stateful" is only a mark here.
static QGuestAllocator *stateful_alloc;

static uint64_t (*stateful_guest_alloc)(size_t) = NULL;
static void (*stateful_guest_free)(size_t) = NULL;

static uint64_t __wrap_guest_alloc(size_t size) {
    if (stateful_guest_alloc)
        return stateful_guest_alloc(size);
    else
        // alloc a dma accessible buffer in guest memory
        return guest_alloc(stateful_alloc, size);
}

static void __wrap_guest_free(uint64_t addr) {
    if (stateful_guest_free)
        stateful_guest_free(addr);
    else
        // free the dma accessible buffer in guest memory
        guest_free(stateful_alloc, addr);
}

static uint64_t stateful_malloc(size_t size, bool chained) {
    return __wrap_guest_alloc(size);
}

static bool stateful_free(uint64_t addr) {
    // give back the guest memory
    __wrap_guest_free(addr);
    return true;
}

#endif /* STATEFUL_FUZZ_H */
