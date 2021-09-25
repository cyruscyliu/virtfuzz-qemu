/*
 * Stateful Virtual-Device Fuzzing Target
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <qiangliu@zju.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef STATEFUL_FUZZ_H
#define STATEFUL_FUZZ_H

#include "qemu/osdep.h"
#include <wordexp.h>
#include "hw/core/cpu.h"
#include "tests/qtest/libqos/libqtest.h"
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

// +-----+-----+-----+
// +    libfuzzer    +
// +-----+-----+-----+
// +      input      + <- core
// +-----+-----+-----+
// +event+event+event+ <- core
// +-----+-----+-----+
// + inf + inf + inf +
// +-----+-----+-----+
// +      qtest      +
// +-----+-----+-----+
// +     virtdev     +
// +-----+-----+-----+

// +-----------------+
// +      event      +
// +-----------------+
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

// +-----------------+
// +     inf_ops     +
// +-----------------+
static void printf_event_description() {
    for (int i = 0; i < n_interfaces; i++) {
        InterfaceDescription ed = Id_Description[i];
        fprintf(stderr, "  * %s, %s, 0x%lx +0x%x, %d,%d\n",
                ed.name, EventTypeNames[ed.type],
                ed.emb.addr, ed.emb.size,
                ed.min_access_size, ed.max_access_size);
    }
}

static uint8_t get_possible_interface(EventType type) {
    // first best
    if (type != EVENT_TYPE_CLOCK_STEP && type != EVENT_TYPE_SOCKET_WRITE) {
        for (int i = 0; i < n_interfaces; i++) {
            if (Id_Description[i].type == type)
                return i;
        }
    }
    return type % 2 ? INTERFACE_CLOCK_STEP : INTERFACE_SOCKET_WRITE;
}

static int get_interface_id(const char *name, EventType type) {
    // first best
    int i;
    InterfaceDescription ed;
    for (i = 0; i < n_interfaces; i++) {
        ed = Id_Description[i];
        if (ed.type == type && g_strcmp0(ed.name, name) == 0) {
            return i;
        }
    }
    fprintf(stderr, "cannot find a valid interface\n");
    _Exit(0);
}

// +-----------------+
// +    event_ops    +
// +-----------------+
static void printf_event(Event *event) {
    fprintf(stderr, "  * %d, %s", event->id, EventTypeNames[event->type]);
    switch(event->type) {
        case EVENT_TYPE_MMIO_READ:
        case EVENT_TYPE_PIO_READ:
        case EVENT_TYPE_MEM_READ:
        case EVENT_TYPE_MEM_WRITE:
            fprintf(stderr, ", 0x%lx, 0x%x\n", event->addr, event->size);
            break;
        case EVENT_TYPE_SOCKET_WRITE:
        case EVENT_TYPE_DATA_POOL:
            fprintf(stderr, ", 0x%x\n", event->size);
            break;
        case EVENT_TYPE_MMIO_WRITE:
        case EVENT_TYPE_PIO_WRITE:
            fprintf(stderr, ", 0x%lx, 0x%x", event->addr, event->size);
            fprintf(stderr, ", 0x%lx\n", event->val);
            break;
        case EVENT_TYPE_CLOCK_STEP:
            fprintf(stderr, ", 0x%lx\n", event->val);
            break;
        default:
            fprintf(stderr, "wrong type of event %d\n", event->type);
    }
}

static uint8_t around_event_id(uint8_t id) {
    if (id == INTERFACE_MEM_READ ||
            id == INTERFACE_MEM_WRITE ||
            id == INTERFACE_DATA_POOL ||
            id == INTERFACE_CLOCK_STEP ||
            id == INTERFACE_SOCKET_WRITE)
        return id;
    return id % n_interfaces;
}

static uint64_t around_event_addr(uint8_t id, uint64_t raw_addr) {
    if (id == INTERFACE_MEM_READ ||
            id == INTERFACE_MEM_WRITE ||
            id == INTERFACE_DATA_POOL ||
            id == INTERFACE_CLOCK_STEP ||
            id == INTERFACE_SOCKET_WRITE)
        return raw_addr;
    InterfaceDescription ed = Id_Description[id];
    // only rtl3189 has one-byte aligned address
    if (getenv("QEMU_BYTE_ADDRESS")) {
        return (ed.emb.addr + raw_addr % ed.emb.size) & 0xFFFFFFFFFFFFFFFF;
    } else {
        return (ed.emb.addr + raw_addr % ed.emb.size) & 0xFFFFFFFFFFFFFFFC;
    }
}

static uint32_t around_event_size(uint8_t id, uint8_t type, uint32_t raw_size) {
    InterfaceDescription ed;
    uint8_t diff;
    switch (type) {
        case EVENT_TYPE_MMIO_READ:
        case EVENT_TYPE_MMIO_WRITE:
        case EVENT_TYPE_PIO_READ:
        case EVENT_TYPE_PIO_WRITE:
            ed = Id_Description[id];
            diff = ed.max_access_size - ed.min_access_size + 1;
            return pow2floor(((raw_size - ed.min_access_size) % diff) + ed.min_access_size);
        case EVENT_TYPE_MEM_READ:
        case EVENT_TYPE_MEM_WRITE:
        case EVENT_TYPE_SOCKET_WRITE:
        case EVENT_TYPE_DATA_POOL:
            return raw_size;
        default:
            fprintf(stderr, "wrong type of event %d\n", type);
            return 0;
    }
}

static uint8_t around_event_type(uint8_t raw_type) {
    if (raw_type == EVENT_TYPE_MEM_READ ||
            raw_type == EVENT_TYPE_MEM_WRITE ||
            raw_type == EVENT_TYPE_DATA_POOL)
        return raw_type;
    return raw_type % N_VALID_TYPES;
}

static uint32_t serialize(uint8_t *Data, size_t Offset, size_t MaxSize,
        uint8_t id, uint64_t addr, uint32_t size, uint8_t *val) {
    uint8_t type;
    InterfaceDescription ed = Id_Description[id];
    type = around_event_type(ed.type);
    switch (type) {
        case EVENT_TYPE_MMIO_READ:
        case EVENT_TYPE_PIO_READ:
            if (Offset + 13 >= MaxSize)
                return 0;
            Data[Offset] = id;
            memcpy(Data + Offset + 1, (uint8_t *)&addr, 8);
            memcpy(Data + Offset + 9, (uint8_t *)&size, 4);
            return 13;
        case EVENT_TYPE_PIO_WRITE:
        case EVENT_TYPE_MMIO_WRITE:
            if (Offset + 21 >= MaxSize)
                return 0;
            Data[Offset] = id;
            memcpy(Data + Offset + 1, (uint8_t *)&addr, 8);
            memcpy(Data + Offset + 9, (uint8_t *)&size, 4);
            memcpy(Data + Offset + 13, (uint8_t *)val, 8);
            return 21;
        case EVENT_TYPE_MEM_READ:
        case EVENT_TYPE_MEM_WRITE:
            if (Offset + 13 + size >= MaxSize)
                return 0;
            Data[Offset] = id;
            memcpy(Data + Offset + 1, (uint8_t *)&addr, 8);
            memcpy(Data + Offset + 9, (uint8_t *)&size, 4);
            if (type == EVENT_TYPE_MEM_READ)
                memset(Data + Offset + 13, 0, size);
            else
                memcpy(Data + Offset + 13, (uint8_t *)val, size);
            return 13 + size;
        case EVENT_TYPE_SOCKET_WRITE:
        case EVENT_TYPE_DATA_POOL:
            if (Offset + 5 + size >= MaxSize)
                return 0;
            Data[Offset] = id;
            memcpy(Data + Offset + 1, (uint8_t *)&size, 4);
            memcpy(Data + Offset + 5, (uint8_t *)val, size);
            return 5 + size;
        case EVENT_TYPE_CLOCK_STEP:
            if (Offset + 9 >= MaxSize)
                return 0;
            Data[Offset] = id;
            memcpy(Data + Offset + 1, (uint8_t *)val, 8);
            return 9;
        default:
            fprintf(stderr, "Unsupport Event Type (serialize)\n");
            return 0;
    }
}

#define DATA_POOL_MAXSIZE 4096
// Specially, we have to put one EVENT_TYPE_DATA_POOL event
// at the end of the input and make it a fuzzy data pool.
#define SERIALIZE(id, addr, size, value) \
    serialize(Data, Offset, DATA_POOL_MAXSIZE, id, addr, size, (uint8_t *)&value)
static size_t reset_data(uint8_t *Data, size_t MaxSize) {
    size_t Offset = 0;
    uint64_t null = 0;
    InterfaceDescription ed;
    // we first call each interface one by one
    for (int i = 0; i < n_interfaces; ++i) {
        ed = Id_Description[i];
        switch(ed.type) {
            case EVENT_TYPE_MMIO_READ:
            case EVENT_TYPE_PIO_READ:
                // EVENT_TYPE_X_READ  addr=0 size=4
                Offset += SERIALIZE(i, 0x0, 0x4, null);
                break;
            case EVENT_TYPE_MMIO_WRITE:
            case EVENT_TYPE_PIO_WRITE:
                // EVENT_TYPE_X_WRITE addr=0 size=4
                Offset += SERIALIZE(i, 0x0, 0x4, null);
                break;
            default:
                continue;
        }
    }
    // EVENT_TYPE_CLOCK_STEP step=0x100
    uint64_t clock_step = CLOCK_MAX_STEP;
    Offset += SERIALIZE(INTERFACE_CLOCK_STEP, 0x0, 0x0, clock_step);
    // EVENT_TYPE_SOCKET_WRITE size=13 Data=\0x00... (13 repeated \x00)
    Offset += serialize(Data, Offset, MaxSize, INTERFACE_SOCKET_WRITE, 0, 13, Data);
    // EVENT_TYPE_DATA_POOL size=13 Data=\x00... (13 repeated \x00)
    // cannot use SERIALIZE because Data is a pointer
    Offset += serialize(Data, Offset, MaxSize, INTERFACE_DATA_POOL, 0, 13, Data);
    return Offset;
}

static void good_input(void) {
/*
    uint64_t portsc_preset = 1 << 8;
    uint64_t portsc_ped = 1 << 2;
    uint64_t usbcmd_runstop_or_usbcmd_pse = (1 << 0) | (1 << 4);
    Offset += SERIALIZE(5, 0x0, 4, portsc_preset);
    Offset += SERIALIZE(5, 0x0, 4, portsc_ped);
    Offset += SERIALIZE(3, 0x0, 4, usbcmd_runstop_or_usbcmd_pse);
    uint64_t clock_step = 0x100;
    Offset += SERIALIZE(INTERFACE_CLOCK_STEP, 0x0, 0x0, clock_step);
    // Offset += SERIALIZE(5, 0x0, 4, portsc_preset);
    // Offset += SERIALIZE(5, 0x0, 4, portsc_ped);
    // Offset += SERIALIZE(3, 0x0, 4, usbcmd_runstop_or_usbcmd_pse);
    // Offset += SERIALIZE(INTERFACE_CLOCK_STEP, 0x0, 0x0, clock_step);
    */
}

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
    /*
    uint32_t ret = (uint32_t)rand();
    switch (size) {
        case 1:
            return ret % 0xff;
        case 2:
            return ret % 0xffff;
        case 4:
            return ret % 0xffffffff;
        default:
            fprintf(stderr, "Wrong size of get_data_from_pool: %d\n", size);
            return 0xffffffff;
    }
    */
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

// +-----------------+
// +    input_ops    +
// +-----------------+
static uint32_t get_event_size(Input *input, uint32_t index) {
    // event->next, event->event_size are used
    Event *event = input->events;
    for (int i = 0; i < index; i++) {
        if (!event->next)
            break;
        event = event->next;
    }
    return event->event_size;
}

static uint32_t get_event_offset(Input *input, uint32_t index) {
    // event->next, event->offset are used
    Event *event = input->events;
    for (int i = 0; i < index; i++) {
        if (!event->next)
            break;
        event = event->next;
    }
    return event->offset;
}

static Event *get_event(Input *input, uint32_t index) {
    Event *event = input->events;
    for (int i = 0; i != index; i++)
        event = event->next;
    return event;
}

static bool input_check_index(Input* input, int request) {
    if (input->index + request > input->limit) {
        return false;
    }
    return true;
}

static void input_next(Input* input, void* buf, size_t size) {
    // littile-endian
    memcpy(buf, input->buf + input->index, size);
    input->index += size;
}

#define CONSUME_INPUT_NEXT(sz) \
    static uint##sz##_t input_next_##sz(Input* input) { \
    uint##sz##_t ch = 0; \
    input_next(input, &ch, sizeof(ch)); \
    return ch; \
}

CONSUME_INPUT_NEXT(8);
CONSUME_INPUT_NEXT(16);
CONSUME_INPUT_NEXT(32);
CONSUME_INPUT_NEXT(64);
CONSUME_INPUT_NEXT(ptr);

static Input *init_input(const uint8_t *Data, size_t Size) {
    if (Size < 13)
        return NULL;
    Input *input = (Input *)malloc(sizeof(Input));
    input->limit = Size;
    input->buf = (void *)malloc(Size);
    memcpy(input->buf, Data, Size);
    input->index = 0;
    input->events = NULL;
    input->n_events = 0;
    return input;
}

static void append_event(Input *input, Event *event) {
    Event *last_event = input->events;
    if (!last_event) {
        input->events = event;
    } else {
        while (last_event->next) {
            last_event = last_event->next;
        }
        last_event->next = event;
    }
    event->next = NULL;
    input->n_events++;
}

static void free_events(Input *input, bool indexer) {
    Event *events = input->events, *tmp;
    while ((tmp = events)) {
        switch (tmp->type) {
            case EVENT_TYPE_MEM_READ:
            case EVENT_TYPE_MEM_WRITE:
            case EVENT_TYPE_SOCKET_WRITE:
            case EVENT_TYPE_DATA_POOL:
                free(tmp->data);
        }
        events = events->next;
        free(tmp);
    }
}

static void free_input(Input *input, bool indexer) {
    free(input->buf);
    free_events(input, indexer);
    free(input);
}

static uint32_t deserialize(Input *input, bool indexer) {
    uint8_t id, type;
    uint64_t addr, val;
    uint32_t size, DataSize = 0;
    Event *event = NULL;
    uint8_t *Data;
    while (input_check_index(input, 1)) {
        id = around_event_id(input_next_8(input));
        InterfaceDescription ed = Id_Description[id];
        type = around_event_type(ed.type);
        switch (type) {
            case EVENT_TYPE_MMIO_READ:
            case EVENT_TYPE_PIO_READ:
                //   1B   8B   4B
                // +----+----+----+
                // + ID +ADDR+SIZE+
                // +----+----+----+
                if (!input_check_index(input, 8 + 4)) {
                    input->index--;
                    return DataSize;
                }
                addr = input_next_64(input);
                size = input_next_32(input);
                event = (Event *)malloc(sizeof(Event));
                event->id = id;
                event->type = type;
                event->addr = around_event_addr(id, addr);
                event->size = around_event_size(id, type, size);
                event->pad = 0;
                event->offset = DataSize;
                event->event_size = 13;
                append_event(input, event);
                DataSize += 13;
                break;
            case EVENT_TYPE_PIO_WRITE:
            case EVENT_TYPE_MMIO_WRITE:
                //   1B   8B   4B   8B
                // +----+----+----+----+
                // + ID +ADDR+SIZE+VALU+
                // +----+----+----+----+
                if (!input_check_index(input, 8 + 4 + 8)) {
                    input->index--;
                    return DataSize;
                }
                addr = input_next_64(input);
                size = input_next_32(input);
                val = input_next_64(input);
                event = (Event *)malloc(sizeof(Event));
                event->id = id;
                event->type = type;
                event->addr = around_event_addr(id, addr);
                event->size = around_event_size(id, type, size);
                event->val = val;
                event->offset = DataSize;
                event->event_size = 21;
                append_event(input, event);
                DataSize += 21;
                break;
            case EVENT_TYPE_MEM_READ:
            case EVENT_TYPE_MEM_WRITE:
                //   1B   8B   4B   XB
                // +----+----+----+----+
                // + ID +ADDR+SIZE+DATA+
                // +----+----+----+----+
                if (!input_check_index(input, 8 + 4)) {
                    input->index--;
                    return DataSize;
                }
                addr = input_next_64(input);
                size = input_next_32(input);
                if (!input_check_index(input, size)) {
                    input->index--;
                    return DataSize;
                }
                Data = (uint8_t *)malloc(size);
                input_next(input, Data, size);
                event = (Event *)malloc(sizeof(Event));
                event->id = id;
                event->type = type;
                event->addr = around_event_addr(id, addr);
                event->size = around_event_size(id, type, size);
                event->data = Data;
                event->offset = DataSize;
                event->event_size = size + 13;
                append_event(input, event);
                DataSize += (size + 13);
                break;
            case EVENT_TYPE_SOCKET_WRITE:
            case EVENT_TYPE_DATA_POOL:
                //   1B   4B   XB
                // +----+----+----+
                // + ID +SIZE+DATA+
                // +----+----+----+
                if (!input_check_index(input, 4)) {
                    input->index--;
                    return DataSize;
                }
                size = input_next_32(input);
                if (!input_check_index(input, size)) {
                    input->index--;
                    return DataSize;
                }
                Data = (uint8_t *)malloc(size);
                input_next(input, Data, size);
                event = (Event *)malloc(sizeof(Event));
                event->id = id;
                event->type = type;
                event->addr = 0xFFFFFFFFFFFFFFFF;
                event->size = around_event_size(id, type, size);
                event->data = Data;
                event->offset = DataSize;
                event->event_size = size + 5;
                append_event(input, event);
                DataSize += (size + 5);
                break;
            case EVENT_TYPE_CLOCK_STEP:
                //   1B   8B
                // +----+----+
                // + ID +VALU+
                // +----+----+
                if (!input_check_index(input, 8)) {
                    input->index--;
                    return DataSize;
                }
                val = input_next_64(input);
                event = (Event *)malloc(sizeof(Event));
                event->id = id;
                event->type = type;
                event->addr = 0xFFFFFFFFFFFFFFFF;
                event->size = 0xFFFFFFFF;
                event->val = val % CLOCK_MAX_STEP;
                event->offset = DataSize;
                event->event_size = 9;
                append_event(input, event);
                DataSize += 9;
                break;
            default:
                fprintf(stderr, "Unsupport Event Type (deserialize)\n");
        }
    }
    return DataSize;
}

// P.S. "stateful" is only a mark here.
static QGuestAllocator *stateful_alloc;

#define CHAINED_ADDR_UNALLOCATED 0
#define CHAINED_ADDR_UNCOMMITTED 1
#define CHAINED_ADDR_COMMITTED   2

typedef struct ChainedAddr {
    uint64_t addr;
    size_t size;
    uint8_t committed;
} ChainedAddr;

typedef struct ChainedBuffer {
    uint64_t addr;
    size_t size;
    size_t lock_size;
    size_t dirty_size;
    ChainedAddr chained_addr;
} ChainedBuffer;

typedef struct StatefulMemoryPool {
    ChainedBuffer chained_buffers[8];
    uint8_t valid;
} StatefulMemoryPool;

static StatefulMemoryPool stateful_memory_pool;

static void stateful_memory_pool_init(void) {
    StatefulMemoryPool *smp = &stateful_memory_pool;
    memset(smp, 0, sizeof(StatefulMemoryPool));
    smp->valid = -1;
}

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
    if (!chained)
        return __wrap_guest_alloc(size);

    StatefulMemoryPool *smp = &stateful_memory_pool;
    smp->valid = (smp->valid + 1) % 8;
    ChainedBuffer *chained_buffer = &smp->chained_buffers[smp->valid];
    uint64_t addr = __wrap_guest_alloc(size);
    chained_buffer->addr = addr;
    chained_buffer->size = size;
    chained_buffer->chained_addr.committed = CHAINED_ADDR_UNALLOCATED;
    return addr;
}

static ChainedBuffer *get_valid_chained_buffer(uint64_t addr) {
    ChainedBuffer *chained_buffer;
    int i;

    StatefulMemoryPool *smp = &stateful_memory_pool;
    for (i = 0; i < smp->valid + 1; i++) {
        chained_buffer = &smp->chained_buffers[i];
        if (chained_buffer->addr == addr)
            break;
    }
    if (i == smp->valid + 1)
        return NULL;
    return chained_buffer;
}

static bool stateful_free(uint64_t addr) {
    // give back the guest memory
    __wrap_guest_free(addr);
    ChainedBuffer *chained_buffer = get_valid_chained_buffer(addr);
    if (!chained_buffer)
        return false;
    memset(chained_buffer, 0, sizeof(ChainedBuffer));
    return true;
}

static bool stateful_lock(uint64_t addr, size_t size) {
    ChainedBuffer *chained_buffer = get_valid_chained_buffer(addr);
    if (!chained_buffer)
        return false;
    chained_buffer->lock_size = size;
    if (chained_buffer->dirty_size < size)
        chained_buffer->dirty_size = size;
    return true;
}

static uint64_t stateful_require(size_t size) {
    StatefulMemoryPool *smp = &stateful_memory_pool;
    ChainedBuffer *chained_buffer = &smp->chained_buffers[smp->valid];
    switch (chained_buffer->chained_addr.committed) {
        case CHAINED_ADDR_UNCOMMITTED:
            return chained_buffer->chained_addr.addr;
        case CHAINED_ADDR_COMMITTED:
        case CHAINED_ADDR_UNALLOCATED:
            if (size + chained_buffer->dirty_size >= chained_buffer->size)
                return 0;
            chained_buffer->chained_addr.addr =
                chained_buffer->addr + chained_buffer->dirty_size;
            chained_buffer->chained_addr.size = size;
            chained_buffer->chained_addr.committed = CHAINED_ADDR_UNCOMMITTED;
            chained_buffer->dirty_size += size;
            return chained_buffer->chained_addr.addr;
        default:
            return 0;
    }
}

static bool stateful_commit(uint64_t addr) {
    ChainedBuffer *chained_buffer = get_valid_chained_buffer(addr);
    if (!chained_buffer)
        return false;
    chained_buffer->chained_addr.committed = CHAINED_ADDR_COMMITTED;
    return true;
}
#endif /* STATEFUL_FUZZ_H */
