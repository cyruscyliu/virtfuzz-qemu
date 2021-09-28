/*
 * Stateful Virtual-Device Fuzzing IO
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef STATEFUL_FUZZ_IO_H
#define STATEFUL_FUZZ_IO_H

enum Sizes {Empty, Byte0=1, Word=2, Long=4, Quad=8};

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

#endif /* STATEFUL_FUZZ_IO_H */