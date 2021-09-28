/*
 * Stateful Virtual-Device Fuzzing Dispatch
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef STATEFUL_FUZZ_DISPATCH_H
#define STATEFUL_FUZZ_DISPATCH_H

#include "stateful_fuzz.h"

/*
 * Generic MMIO Dispatcher.
 */
static void dispatch_mmio_read(QTestState *s, uint64_t addr, uint32_t size) {
    switch (size) {
        case Byte0:
            qtest_readb(s, addr);
            break;
        case Word:
            qtest_readw(s, addr);
            break;
        case Long:
            qtest_readl(s, addr);
            break;
        case Quad:
            qtest_readq(s, addr);
            break;
        default:
            fprintf(stderr, "wrong size of dispatch_mmio_read %d\n", size);
            break;
    }
}

/*
 * Generic PIO Dispatcher.
 */
static void dispatch_pio_read(QTestState *s, uint64_t addr, uint32_t size) {
    switch (size) {
        case Byte0:
            qtest_inb(s, addr);
            break;
        case Word:
            qtest_inw(s, addr);
            break;
        case Long:
            qtest_inl(s, addr);
            break;
        default:
            fprintf(stderr, "wrong size of dispatch_pio_read %d\n", size);
            break;
    }
}

/*
 * Generic memory Dispatcher.
 */
static void dispatch_mem_read(QTestState *s, uint64_t addr, uint8_t *data, uint32_t size) {
    qtest_memread(s, addr, data, size);
}

/*
 * Generic MMIO Dispatcher.
 */
static void dispatch_mmio_write(QTestState *s, uint64_t addr, uint32_t size, uint64_t val) {
    switch (size) {
        case Byte0:
            qtest_writeb(s, addr, val & 0xFF);
            break;
        case Word:
            qtest_writew(s, addr, val & 0xFFFF);
            break;
        case Long:
            qtest_writel(s, addr, val & 0xFFFFFFFF);
            break;
        case Quad:
            qtest_writeq(s, addr, val);
            break;
        default:
            fprintf(stderr, "wrong size of dispatch_mmio_write %d\n", size);
            break;
    }
}

/*
 * Generic PIO Dispatcher.
 */
static void dispatch_pio_write(QTestState *s, uint64_t addr, uint32_t size, uint64_t val) {
    switch (size) {
        case Byte0:
            qtest_outb(s, addr, val & 0xFF);
            break;
        case Word:
            qtest_outw(s, addr, val & 0xFFFF);
            break;
        case Long:
            qtest_outl(s, addr, val & 0xFFFFFFFF);
            break;
        default:
            fprintf(stderr, "wrong size of dispatch_pio_write %d\n", size);
            break;
    }
}

/*
 * Generic memory Dispatcher.
 */
static void dispatch_mem_write(QTestState *s, uint64_t addr, const void *data, uint32_t size) {
    qtest_memwrite(s, addr, data, size);
}

/*
 * Generic clock step dispatcher
 */
static void dispatch_clock_step(QTestState *s, uint64_t val) {
    qtest_clock_step(s, val);
}

/*
 * Generic socket write dispatcher
 */
#define FMT_timeval "%ld.%06ld"
void qtest_get_time(qemu_timeval *tv);
static void printf_qtest_prefix()
{
    qemu_timeval tv;
    qtest_get_time(&tv);
    printf("[R +" FMT_timeval "] ",
            (long) tv.tv_sec, (long) tv.tv_usec);
}

static void dispatch_socket_write(QTestState *s, const void *data, uint32_t size) {
    const uint8_t *ptr = data;
    char *enc;
    uint32_t i;
    if (!sockfds_initialized)
        return;
    uint8_t D[SOCKET_WRITE_MAX_SIZE + 4];
    if (size > SOCKET_WRITE_MAX_SIZE)
        return;
    uint32_t S = htonl(size);
    memcpy(D, (uint8_t *)&S, 4);
    memcpy(D + 4, data, size);
    int ignore = write(sockfds[0], D, size + 4);
    if (getenv("FUZZ_SERIALIZE_QTEST")) {
        enc = g_malloc(2 * size + 1);
        for (i = 0; i < size; i++) {
            sprintf(&enc[i * 2], "%02x", ptr[i]);
        }
        printf_qtest_prefix();
        printf("sock %d 0x%x 0x%s\n", sockfds[0], size, enc);
    }
    (void) ignore;
    return;
}

/*
 * Class Event Dispatch Event
 */
static void dispatch_event(Event *event, QTestState *s) {
    // handle overflow in deserialize
    uint64_t addr = event->addr;
    uint32_t size = event->size;
    uint8_t type = event->type;
    switch (type) {
        case EVENT_TYPE_MMIO_READ:
            dispatch_mmio_read(s, addr, size);
            break;
        case EVENT_TYPE_MMIO_WRITE:
            dispatch_mmio_write(s, addr, size, event->val);
            break;
        case EVENT_TYPE_PIO_READ:
            dispatch_pio_read(s, addr, size);
            break;
        case EVENT_TYPE_PIO_WRITE:
            dispatch_pio_write(s, addr, size, event->val);
            break;
        case EVENT_TYPE_MEM_READ:
            dispatch_mem_read(s, addr, event->data, size);
            break;
        case EVENT_TYPE_MEM_WRITE:
            dispatch_mem_write(s, addr, event->data, size);
            break;
        case EVENT_TYPE_DATA_POOL:
            break;
        case EVENT_TYPE_CLOCK_STEP:
            dispatch_clock_step(s, event->val);
            break;
        case EVENT_TYPE_SOCKET_WRITE:
            dispatch_socket_write(s, event->data, size);
            break;
        default:
            fprintf(stderr, "wrong type of event %d\n", type);
    }
}

#endif /* STATEFUL_FUZZ_DISPATCH_H */