/*
 * Stateful Virtual-Device Fuzzing Target Unittests
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <qiangliu@zju.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "../qtest/fuzz/stateful_fuzz.h"
#include "../qtest/fuzz/stateful_fuzz_mutators.h"

static void test_events(void) {
    // normal
    g_assert(EVENT_TYPE_MMIO_READ == 0);
    g_assert(EVENT_TYPE_PIO_READ == 2);
    g_assert(EVENT_TYPE_MEM_READ == 8);
    g_assert_cmpstr(EventTypeNames[1], ==, "EVENT_TYPE_MMIO_WRITE");
    g_assert_cmpstr(EventTypeNames[3], ==, "EVENT_TYPE_PIO_WRITE");
    g_assert_cmpstr(EventTypeNames[9], ==, "EVENT_TYPE_MEM_WRITE");
    // extended
    g_assert_cmpstr(EventTypeNames[11], ==, "EVENT_TYPE_DATA_POOL");
}

static void test_balanced_interfaces(void) {
    g_assert(Id_Description[INTERFACE_MEM_READ].type == EVENT_TYPE_MEM_READ);
    g_assert(Id_Description[INTERFACE_MEM_WRITE].type == EVENT_TYPE_MEM_WRITE);
    g_assert(Id_Description[INTERFACE_DATA_POOL].type == EVENT_TYPE_DATA_POOL);
}

static void test_de_serializing_events(void) {
    uint8_t *Data = (uint8_t *)malloc(4096);
    size_t Offset = 0;
    uint64_t tmp;
    // serialize
    for (int i = 0; i < 4; i++) {
        Id_Description[i].type = i;
        Id_Description[i].emb.addr = 0xFFFF0000 + 0x100 * i;
        Id_Description[i].emb.size = 0x100;
        Id_Description[i].min_access_size = 0x1;
        Id_Description[i].max_access_size = 0x4;
    }
    n_interfaces = 4;
    Offset += serialize(Data, Offset, 4096, INTERFACE_MEM_READ, 0x100000, 8, NULL);
    g_assert(Offset == (13 + 8));
    Offset += serialize(Data, Offset, 4096, INTERFACE_MEM_WRITE, 0x100000, 8, Data);
    g_assert(Offset == (13 + 8) + (13 + 8));
    Offset += serialize(Data, Offset, 4096, 0, 0x0, 0x4, NULL);
    g_assert(Offset == (13 + 8) + (13 + 8) + 13);
    tmp = 0x200;
    Offset += serialize(Data, Offset, 4096, 1, 0x4, 0x4, (uint8_t *)&tmp);
    g_assert(Offset == (13 + 8) + (13 + 8) + 13 + 21);
    Offset += serialize(Data, Offset, 4096, 2, 0x8, 0x1, NULL);
    g_assert(Offset == (13 + 8) + (13 + 8) + 13 + 21 + 13);
    tmp = 0x400;
    Offset += serialize(Data, Offset, 4096, 3, 0xC, 0x4, (uint8_t *)&tmp);
    g_assert(Offset == (13 + 8) + (13 + 8) + 13 + 21 + 13 + 21);
    Offset += serialize(Data, Offset, 4096, INTERFACE_DATA_POOL, 0x100000, 8, Data);
    g_assert(Offset == (13 + 8) + (13 + 8) + 13 + 21 + 13 + 21 + (5 + 8));
    // deserialize
    Input *input = init_input(Data, Offset);
    g_assert(input);
    deserialize(input, /*indexer=*/false);
    g_assert(input->n_events == 7);
    Event *event = input->events;
    while (event) {
        switch (event->id) {
            case 0:
                g_assert(event->addr == 0xffff0000);
                g_assert(event->size == 0x4);
                break;
            case 1:
                g_assert(event->addr == 0xffff0104);
                g_assert(event->size == 0x4);
                g_assert(event->val == 0x200);
                break;
            case 2:
                g_assert(event->addr == 0xffff0208);
                g_assert(event->size == 0x1);
                break;
            case 3:
                g_assert(event->addr == 0xffff030c);
                g_assert(event->size == 0x4);
                g_assert(event->val == 0x400);
                break;
            case INTERFACE_MEM_READ:
                g_assert(event->addr == 0x100000);
                g_assert(event->size == 0x8);
                break;
            case INTERFACE_MEM_WRITE:
                g_assert(event->addr == 0x100000);
                g_assert(event->size == 0x8);
                g_assert(*(uint64_t *)event->data == 0x0000000010000020);
                break;
            case INTERFACE_DATA_POOL:
                g_assert(event->addr == 0xFFFFFFFFFFFFFFFF);
                g_assert(event->size == 0x8);
                g_assert(*(uint64_t *)event->data == 0x0000000010000020);
                break;
        }
        event = event->next;
    }
    free_input(input, /*indexer=*/false);
    free(Data);
}

static void test_retrieving_fuzzy_data(void) {
    // preprare interface
    Id_Description[0].type = EVENT_TYPE_MMIO_READ;
    Id_Description[0].emb.addr = 0xFFFF0000;
    Id_Description[0].emb.size = 0x100;
    Id_Description[0].min_access_size = 0x1;
    Id_Description[0].max_access_size = 0x4;
    n_interfaces = 1;
    // reset data
    uint8_t *Data = (uint8_t *)malloc(4096);
    size_t Offset = reset_data(Data, 4096);
    g_assert(Offset == (13 + (5 + 13)));
    // deserialize
    Input *input = init_input(Data, Offset);
    g_assert(input);
    deserialize(input, /*indexer=*/false);
    g_assert(input->n_events == 2);
    Event *event = input->events;
    while (event) {
        switch (event->id) {
            case 0:
                g_assert(event->addr == 0xFFFF0000);
                g_assert(event->size == 0x4);
                break;
            case INTERFACE_DATA_POOL:
                g_assert(event->addr == 0xFFFFFFFFFFFFFFFF);
                g_assert(event->size == 0xD);
                g_assert(*(uint64_t *)event->data == 0x0000000000000000);
                break;
        }
        event = event->next;
    }
    // test data pool access
    Event *data_pool_event = get_event(input, input->n_events - 1);
    g_assert(data_pool_event->id == INTERFACE_DATA_POOL);
    set_data_pool(data_pool_event);
    Offset = data_pool_event->offset;
    g_assert(Offset == 13);
    g_assert(data_pool.Size == 0xD);
    g_assert(*(uint64_t *)data_pool.Data == 0x0000000000000000);
    g_assert(data_pool.index == 0);
    // 0 0 0 0 0 0 0 0 0 4 0 0 0
    // ------- ------- ------- +
    // ++++  +++++++ +++++++ ---   
    for (int i = 0; i < 2; i++)
        g_assert(get_data_from_pool4() == 0);
    g_assert(get_data_from_pool4() == 0x400);
    // this buffer is a circle
    for (int i = 0; i < 2; i++)
        g_assert(get_data_from_pool4() == 0);
    g_assert(get_data_from_pool4() == 0x40000);
    free_input(input, /*indexer=*/false);
    free(Data);
}

static uint64_t guest_alloc_under_test(size_t size) {
    static int count = 0;
    return 0x100000 + 0x3000 * (count++);
}

static void test_allocating_chained_buffers(void) {
    stateful_guest_alloc = guest_alloc_under_test;
    stateful_memory_pool_init();

    // first allocate a large buffer that can be chained
    uint64_t addr1 = stateful_malloc(0x3000, /*chained=*/true);
    g_assert(addr1 == 0x100000);
    // before going on, you may want to freeze some addresses
    bool status1 = stateful_lock(addr1, 0x1000);
    g_assert(status1);
    // then you must explicit require a valid chained address immediately
    uint64_t chained_addr1 = stateful_require(0x100);
    g_assert(chained_addr1 == 0x101000);
    // and do not forget to commit it, otherwise you got the same
    uint64_t chained_addr2 = stateful_require(0x100);
    g_assert(chained_addr1 == chained_addr2);
    bool status2 = stateful_commit(addr1);
    g_assert(status2);
    uint64_t chained_addr3 = stateful_require(0x100);
    g_assert(chained_addr3 == 0x101100);
    // finally allocate another buffer that cannot be chained
    uint64_t addr2 = stateful_malloc(0x3000, /*chained=*/false);
    g_assert(addr2 == 0x103000);
    // corner cases
    // if you further allocate a large buffer that can be chained
    // the first allocated large buffer will be unseen
    uint64_t addr3 = stateful_malloc(0x3000, /*chained=*/true);
    g_assert(addr3 == 0x106000);
    uint64_t chained_addr4 = stateful_require(0x100);
    g_assert(chained_addr4 == 0x106000);
    uint64_t chained_addr5 = stateful_require(0x3000);
    g_assert(chained_addr5 == 0x106000);
}

static void test_crossoverfragment_mutator(void) {
    // preprare interface
    Id_Description[0].type = EVENT_TYPE_MMIO_READ;
    Id_Description[0].emb.addr = 0xFFFF0000;
    Id_Description[0].emb.size = 0x100;
    Id_Description[0].min_access_size = 0x1;
    Id_Description[0].max_access_size = 0x4;
    n_interfaces = 1;
    // make 8 events
    uint8_t *Data = (uint8_t *)malloc(4096);
    size_t Offset = 0;
    for (int i = 0; i < 8; i++) {
        Offset += serialize(Data, Offset, 4096, INTERFACE_MEM_READ, 0x100000, 8, NULL);
    }
    // deserialize
    Input *input;
    input = init_input(Data, Offset);
    g_assert(input);
    deserialize(input, /*indexer=*/true);
    g_assert(input->n_events == 8);
    size_t SizeAfterMutation = Mutate_CrossOverFragments(input, Data, Offset, 4096);
    free(input);
    // re-deserialize
    g_assert(SizeAfterMutation == Offset);
    input = init_input(Data, Offset);
    g_assert(input);
    deserialize(input, /*indexer=*/true);
    g_assert(input->n_events == 8);
    Event *event = input->events;
    for (int i = 0; i < 8; i++) {
        g_assert(event->id == INTERFACE_MEM_READ);
        g_assert(event->addr == 0x100000);
        g_assert(event->size == 8);
        event = event->next;
    }
    free(input);
    free(Data);
}

int main(int argc, char **argv) {
    // Unittests for events and interfaces.
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/statefulfuzz/events", test_events);
    g_test_add_func("/statefulfuzz/interfaces/predefine", test_balanced_interfaces);
    g_test_add_func("/statefulfuzz/injectedevents/primitives/de_serialize", test_de_serializing_events);
    g_test_add_func("/statefulfuzz/injectedevents/primitives/retrieve", test_retrieving_fuzzy_data);
    g_test_add_func("/statefulfuzz/injectedevents/primitives/allocate", test_allocating_chained_buffers);
    g_test_add_func("/statefulfuzz/mutators/crossoverfragments", test_crossoverfragment_mutator);
    return g_test_run();
}
