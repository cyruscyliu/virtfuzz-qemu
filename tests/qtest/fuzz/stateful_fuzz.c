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
#include "stateful_fuzz.h"
#include "stateful_fuzz_configs.h"
#include "stateful_fuzz_sms.h"
#include "stateful_fuzz_mutators.h"

bool UseCustomMutator;
static GHashTable *fuzzable_memoryregions;
static GPtrArray *fuzzable_pci_devices;

enum Sizes {Empty, Byte=1, Word=2, Long=4, Quad=8};

/*
 * Generic MMIO Dispatcher.
 */
static void dispatch_mmio_read(QTestState *s, uint64_t addr, uint32_t size) {
    switch (size) {
        case Byte:
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
        case Byte:
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
        case Byte:
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
        case Byte:
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
        default:
            fprintf(stderr, "wrong type of event %d\n", type);
    }
}

extern QTestState *get_qtest_state(void);
void LLVMFuzzerTraceStateCallback(
        size_t StateMachineId, size_t NodeId);
void LLVMFuzzerTraceStateCallback(
        size_t StateMachineId, size_t NodeId) {
    StateMachine *state_machine = &state_machines[StateMachineId];
    Node *node = &state_machine->nodes[NodeId];

    // read Data to Input
    uint8_t *Data = node->get_data();
    size_t Size = node->get_size();
    Input *input = init_input(Data, Size);
    // free Data because nobody will free it later
    free(Data);
    if (!input)
        return;
    // deserialize Data to Events
    deserialize(input, /*indexer=*/false);
    // issue event one by one
    Event *event = input->events;
    QTestState *s = get_qtest_state();
    for (int i = 0; event != NULL; i++) {
        dispatch_event(event, s);
        flush_events(s);
        event = event->next;
    }
    // free Input
    free_input(input, /*indexer=*/false);
}

#define INVLID_ADDRESS 0
#define   MMIO_ADDRESS 1
#define    PIO_ADDRESS 2

static uint8_t get_memoryregion_addr(MemoryRegion *mr, uint64_t *addr) {
    MemoryRegion *tmp_mr = mr;
    uint64_t tmp_addr = tmp_mr->addr;
    while (tmp_mr->container) {
        tmp_mr = tmp_mr->container;
        tmp_addr += tmp_mr->addr;
    }
    if (strcmp(tmp_mr->name, "system") == 0) {
        *addr = tmp_addr;
        return MMIO_ADDRESS;
    } else if (strcmp(tmp_mr->name, "io") == 0) {
        *addr = tmp_addr;
        return PIO_ADDRESS;
    } else {
        return INVLID_ADDRESS;
    }
}

static int insert_qom_composition_child(Object *obj, void *opaque)
{
    g_array_append_val(opaque, obj);
    return 0;
}

static void locate_fuzzable_objects(Object *obj, char *mrname) {
    GArray *children = g_array_new(false, false, sizeof(Object *));
    const char *name;
    MemoryRegion *mr;
    int i;

    if (obj == object_get_root()) {
        name = "";
    } else {
        name = object_get_canonical_path_component(obj);
    }

    uint64_t addr;
    uint8_t mr_type, max, min;
    if (object_dynamic_cast(OBJECT(obj), TYPE_MEMORY_REGION)) {
        if (g_pattern_match_simple(mrname, name)) {
            mr = MEMORY_REGION(obj);
            g_hash_table_insert(fuzzable_memoryregions, mr, (gpointer)true);
            mr_type = get_memoryregion_addr(mr, &addr);
            // TODO: Improve to resolve the max/min in the future
            if (mr_type == MMIO_ADDRESS) {
                if (mr->ops->valid.min_access_size == 0 &&
                        mr->ops->valid.max_access_size ==0) {
                    min = max = 4;
                } else {
                    min = mr->ops->valid.min_access_size;
                    max = mr->ops->valid.max_access_size;
                }
                Id_Description[n_interfaces].type = EVENT_TYPE_MMIO_READ;
                Id_Description[n_interfaces + 1].type = EVENT_TYPE_MMIO_WRITE;
            } else if (mr_type == PIO_ADDRESS) {
                min = 1;
                max = (((MemoryRegionPortio *)((MemoryRegionPortioList *)mr->opaque)->ports)[0]).size;
                if (max == 0) { max = min; }
                Id_Description[n_interfaces].type = EVENT_TYPE_PIO_READ;
                Id_Description[n_interfaces+ 1].type = EVENT_TYPE_PIO_WRITE;
            }
            // TODO: Deduplicate MemoryRegions in the future
            if (mr_type != INVLID_ADDRESS) {
                Id_Description[n_interfaces].emb.addr = addr;
                Id_Description[n_interfaces].emb.size = mr->size;
                Id_Description[n_interfaces].min_access_size = min;
                Id_Description[n_interfaces].max_access_size = max;
                memcpy(Id_Description[n_interfaces].name, mr->name,
                       strlen(mr->name) <= 32 ? strlen(mr->name) : 32);
                Id_Description[n_interfaces + 1].emb.addr = addr;
                Id_Description[n_interfaces + 1].emb.size = mr->size;
                Id_Description[n_interfaces + 1].min_access_size = min;
                Id_Description[n_interfaces + 1].max_access_size = max;
                memcpy(Id_Description[n_interfaces + 1].name, mr->name,
                       strlen(mr->name) <= 32 ? strlen(mr->name) : 32);
                n_interfaces += 2;
            }
         }
     } else if(object_dynamic_cast(OBJECT(obj), TYPE_PCI_DEVICE)) {
            /*
             * Don't want duplicate pointers to the same PCIDevice, so remove
             * copies of the pointer, before adding it.
             */
            g_ptr_array_remove_fast(fuzzable_pci_devices, PCI_DEVICE(obj));
            g_ptr_array_add(fuzzable_pci_devices, PCI_DEVICE(obj));
     }

     object_child_foreach(obj, insert_qom_composition_child, children);

     for (i = 0; i < children->len; i++) {
         locate_fuzzable_objects(g_array_index(children, Object *, i), mrname);
     }
     g_array_free(children, TRUE);
}

static void stateful_pre_fuzz(QTestState *s) {
    GHashTableIter iter;
    MemoryRegion *mr;
    QPCIBus *pcibus;
    char **mrnames;
    UseCustomMutator = 1;

    if (getenv("QTEST_LOG")) {
        qtest_log_enabled = 1;
    }
    if (getenv("QEMU_FUZZ_TIMEOUT")) {
        timeout = g_ascii_strtoll(getenv("QEMU_FUZZ_TIMEOUT"), NULL, 0);
    }

    fuzzable_memoryregions = g_hash_table_new(NULL, NULL);
    fuzzable_pci_devices = g_ptr_array_new();

    mrnames = g_strsplit(getenv("QEMU_FUZZ_MRNAME"), " ", -1);
    for (int i = 0; mrnames[i] != NULL; i++) {
        locate_fuzzable_objects(qdev_get_machine(), mrnames[i]);
    }

    pcibus = qpci_new_pc(s, NULL);
    g_ptr_array_foreach(fuzzable_pci_devices, pci_enum, pcibus);
    qpci_free_pc(pcibus);

    fprintf(stderr, "Matching objects by name ");
    for (int i = 0; mrnames[i] != NULL; i++) {
        fprintf(stderr, ", %s", mrnames[i]);
        locate_fuzzable_objects(qdev_get_machine(), mrnames[i]);
    }
    fprintf(stderr, "\n");
    g_strfreev(mrnames);

    fprintf(stderr, "This process will fuzz the following MemoryRegions:\n");
    g_hash_table_iter_init(&iter, fuzzable_memoryregions);
    while (g_hash_table_iter_next(&iter, (gpointer)&mr, NULL)) {
        printf("  * %s (size %lx)\n",
               object_get_canonical_path_component(&(mr->parent_obj)),
               (uint64_t)mr->size);
    }
    if (!g_hash_table_size(fuzzable_memoryregions)) {
        printf("No fuzzable memory regions found ...\n");
        exit(1);
    }

    fprintf(stderr, "This process will fuzz through the following interfaces:\n");
    if (!n_interfaces) {
        printf("No fuzzable interfaces found ...\n");
        exit(2);
    } else {
        printf_event_description();
    }

    counter_shm_init();
}

static void stateful_fuzz(QTestState *s, const uint8_t *Data, size_t Size) {
    // read Data to Input
    Input *input = init_input(Data, Size);
    if (!input)
        return;
    // deserialize Data to Events
    deserialize(input, /*indexer=*/false);
    // fetch data pool
    Event *data_pool_event = get_event(input, input->n_events - 1);
    g_assert(data_pool_event->id == INTERFACE_DATA_POOL);
    set_data_pool(data_pool_event);
    // if (fork() == 0) {
        /*
         * Sometimes the fuzzer will find inputs that take quite a long time to
         * process. Often times, these inputs do not result in new coverage.
         * Even if these inputs might be interesting, they can slow down the
         * fuzzer, overall. Set a timeout to avoid hurting performance, too much
         */
        // if (timeout) {
            // struct sigaction sact;
            // struct itimerval timer;

            // sigemptyset(&sact.sa_mask);
            // sact.sa_flags   = SA_NODEFER;
            // sact.sa_handler = handle_timeout;
            // sigaction(SIGALRM, &sact, NULL);

            // memset(&timer, 0, sizeof(timer));
            // timer.it_value.tv_sec = timeout / USEC_IN_SEC;
            // timer.it_value.tv_usec = timeout % USEC_IN_SEC;
            // setitimer(ITIMER_VIRTUAL, &timer, NULL);
        // }
        // issue event one by one
        Event *event = input->events;
        for (int i = 0; event != NULL; i++) {
            dispatch_event(event, s);
            flush_events(s);
            event = event->next;
        }
        // _Exit(0);
    // } else {
        // flush_events(s);
        // wait(0);
    // }
    free_input(input, /*indexer=*/false);
}

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed);

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
        size_t MaxSize, unsigned int Seed) {
    // for generic fuzz targets
    if (!UseCustomMutator)
        return LLVMFuzzerMutate(Data, Size, MaxSize);

    Input *input = init_input(Data, Size);
    if (!input) {
        return reset_data(Data, MaxSize);
    }
    // deserialize Data to Events
    // If the input is too short to contain longer event, stop early.
    Size = deserialize(input, /*indexer=*/true);
    if (Size == 0) {
        free_input(input, /*indexer=*/true);
        return reset_data(Data, MaxSize);
    }
    // Keep the EVENT_TYPE_DATA_POOL
    Event *data_pool_event = get_event(input, input->n_events - 1);
    g_assert(data_pool_event->id == INTERFACE_DATA_POOL);
    set_data_pool(data_pool_event);
    size_t DataPoolOffset = data_pool_event->offset;
    size_t NewDataPoolSize = LLVMFuzzerMutate(data_pool.Data, data_pool.Size, DATA_POOL_MAXSIZE);
    if (!NewDataPoolSize) {
        reset_data_pool();
        free_input(input, /*indexer=*/true);
        return reset_data(Data, MaxSize);
    }
    data_pool.Size = NewDataPoolSize;
    // Note that EVENT_TYPE_DATA_POOL should not be aware
    input->n_events--;
    // Mutate other events
    for (int i = 0; i < 100; i++) {
        size_t aaaaaaa = rand() % N_MUTATORS;
        size_t NewSize = CustomMutators[aaaaaaa](input, Data, DataPoolOffset, MaxSize);
        if (NewSize) {
            size_t bbbbbbb = serialize(Data, NewSize, MaxSize,
                INTERFACE_DATA_POOL, 0, data_pool.Size, data_pool.Data);
            if (!bbbbbbb) {
                reset_data_pool();
                free_input(input, /*indexer=*/true);
                return reset_data(Data, MaxSize);
            }
            NewSize += bbbbbbb;
            reset_data_pool();
            free_input(input, /*indexer=*/true);
            return NewSize;
        }
    }
    reset_data_pool();
    free_input(input, /*indexer=*/true);
    return reset_data(Data, MaxSize); // Fallback, should not happen frequently.
}

static void usage(void) {
    printf("Please specify the following environment variables:\n");
    printf("QEMU_FUZZ_ARGS= the command line arguments passed to qemu\n");
    printf("QEMU_FUZZ_OBJECTS= "
            "a space separated list of QOM type names for objects to fuzz\n");
    printf("Optionally: QEMU_FUZZ_TIMEOUT= Specify a custom timeout (us). "
            "0 to disable. %d by default\n", timeout);
    exit(0);
}

static void register_stateful_fuzz_targets(void) {
    fuzz_add_target(&(FuzzTarget){
            .name = "stateful-fuzz",
            .description = "Fuzz based on any qemu command-line args. ",
            .get_init_cmdline = generic_fuzz_cmdline,
            .pre_fuzz = stateful_pre_fuzz,
            .fuzz = stateful_fuzz,
    });

    GString *name;
    const generic_fuzz_config *config;

    for (int i = 0;
         i < sizeof(predefined_configs) / sizeof(generic_fuzz_config);
         i++) {
        config = predefined_configs + i;
        name = g_string_new("stateful-fuzz");
        g_string_append_printf(name, "-%s", config->name);
        fuzz_add_target(&(FuzzTarget){
                .name = name->str,
                .description = "Predefined stateful-fuzz config.",
                .get_init_cmdline = generic_fuzz_predefined_config_cmdline,
                .pre_fuzz = stateful_pre_fuzz,
                .fuzz = stateful_fuzz,
                .opaque = (void *)config
        });
    }
}

fuzz_target_init(register_stateful_fuzz_targets);
