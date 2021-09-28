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
#include "stateful_fuzz.h"
#include "stateful_fuzz_configs.h"
#include "stateful_fuzz_bridge.h"
#include "stateful_fuzz_io.h"
#include "stateful_fuzz_dispatch.h"
#include "stateful_fuzz_mutators.h"
#include "stateful_fuzz_callbacks.h"
#ifdef CLANG_COV_DUMP
#include "clangcovdump.h"
#endif

/* initializing flow */
static void stateful_pre_fuzz(QTestState *s) {
    GHashTableIter iter;
    MemoryRegion *mr;
    QPCIBus *pcibus;
    char **mrnames;
    StatefulFuzzer = 1;

    if (getenv("QTEST_LOG")) {
        qtest_log_enabled = 1;
    }
    if (getenv("QEMU_FUZZ_TIMEOUT")) {
        timeout = g_ascii_strtoll(getenv("QEMU_FUZZ_TIMEOUT"), NULL, 0);
    }

    fuzzable_memoryregions = g_hash_table_new(NULL, NULL);
    fuzzable_pci_devices = g_ptr_array_new();

    mrnames = g_strsplit(getenv("QEMU_FUZZ_MRNAME"), ",", -1);
    for (int i = 0; mrnames[i] != NULL; i++) {
        locate_fuzzable_objects(qdev_get_machine(), mrnames[i]);
    }

    if (strcmp(TARGET_NAME, "i386") == 0) {
        pcibus = qpci_new_pc(s, NULL);
        g_ptr_array_foreach(fuzzable_pci_devices, pci_enum, pcibus);
        qpci_free_pc(pcibus);
    }

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

    stateful_alloc = get_stateful_alloc(s);
    counter_shm_init();

#ifdef CLANG_COV_DUMP
    llvm_profile_initialize_file();
#endif
}

/* fuzzing flow */
static void stateful_fuzz(QTestState *s, const uint8_t *Data, size_t Size) {
    if (vnc_client_needed && !vnc_client_initialized) {
        init_vnc_client(s);
    }
    // read Data to Input
    Input *input = init_input(Data, Size);
    if (!input)
        return;
    // deserialize Data to Events
    deserialize(input, /*indexer=*/false);
    // fetch data pool
    Event *data_pool_event = get_event(input, input->n_events - 1);
    // printf_event(data_pool_event);
    // printf("[-] Size=%zu\n", Size);
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
            if (getenv("PRINT_EVENT")) {
                fprintf(stderr, "%d ", i);
                printf_event(event);
            }
            dispatch_event(event, s);
            flush_events(s);
            event = event->next;
        }
        // _Exit(0);
    // } else {
        // flush_events(s);
        // wait(0);
    // }
    reset_data_pool();
    free_input(input, /*indexer=*/false);
}

void TraceStateCallback(uint8_t id) {
    if (!StatefulFuzzer)
        return;
    if (getenv("DISABLE_STRUCTURAL_BUFFER"))
        return;
    Callback *callback = &callbacks[id];
    // read Data to Input
    uint8_t *Data = callback->get_data();
    size_t Size = callback->get_size();
    Input *input = init_input(Data, Size);
    // free Data because nobody will free it later
    free(Data);
    if (!input) {
        return;
    }
    // deserialize Data to Events
    static int counter = 0;
    if (counter % 1000 == 0)
        printf("[+] TraceStateCallback %d (%d)\n", id, counter);
    counter++;
    deserialize(input, /*indexer=*/false);
    // issue event one by one
    if (getenv("FUZZ_SERIALIZE_QTEST")) {
        printf_qtest_prefix();
        printf("trace_state_callback start\n");
    }
    Event *event = input->events;
    QTestState *s = get_qtest_state();
    for (int i = 0; event != NULL; i++) {
        if (getenv("PRINT_EVENT")) {
            fprintf(stderr, "%d ", i);
            printf_event(event);
        }
        dispatch_event(event, s);
        flush_events(s);
        event = event->next;
    }
    // free Input
    free_input(input, /*indexer=*/false);
    if (getenv("FUZZ_SERIALIZE_QTEST")) {
        printf_qtest_prefix();
        printf("trace_state_callback end\n");
    }
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
            .get_init_cmdline = stateful_fuzz_cmdline,
            .pre_fuzz = stateful_pre_fuzz,
            .fuzz = stateful_fuzz,
    });

    GString *name;
    const stateful_fuzz_config *config;

    for (int i = 0;
         i < sizeof(predefined_configs) / sizeof(stateful_fuzz_config);
         i++) {
        config = predefined_configs + i;
        if (strcmp(TARGET_NAME, config->arch) != 0)
            continue;
        name = g_string_new("stateful-fuzz");
        g_string_append_printf(name, "-%s", config->name);
        fuzz_add_target(&(FuzzTarget){
                .name = name->str,
                .description = "Predefined stateful-fuzz config.",
                .get_init_cmdline = stateful_fuzz_predefined_config_cmdline,
                .pre_fuzz = stateful_pre_fuzz,
                .fuzz = stateful_fuzz,
                .opaque = (void *)config
        });
    }
}

fuzz_target_init(register_stateful_fuzz_targets);
