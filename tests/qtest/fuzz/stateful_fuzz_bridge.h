/*
 * Stateful Virtual-Device Fuzzing Bridge
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef STATEFUL_FUZZ_BRIDGE_H
#define STATEFUL_FUZZ_BRIDGE_H

#include "stateful_fuzz.h"

/* enumerate PCI devices */
static inline void pci_enum(gpointer pcidev, gpointer bus)
{
    PCIDevice *dev = pcidev;
    QPCIDevice *qdev;
    int i;

    qdev = qpci_device_find(bus, dev->devfn);
    g_assert(qdev != NULL);
    for (i = 0; i < 6; i++) {
        if (dev->io_regions[i].size) {
            qpci_iomap(qdev, i, NULL);
        }
    }
    qpci_device_enable(qdev);
    g_free(qdev);
}

#define INVLID_ADDRESS 0
#define   MMIO_ADDRESS 1
#define    PIO_ADDRESS 2

/* parse memory region physical address */
static uint8_t get_memoryregion_addr(MemoryRegion *mr, uint64_t *addr) {
    MemoryRegion *tmp_mr = mr;
    uint64_t tmp_addr = tmp_mr->addr;
    while (tmp_mr->container) {
        tmp_mr = tmp_mr->container;
        tmp_addr += tmp_mr->addr;
        if (strcmp(tmp_mr->name, "system") == 0) {
            *addr = tmp_addr;
            return MMIO_ADDRESS;
        // TODO fix me
        } else if (strcmp(tmp_mr->name, "nrf51-container") == 0) {
            *addr = tmp_addr;
            return MMIO_ADDRESS;
        } else if (strcmp(tmp_mr->name, "io") == 0) {
            *addr = tmp_addr;
            return PIO_ADDRESS;
        }
    }
    return INVLID_ADDRESS;
}

/* insertion helper */
static int insert_qom_composition_child(Object *obj, void *opaque)
{
    g_array_append_val(opaque, obj);
    return 0;
}

/* testing interface identifiction */
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
                        mr->ops->valid.max_access_size == 0 &&
                        mr->ops->impl.min_access_size == 0 &&
                        mr->ops->impl.max_access_size == 0) {
                    min = 1;
                    max = 4;
                } else {
                    min = MAX(mr->ops->valid.min_access_size, mr->ops->impl.min_access_size);
                    max = MAX(mr->ops->valid.max_access_size, mr->ops->impl.max_access_size);
                }
                Id_Description[n_interfaces].type = EVENT_TYPE_MMIO_READ;
                Id_Description[n_interfaces + 1].type = EVENT_TYPE_MMIO_WRITE;
            } else if (mr_type == PIO_ADDRESS) {
                MemoryRegionPortioList *mrpl = (MemoryRegionPortioList *)mr->opaque;
                if (mr->ops->valid.min_access_size == 0 &&
                        mr->ops->valid.max_access_size == 0 &&
                        mr->ops->impl.min_access_size == 0 &&
                        mr->ops->impl.max_access_size == 0 && mrpl) {
                    min = 1;
                    max = (((MemoryRegionPortio *)((MemoryRegionPortioList *)mr->opaque)->ports)[0]).size;
                    if (max == 0 || max > 4) { max = 4; }
                } else {
                    min = MAX(mr->ops->valid.min_access_size, mr->ops->impl.min_access_size);
                    max = MAX(mr->ops->valid.max_access_size, mr->ops->impl.max_access_size);
                }
                Id_Description[n_interfaces].type = EVENT_TYPE_PIO_READ;
                Id_Description[n_interfaces + 1].type = EVENT_TYPE_PIO_WRITE;
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

/* event description helper */
static void printf_event_description() {
    for (int i = 0; i < n_interfaces; i++) {
        InterfaceDescription ed = Id_Description[i];
        fprintf(stderr, "  * %s, %s, 0x%lx +0x%x, %d,%d\n",
                ed.name, EventTypeNames[ed.type],
                ed.emb.addr, ed.emb.size,
                ed.min_access_size, ed.max_access_size);
    }
}

/* return a interface of the same type */
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

/* return a interface by its name and type */
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

#endif /* STATEFUL_FUZZ_BRIDEG_H */
