/*
 * Generic Virtual-Device Fuzzing Target Configs
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Alexander Bulekov   <alxndr@bu.edu>
 *  Qiang Liu <qiangliu@zju.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef STATEFUL_FUZZ_CONFIGS_H
#define STATEFUL_FUZZ_CONFIGS_H

#include "exec/ioport.h"
#include "tests/qtest/libqos/pci-pc.h"
#include "tests/qtest/libqos/libqtest.h"
#include "fuzz.h"
#include "tests/qtest/libqos/qos_external.h"
#include "tests/qtest/libqos/qgraph_internal.h"

#define DEFAULT_TIMEOUT_US 100000
#define USEC_IN_SEC 1000000000

static void usage(void);
static bool qtest_log_enabled;

static inline void handle_timeout(int sig) {
    if (qtest_log_enabled) {
        fprintf(stderr, "[Timeout]\n");
        fflush(stderr);
    }
    _Exit(0);
}

static useconds_t timeout = DEFAULT_TIMEOUT_US;

typedef struct generic_fuzz_config {
    const char *name, *args, *objects, *mrnames, *file;
    gchar* (*argfunc)(void); /* Result must be freeable by g_free() */
} generic_fuzz_config;

typedef struct MemoryRegionPortioList {
    MemoryRegion mr;
    void *portio_opaque;
    MemoryRegionPortio ports[];
} MemoryRegionPortioList;

static inline GString *generic_fuzz_cmdline(FuzzTarget *t)
{
    GString *cmd_line = g_string_new(TARGET_NAME);
    if (!getenv("QEMU_FUZZ_ARGS")) {
        usage();
    }
    g_string_append_printf(cmd_line, " -display none \
                                      -machine accel=qtest, \
                                      -m 512M %s ", getenv("QEMU_FUZZ_ARGS"));
    return cmd_line;
}

static inline GString *generic_fuzz_predefined_config_cmdline(FuzzTarget *t)
{
    gchar *args;
    const generic_fuzz_config *config;
    g_assert(t->opaque);

    config = t->opaque;
    setenv("QEMU_AVOID_DOUBLE_FETCH", "1", 1);
    if (config->argfunc) {
        args = config->argfunc();
        setenv("QEMU_FUZZ_ARGS", args, 1);
        g_free(args);
    } else {
        g_assert_nonnull(config->args);
        setenv("QEMU_FUZZ_ARGS", config->args, 1);
    }
    setenv("QEMU_FUZZ_OBJECTS", config->objects, 1);
    setenv("QEMU_FUZZ_MRNAME", config->mrnames, 1);
    return generic_fuzz_cmdline(t);
}

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

static QGuestAllocator *get_stateful_alloc(QTestState *qts) {
    QOSGraphNode *node;
    QOSGraphObject *obj;

    // TARGET_NAME=i386 -> i386/pc
    // TARGET_NAME=     -> x86_64/pc
    node = qos_graph_get_node("i386/pc");
    g_assert(node->type == QNODE_MACHINE);

    obj = qos_machine_new(node, qts);
    qos_object_queue_destroy(obj);
    return obj->get_driver(obj, "memory");
}

static inline gchar *generic_fuzzer_virtio_9p_args(void){
    char tmpdir[] = "/tmp/qemu-fuzz.XXXXXX";
    g_assert_nonnull(mkdtemp(tmpdir));

    return g_strdup_printf("-machine q35 -nodefaults "
    "-device virtio-9p,fsdev=hshare,mount_tag=hshare "
    "-fsdev local,id=hshare,path=%s,security_model=mapped-xattr,"
    "writeout=immediate,fmode=0600,dmode=0700", tmpdir);
}

static inline gchar *stateful_fuzz_ati_args(void) {
    if (strcmp(TARGET_NAME, "mipsel") == 0) {
        fprintf(stderr, "Cannot support qtest in %s\n", TARGET_NAME);
        _Exit(0);
        // return g_strdup_printf("-machine fulong2e -device ati-vga");
    } else if (strcmp(TARGET_NAME, "ppc") == 0) {
        fprintf(stderr, "Cannot find the ati-vga address in %s\n", TARGET_NAME);
        _Exit(0);
        // return g_strdup_printf("-machine mac99 -device ati-vga,romfile=\"\"");
    } else if (strcmp(TARGET_NAME, "i386") == 0) {
        return g_strdup_printf("-machine q35 -nodefaults -device ati-vga,romfile=\"\"");
    } else {
        fprintf(stderr, "Cannot support ati-vga in %s\n", TARGET_NAME);
        _Exit(0);
    }
}

static const generic_fuzz_config predefined_configs[] = {
    /*
    {
        .name = "virtio-net-pci-slirp",
        .args = "-M q35 -nodefaults "
        "-device virtio-net,netdev=net0 -netdev user,id=net0",
        .objects = "virtio*",
    },{
        .name = "virtio-blk",
        .args = "-machine q35 -device virtio-blk,drive=disk0 "
        "-drive file=null-co://,id=disk0,if=none,format=raw",
        .objects = "virtio*",
    },{
        .name = "virtio-scsi",
        .args = "-machine q35 -device virtio-scsi,num_queues=8 "
        "-device scsi-hd,drive=disk0 "
        "-drive file=null-co://,id=disk0,if=none,format=raw",
        .objects = "scsi* virtio*",
    },{
        .name = "virtio-gpu",
        .args = "-machine q35 -nodefaults -device virtio-gpu",
        .objects = "virtio*",
    },{
        .name = "virtio-vga",
        .args = "-machine q35 -nodefaults -device virtio-vga",
        .objects = "virtio*",
    },{
        .name = "virtio-rng",
        .args = "-machine q35 -nodefaults -device virtio-rng",
        .objects = "virtio*",
    },{
        .name = "virtio-balloon",
        .args = "-machine q35 -nodefaults -device virtio-balloon",
        .objects = "virtio*",
    },{
        .name = "virtio-serial",
        .args = "-machine q35 -nodefaults -device virtio-serial",
        .objects = "virtio*",
    },{
        .name = "virtio-mouse",
        .args = "-machine q35 -nodefaults -device virtio-mouse",
        .objects = "virtio*",
    },{
        .name = "virtio-9p",
        .argfunc = generic_fuzzer_virtio_9p_args,
        .objects = "virtio*",
    },{
        .name = "virtio-9p-synth",
        .args = "-machine q35 -nodefaults "
        "-device virtio-9p,fsdev=hshare,mount_tag=hshare "
        "-fsdev synth,id=hshare",
        .objects = "virtio*",
    },{
        .name = "e1000",
        .args = "-M q35 -nodefaults "
        "-device e1000,netdev=net0 -netdev user,id=net0",
        .objects = "e1000",
    },{
        .name = "e1000e",
        .args = "-M q35 -nodefaults "
        "-device e1000e,netdev=net0 -netdev user,id=net0",
        .objects = "e1000e",
    },{
        .name = "cirrus-vga",
        .args = "-machine q35 -nodefaults -device cirrus-vga",
        .objects = "cirrus*",
    },{
        .name = "bochs-display",
        .args = "-machine q35 -nodefaults -device bochs-display",
        .objects = "bochs*",
    },{
        .name = "intel-hda",
        .args = "-machine q35 -nodefaults -device intel-hda,id=hda0 "
        "-device hda-output,bus=hda0.0 -device hda-micro,bus=hda0.0 "
        "-device hda-duplex,bus=hda0.0",
        .objects = "intel-hda",
    },{
        .name = "ide-hd",
        .args = "-machine pc -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-hd,drive=disk0",
        .objects = "*ide*",
    },{
        .name = "ide-atapi",
        .args = "-machine pc -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-cd,drive=disk0",
        .objects = "*ide*",
    },{
        .name = "ahci-hd",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-hd,drive=disk0",
        .objects = "*ahci*",
    },{
        .name = "ahci-atapi",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device ide-cd,drive=disk0",
        .objects = "*ahci*",
    },{
        .name = "floppy",
        .args = "-machine pc -nodefaults -device floppy,id=floppy0 "
        "-drive id=disk0,file=null-co://,file.read-zeroes=on,if=none,format=raw "
        "-device floppy,drive=disk0,drive-type=288",
        .objects = "fd* floppy* i8257",
        .mrnames = "*fdc* *fdctrl*",
    },*/{
        .name = "xhci",
        .args = "-machine q35 -nodefaults "
        "-drive file=null-co://,if=none,format=raw,id=disk0 "
        "-device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0 "
        "-device usb-bot -device usb-storage,drive=disk0 "
        "-chardev null,id=cd0 -chardev null,id=cd1 "
        "-device usb-braille,chardev=cd0 -device usb-ccid -device usb-ccid "
        "-device usb-kbd -device usb-mouse -device usb-serial,chardev=cd1 "
        "-device usb-tablet -device usb-wacom-tablet -device usb-audio",
        .objects = "*usb* *uhci* *xhci*",
        .mrnames = "*capabilities*,*operational*,*runtime*,*doorbell*",
        .file = "hw/usb/hcd-xhci.c",
    },/*{
        .name = "pc-i440fx",
        .args = "-machine pc",
        .objects = "*",
    },{
        .name = "pc-q35",
        .args = "-machine q35",
        .objects = "*",
    },{
        .name = "vmxnet3",
        .args = "-machine q35 -nodefaults "
        "-device vmxnet3,netdev=net0 -netdev user,id=net0",
        .objects = "vmxnet3"
    },{
        .name = "ne2k_pci",
        .args = "-machine q35 -nodefaults "
        "-device ne2k_pci,netdev=net0 -netdev user,id=net0",
        .objects = "ne2k*"
    },{
        .name = "pcnet",
        .args = "-machine q35 -nodefaults "
        "-device pcnet,netdev=net0 -netdev user,id=net0",
        .objects = "pcnet"
    },{
        .name = "rtl8139",
        .args = "-machine q35 -nodefaults "
        "-device rtl8139,netdev=net0 -netdev user,id=net0",
        .objects = "rtl8139"
    },{
        .name = "i82550",
        .args = "-machine q35 -nodefaults "
        "-device i82550,netdev=net0 -netdev user,id=net0",
        .objects = "i8255*"
    },{
        .name = "sdhci-v3",
        .args = "-nodefaults -device sdhci-pci,sd-spec-version=3 "
        "-device sd-card,drive=mydrive "
        "-drive if=none,index=0,file=null-co://,format=raw,id=mydrive -nographic",
        .objects = "sd*"
    },*/{
        .name = "ehci",
        .args = "-machine q35 -nodefaults "
        "-device ich9-usb-ehci1,bus=pcie.0,addr=1d.7,"
        "multifunction=on,id=ich9-ehci-1 "
        "-device ich9-usb-uhci1,bus=pcie.0,addr=1d.0,"
        "multifunction=on,masterbus=ich9-ehci-1.0,firstport=0 "
        "-device ich9-usb-uhci2,bus=pcie.0,addr=1d.1,"
        "multifunction=on,masterbus=ich9-ehci-1.0,firstport=2 "
        "-device ich9-usb-uhci3,bus=pcie.0,addr=1d.2,"
        "multifunction=on,masterbus=ich9-ehci-1.0,firstport=4 "
        "-drive if=none,id=usbcdrom,media=cdrom "
        "-device usb-tablet,bus=ich9-ehci-1.0,port=1,usb_version=1 "
        "-device usb-storage,bus=ich9-ehci-1.0,port=2,drive=usbcdrom",
        .objects = "*usb* *hci*",
        .mrnames = "*capabilities*,*operational*,*ports*",
        .file = "hw/usb/hcd-ehci.c",
    },{
        .name = "ohci",
        .args = "-machine q35 -nodefaults  -device pci-ohci -device usb-kbd",
        .objects = "*usb* *ohci*",
        .mrnames = "*ohci*",
        .file = "hw/usb/hcd-ohci.c",
    },/*{
        .name = "megaraid",
        .args = "-machine q35 -nodefaults -device megasas -device scsi-cd,drive=null0 "
        "-blockdev driver=null-co,read-zeroes=on,node-name=null0",
        .objects = "megasas*",
    },{
        .name = "am53c974",
        .args = "-device am53c974,id=scsi -device scsi-hd,drive=disk0 "
                 "-drive id=disk0,if=none,file=null-co://,format=raw "
                 "-nodefaults",
        .objects = "*esp* *scsi* *am53c974*",
    },{
        .name = "ac97",
        .args = "-machine q35 -nodefaults "
        "-device ac97,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "ac97*",
    },*/{
        .name = "cs4231a",
        .args = "-machine q35 -nodefaults "
        "-device cs4231a,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "cs4231a* i8257*",
        .mrnames = "*cs4231a",
        .file = "hw/audio/cs4231a.c",
    },{
        .name = "es1370",
        .args = "-machine q35 -nodefaults "
        "-device es1370,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "es1370*",
        .mrnames = "*es1370*",
        .file = "hw/audio/es1370.c",
    },{
        .name = "sb16",
        .args = "-machine q35 -nodefaults "
        "-device sb16,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "sb16* i8257*",
        .mrnames = "*sb16*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/audio/sb16.c hw/dma/i8257.c"
    },{
        .name = "parallel",
        .args = "-machine q35 -nodefaults "
        "-parallel file:/dev/null",
        .objects = "parallel*",
        .mrnames = "*parallel*",
        .file = "hw/char/parallel.c",
    },{
        // hppa
        .name = "artist",
        .args = "",
        .objects = "*artist.reg*,*artist.vram*",
        .mrnames = "*artist.reg*,*artist.vram*",
        .file = "hw/display/artist.c",
    },{
        // i386, mipsel and ppc
        .name = "ati",
        .argfunc = stateful_fuzz_ati_args,
        .objects = "*ati.mmregs*",
        .mrnames = "*ati.mmregs*",
        .file = "hw/display/ati.c",
    },/*{
        // arm
        .name = "bcm2835-fb",
        // arm supports raspi0/1/2, aarch64 supports raspi3
        .args = "-machine raspi0",
        .objects = "*bcm2835-fb*",
        .mrnames = "*bcm2835-fb*",
        .file = "hw/display/bcm2835_fb.c",
    }*/{
        // i386
        .name = "bochs-display",
        .args = "-device bochs-display",
        .objects = "*bochs dispi interface*,*qemu extended regs*,*bochs-display-mmio*",
        .mrnames = "*bochs dispi interface*,*qemu extended regs*,*bochs-display-mmio*",
        .file = "hw/display/bochs-display.c",
    },{
        // sparc
        .name = "cg3",
        .args = "-m 256M -vga cg3",
        .objects = "*cg3.reg*",
        .mrnames = "*cg3.reg*",
        .file = "hw/display/cg3.c",
    }
};

#endif /* STATEFUL_FUZZ_CONFIGS_H */
