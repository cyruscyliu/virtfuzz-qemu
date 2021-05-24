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
    const char *arch, *name, *args, *objects, *mrnames, *file;
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
        .arch = "i386",
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
    },{
        .arch = "i386",
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
        .arch = "i386",
        .name = "ohci",
        .args = "-machine q35 -nodefaults -device pci-ohci -device usb-kbd",
        .objects = "*usb* *ohci*",
        .mrnames = "*ohci*",
        .file = "hw/usb/hcd-ohci.c",
    },{
        .arch = "i386",
        .name = "uhci",
        .args = "-machine q35 -nodefaults -device piix3-usb-uhci,id=uhci,addr=1d.0 "
        "-drive id=drive0,if=none,file=null-co://,file.read-zeroes=on,format=raw "
        "-device usb-tablet,bus=uhci.0,port=1",
        .objects = "*uhci*",
        .mrnames = "*uhci*",
        .file = "hw/usb/hcd-uhci.c",
    },/*{
        .name = "pc-i440fx",
        .args = "-machine pc",
        .objects = "*",
    },{
        .name = "pc-q35",
        .args = "-machine q35",
        .objects = "*",
    },*/{
        .arch = "i386",
        .name = "vmxnet3",
        .args = "-machine q35 -nodefaults "
        "-device vmxnet3,netdev=net0 -netdev user,id=net0",
        .objects = "vmxnet3",
        .mrnames = "*vmxnet3-b0*,*vmxnet3-b1*",
        .file = "hw/net/vmxnet3.c",
    },{
        .arch = "i386",
        .name = "ne2000",
        .args = "-machine q35 -nodefaults "
        "-device ne2k_pci,netdev=net0 -netdev user,id=net0",
        .objects = "ne2k*",
        .mrnames = "*ne2000*",
        .file = "hw/net/ne2000.c",
    },{
        .arch = "i386",
        .name = "pcnet",
        .args = "-machine q35 -nodefaults "
        "-device pcnet,netdev=net0 -netdev user,id=net0",
        .objects = "pcnet",
        .mrnames = "*pcnet-mmio*,*pcnet-io*",
        .file = "hw/net/pcnet-pci.c",
    },{
        .arch = "i386",
        .name = "rtl8139",
        .args = "-machine q35 -nodefaults "
        "-device rtl8139,netdev=net0 -netdev user,id=net0",
        .objects = "rtl8139",
        .mrnames = "*rtl8139*",
        .file = "hw/net/rtl8139.c",
    },{
        .arch = "i386",
        .name = "i82550",
        .args = "-machine q35 -nodefaults "
        "-device i82550,netdev=net0 -netdev user,id=net0",
        .objects = "*eepro100-mmio*,*eepro100-io*,*eepro100-flash*",
        .mrnames = "*eepro100-mmio*,*eepro100-io*,*eepro100-flash*",
        .file = "hw/net/eepro100.c",
    },{
        .arch = "i386",
        .name = "e1000",
        .args = "-M q35 -nodefaults "
        "-device e1000,netdev=net0 -netdev user,id=net0",
        .objects = "e1000",
        .mrnames = "*e1000-mmio*,*e1000-io*",
        .file = "hw/net/e1000.c",
    },{
        .arch = "i386",
        .name = "e1000e",
        .args = "-M q35 -nodefaults "
        "-device e1000e,netdev=net0 -netdev user,id=net0",
        .objects = "e1000e",
        .mrnames = "*e1000e-mmio*,*e1000e-io*",
        .file = "hw/net/e1000e.c",
    },{
        .arch = "i386",
        .name = "kvaser-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0 -device kvaser_pci,canbus=canbus0",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .objects = "*kvaser_pci-s5920*,*kvaser_pci-sja*,*kvaser_pci-xilinx*",
        .mrnames = "*kvaser_pci-s5920*,*kvaser_pci-sja*,*kvaser_pci-xilinx*",
    },{
        .arch = "i386",
        .name = "mioe3680-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0 "
        "-device pcm3680_pci,canbus0=canbus0,canbus1=canbus0",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .objects = "*mioe3680_pci-sja1*,*mioe3680_pci-sja2*",
        .mrnames = "*mioe3680_pci-sja1*,*mioe3680_pci-sja2*"
    },{
        .arch = "i386",
        .name = "pcm3680-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0 "
        "-device mioe3680_pci,canbus0=canbus0",
        // "-object can-host-socketcan,id=canhost0,if=can0,canbus=canbus0",
        .objects = "*pcm3680i_pci-sja1*,*pcm3680i_pci-sja2*",
        .mrnames = "*pcm3680i_pci-sja1*,*pcm3680i_pci-sja2*",
    },{
        .arch = "i386",
        .name = "ctu-can",
        .args = "-machine q35 -nodefaults "
        "-object can-bus,id=canbus0-bus "
        "-device cutcan_pci,canbus0=canbus0-bus,canbus1=canbus0-bus",
        // "-object can-host-socketcan,if=can0,canbus=canbus0-bus,id=canbus0-socketcan",
        .objects = "*ctucan_pci-core0*,*ctucan_pci-core1*",
        .mrnames = "*ctucan_pci-core0*,*ctucan_pci-core1*",
    },{
        .arch = "i386",
        .name = "rocker",
        .args = "-machine q35 -nodefaults "
        "-device rocker,name=sw1,len-ports=4,ports[0]=dev0,"
        "ports[1]=dev1,ports[2]=dev2,ports[3]=dev3 "
        "-netdev socket,udp=127.0.0.1:1204,localaddr=127.0.0.1:1215,id=dev0 "
        "-netdev socket,udp=127.0.0.1:1205,localaddr=127.0.0.1:1219,id=dev1 "
        "-netdev socket,udp=127.0.0.1:1206,localaddr=127.0.0.1:1211,id=dev2 "
        "-netdev socket,udp=127.0.0.1:1207,localaddr=127.0.0.1:1223,id=dev3",
        .objects = "*rocker-mmio*",
        .mrnames = "*rocker-mmio*",
        .file = "hw/net/rocker/rocker.c",
    },/*{
        .name = "sdhci-v3",
        .args = "-nodefaults -device sdhci-pci,sd-spec-version=3 "
        "-device sd-card,drive=mydrive "
        "-drive if=none,index=0,file=null-co://,format=raw,id=mydrive -nographic",
        .objects = "sd*"
    },{
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
    },*/{
        .arch = "i386",
        .name = "ac97",
        .args = "-machine q35 -nodefaults "
        "-device ac97,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "ac97*",
        .mrnames = "*ac97-nam*,*ac97-nabm*",
        .file = "hw/audio/ac97.c",
    },{
        .arch = "i386",
        .name = "cs4231a",
        .args = "-machine q35 -nodefaults "
        "-device cs4231a,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "cs4231a* i8257*",
        .mrnames = "*cs4231a*",
        .file = "hw/audio/cs4231a.c",
    },{
        .arch = "i386",
        .name = "cs4231",
        .args = "-machine q35 -nodefaults "
        "-device cs4231,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "cs4231a* i8257*",
        .mrnames = "*cs4231*",
        .file = "hw/audio/cs4231.c",
    },{
        .arch = "i386",
        .name = "es1370",
        .args = "-machine q35 -nodefaults "
        "-device es1370,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "es1370*",
        .mrnames = "*es1370*",
        .file = "hw/audio/es1370.c",
    },{
        .arch = "i386",
        .name = "sb16",
        .args = "-machine q35 -nodefaults "
        "-device sb16,audiodev=snd0 -audiodev none,id=snd0 -nodefaults",
        .objects = "sb16* i8257*",
        .mrnames = "*sb16*,*dma-chan*,*dma-page*,*dma-pageh*,*dma-cont*",
        .file = "hw/audio/sb16.c hw/dma/i8257.c"
    },{
        .arch = "i386",
        .name = "parallel",
        .args = "-machine q35 -nodefaults "
        "-parallel file:/dev/null",
        .objects = "parallel*",
        .mrnames = "*parallel*",
        .file = "hw/char/parallel.c",
    },{
        // i386, mipsel and ppc
        .arch = "i386",
        .name = "ati",
        .args = "-machine q35 -nodefaults "
        "-device ati-vga,romfile=\"\"",
        .objects = "*ati.mmregs*",
        .mrnames = "*ati.mmregs*",
        .file = "hw/display/ati.c",
    },{
        .arch = "i386",
        .name = "cirrus-vga",
        .args = "-machine q35 -nodefaults -device cirrus-vga",
        .objects = "cirrus*",
        .mrnames = "*cirrus-io*,*cirrus-low-memory*,"
        "*cirrus-linear-io*,*cirrus-bitblt-mmio*,*cirrus-mmio*",
        .file = "hw/display/cirrus-vga.c",
    },{
        .arch = "i386",
        .name = "qxl",
        .args = "-machine q35 -nodefaults -device qxl",
        .objects = "*qxl-ioports*",
        .mrnames = "*qxl-ioports*",
        .file = "hw/display/qxl.c",
    },{
        .arch = "i386",
        .name = "vmware-svga",
        .args = "-machine q35 -nodefaults -device vmware-svga",
        .objects = "*vmsvga-io*",
        .mrnames = "*vmsvga-io*",
        .file = "hw/display/vmware-svga.c",
    },{
        .arch = "i386",
        .name = "vga-std",
        .args = "-machine q35 -nodefaults -device VGA",
        .objects = "*vga-lowmem*,*vga ioports remapped*,"
        "*bochs dispi interface*,*qemu extended regs*,"
        "*vga-mm-ctrl*,*vga-mem*,",
        .mrnames = "*vga-lowmem*,*vga ioports remapped*,"
        "*bochs dispi interface*,*qemu extended regs*,"
        "*vga-mm-ctrl*,*vga-mem*,",
        .file = "hw/display/vga.c",
    },{
        .arch = "i386",
        .name = "bochs-display",
        .args = "-machine q35 -nodefaults -device bochs-display",
        .objects = "*bochs dispi interface*,*qemu extended regs*,*bochs-display-mmio*",
        .mrnames = "*bochs dispi interface*,*qemu extended regs*,*bochs-display-mmio*",
        .file = "hw/display/bochs-display.c",
    },{
        .arch = "i386",
        .name = "vmw-pvscsi",
        .args = "-machine q35 -nodefaults -device pvscsi",
        .objects = "*pvscsi-io*",
        .mrnames = "*pvscsi-io*",
        .file = "hw/scsi/vmw_pvscsi.c",
    },
    /*{
        .arch = "arm",
        .name = "tusb6010",
        .args = "-machine n810 -m 128M -usb",
        .objects = "*tusb-async* *",
        .mrnames = "*tusb-async*",
        .file = "hw/usb/tusb6010.c",
    },*/{
        .arch = "arm",
        .name = "imx-usb-phy",
        .args = "-machine sabrelite",
        .objects = "*imx-usbphy*",
        .mrnames = "*imx-usbphy*",
        .file = "hw/usb/imx-usb-phy.c",
    },{
        .arch = "arm",
        .name = "chipidea",
        .args = "-machine sabrelite",
        .objects = "*usb-chipidea.misc*,*capabilities*,"
        "*usb-chipidea.dc*,*operational*,*ports*,*usb-chipidea.endpoints*",
        .mrnames = "*usb-chipidea.misc*,*capabilities*,"
        "*usb-chipidea.dc*,*operational*,*ports*,*usb-chipidea.endpoints*",
        .file = "hw/usb/chipidea.c",
    },{
        .arch = "aarch64",
        .name = "versal-usb2",
        .args = "-machine xlnx-versal-virt",
        .objects = "*versal.usb2Ctrl_alias*",
        .mrnames = "*versal.usb2Ctrl_alias*",
        .file = "hw/usb/xlnx-versal-usb2-ctrl-regs.c",
    },{
        .arch = "aarch64",
        .name = "dwc3",
        .args = "-machine xlnx-versal-virt",
        .objects = "*versal.dwc3_alias*",
        .mrnames = "*versal.dwc3_alias*",
        .file = "hw/usb/hcd-dwc3.c",
    },{
        .arch = "arm",
        .name = "dwc2",
        // arm supports raspi0/1/2, aarch64 supports raspi3
        .args = "-machine raspi0",
        .objects = "*dwc2-io* *dwc2-fifo*",
        .mrnames = "*dwc2-io*,*dwc2-fifo*",
        .file = "hw/usb/hcd-dwc2.c",
    },{
        .arch = "arm",
        .name = "xgmac",
        .args = "-machine midway",
        .objects = "*xgmac*",
        .mrnames = "*xgmac*",
        .file = "hw/net/xgmac.c",
    },{
        .arch = "arm",
        .name = "stellaris-enet",
        .args = "-machine lm3s6965evb",
        .objects = "*stellaris_enet*",
        .mrnames = "*stellaris_enet*",
        .file = "hw/net/stellaris_enet.c",
    },{
        .arch = "arm",
        .name = "scm91c111",
        .args = "-machine mainstone",
        .objects = "*smc91c111-mmio*",
        .mrnames = "*smc91c111-mmio*",
        .file = "hw/net/smc91c111.c",
    },{
        .arch = "arm",
        .name = "npcm7xx-emc",
        .args = "-machine npcm750-evb",
        .objects = "*npcm7xx-emc*",
        .mrnames = "*npcm7xx-emc*",
        .file = "hw/net/npcm7xx_emc.c",
    },{
        .arch = "arm",
        .name = "msf2-emac",
        .args= "-machine emcraft-sf2",
        .objects = "*msf2-emac*",
        .mrnames = "*msf2-emac*",
        .file = "hw/net/msf2-emac.c",
    },{
        .arch = "arm",
        .name = "lan9118",
        .args = "-machine smdkc210",
        .objects = "*lan9118-mmio*",
        .mrnames = "*lan9118-mmio*",
        .file = "hw/net/lan9118.c",
    },{
        .arch = "arm",
        .name = "imx-fec",
        .args = "-machine sabrelite",
        .objects = "*imx.fec*",
        .mrnames = "*imx.fec*",
        .file = "hw/net/imx_fec.c",
    },{
        .arch = "arm",
        .name = "ftgmac100",
        .args = "-machine palmetto-bmc",
        .objects = "*ftgmac100*,*aspeed-mmi*",
        .mrnames = "*ftgmac100*,*aspeed-mmi*",
        .file = "hw/net/ftgmac100.c",
    },{
        .arch = "aarch64",
        .name = "cadence-gem",
        .args = "-machine xlnx-versal-virt",
        .objects = "*enet*",
        .mrnames = "*enet*",
        .file = "hw/net/cadence_gem.c",
    },{
        .arch = "arm",
        .name = "allwinner-sun8i-emac",
        .args = "-machine orangepi-pc -m 1G",
        .objects = "*allwinner-sun8i-emac*",
        .mrnames = "*allwinner-sun8i-emac*",
        .file = "hw/net/allwinner-sun8i-emac.c",
    },{
        .arch = "arm",
        .name = "allwinner-emac",
        .args = "-machine cubieboard",
        .objects = "*aw_emac*",
        .mrnames = "*aw_emac*",
        .file = "hw/net/allwinner-sun8i-emac.c",
    },{
        .arch = "aarch64",
        .name = "xlnx-zynqmp-can",
        .args = "-machine xlnx-zcu102",
        .objects = "*xlnx.zynqmp-can*",
        .mrnames = "*xlnx.zynqmp-can*",
        .file = "hw/net/can/xlnx-zynqmp-can.c",
    },{
        .arch = "aarch64",
        .name = "xlnx-dp",
        .args = "-machine xlnx-zcu102",
        .objects = "*.core*,*.v_blend*,*.av_buffer_manager*,*.audio*",
        .mrnames = "*.core*,*.v_blend*,*.av_buffer_manager*,*.audio*",
        .file = "hw/display/xlnx_dp.c",
    },{
        .arch = "arm",
        .name = "exynos4210-fimd",
        .args = "-machine smdkc210",
        .objects = "*exynos4210.fimd*",
        .mrnames = "*exynos4210.fimd*",
        .file = "hw/net/lan9118.c",
    },{
        .arch = "arm",
        .name = "omap-dss",
        .args = "-machine n810 -m 128M",
        .objects = "*omap.diss1*,*omap.disc1*,*omap.rfbi1*,*omap.venc1*,*omap.im3*",
        .mrnames = "*omap.diss1*,*omap.disc1*,*omap.rfbi1*,*omap.venc1*,*omap.im3*",
        .file = "hw/net/omap_dss.c",
    },{
        .arch = "arm",
        .name = "omap-lcdc",
        .args = "-machine sx1-v1 -m 32M",
        .objects = "*omap.lcdc*",
        .mrnames = "*omap.lcdc*",
        .file = "hw/net/omap_lcdc.c",
    },{
        .arch = "arm",
        .name = "pl110",
        .args = "-machine integratorcp",
        .objects = "*pl110*",
        .mrnames = "*pl110*",
        .file = "hw/display/pl110.c",
    },{
        .arch = "arm",
        .name = "pxa2xx-lcd",
        .args = "-machine verdex",
        .objects = "*pxa2xx-lcd-controller*",
        .mrnames = "*pxa2xx-lcd-controller*",
        .file = "/hw/display/pxa2xx_lcd.c",
    },{
        .arch = "arm",
        .name = "tc6393xb",
        .args = "-machine tosa",
        .objects = "*tc6393xb*",
        .mrnames = "*tc6393xb*",
        .file = "hw/display/tc6393xb.c",
    },{
        .arch = "arm",
        .name = "pl041",
        .args = "-machine integratorcp",
        .objects = "*pl041*",
        .mrnames = "*pl041*",
        .file = "hw/audio/pl041.c",
    }
};

#endif /* STATEFUL_FUZZ_CONFIGS_H */
