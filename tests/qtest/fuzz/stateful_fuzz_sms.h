/*
 * Generic Virtual-Device Fuzzing Target Trace State Callbacks
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <qiangliu@zju.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef STATEFUL_FUZZ_TSC_H
#define STATEFUL_FUZZ_TSC_H

#include "exec/ioport.h"
#include "tests/qtest/libqos/pci-pc.h"
#include "tests/qtest/libqos/libqtest.h"
#include "fuzz.h"

typedef struct Callback {
    uint8_t id;
    char name[32];
    uint8_t *(*get_data)(void);
    size_t (*get_size)(void);
} Callback;

#define CALLBACK_MAXSIZE 0x2000

// ==== hw/usb/hcd-uhci.c:uhci_process_frame:frame_addr = ============================
size_t size_0 = 0;

static uint64_t uhci_qh_0 = 0;
static uint64_t UHCI_TD_v4e01cb2c4a = 0;
static uint64_t buffer_vf5858bd7ea = 0;
static uint64_t UHCI_TD_ve55cf5120b = 0;
static uint64_t buffer_v3f969fa3ad = 0;
static uint64_t v251d900aab_base = 0;

static uint8_t *get_data_0() {
    size_0 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    switch (get_data_from_pool4() % 1){ 
        case 0: goto va11dea8b82_0; break;
    }
va11dea8b82_0:;
    stateful_free(uhci_qh_0);
    uhci_qh_0 = stateful_malloc(0x8, /*chained=*/false);
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vdff9582220_0; break;
    }
vdff9582220_0:;
    stateful_free(UHCI_TD_v4e01cb2c4a);
    UHCI_TD_v4e01cb2c4a = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vc10f8f393d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc10f8f393d[i] = (uint32_t)(UHCI_TD_v4e01cb2c4a & 0xfffffffe);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_v4e01cb2c4a + 0x0, 0x4, (uint8_t *)vc10f8f393d);
    free(vc10f8f393d);
    uint32_t *v924ffecc1e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v924ffecc1e[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x12 + 1)) - 1)) << 0x12) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02));
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_v4e01cb2c4a + 0x4, 0x4, (uint8_t *)v924ffecc1e);
    free(v924ffecc1e);
    uint32_t *vc71ec9ab87 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc71ec9ab87[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b));
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_v4e01cb2c4a + 0x8, 0x4, (uint8_t *)vc71ec9ab87);
    free(vc71ec9ab87);
    stateful_free(buffer_vf5858bd7ea);
    buffer_vf5858bd7ea = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v86d5adab70 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v86d5adab70[i] = (uint32_t)get_data_from_pool4();
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf5858bd7ea + 0x0, 0x100, (uint8_t *)v86d5adab70);
    free(v86d5adab70);
    uint32_t *v31ae7619cf = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v31ae7619cf[i] = (uint32_t)(buffer_vf5858bd7ea | 0x0);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_v4e01cb2c4a + 0xc, 0x4, (uint8_t *)v31ae7619cf);
    free(v31ae7619cf);
    uint32_t *v71183461ba = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v71183461ba[i] = (uint32_t)(UHCI_TD_v4e01cb2c4a & 0xfffffffe);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, uhci_qh_0 + 0x0, 0x4, (uint8_t *)v71183461ba);
    free(v71183461ba);
    goto vdff9582220_out;
vdff9582220_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v56f0818d59_0; break;
    }
v56f0818d59_0:;
    stateful_free(UHCI_TD_ve55cf5120b);
    UHCI_TD_ve55cf5120b = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vb96aafbe70 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb96aafbe70[i] = (uint32_t)(UHCI_TD_ve55cf5120b & 0xfffffffe);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_ve55cf5120b + 0x0, 0x4, (uint8_t *)vb96aafbe70);
    free(vb96aafbe70);
    uint32_t *v46fb6b29bc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v46fb6b29bc[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x12 + 1)) - 1)) << 0x12) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02));
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_ve55cf5120b + 0x4, 0x4, (uint8_t *)v46fb6b29bc);
    free(v46fb6b29bc);
    uint32_t *v29eda36e13 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v29eda36e13[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b));
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_ve55cf5120b + 0x8, 0x4, (uint8_t *)v29eda36e13);
    free(v29eda36e13);
    stateful_free(buffer_v3f969fa3ad);
    buffer_v3f969fa3ad = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v685affb810 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v685affb810[i] = (uint32_t)get_data_from_pool4();
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3f969fa3ad + 0x0, 0x100, (uint8_t *)v685affb810);
    free(v685affb810);
    uint32_t *v95ac457759 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v95ac457759[i] = (uint32_t)(buffer_v3f969fa3ad | 0x0);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, UHCI_TD_ve55cf5120b + 0xc, 0x4, (uint8_t *)v95ac457759);
    free(v95ac457759);
    uint32_t *v4e3d7cf023 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4e3d7cf023[i] = (uint32_t)(UHCI_TD_ve55cf5120b & 0xfffffffe);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, uhci_qh_0 + 0x4, 0x4, (uint8_t *)v4e3d7cf023);
    free(v4e3d7cf023);
    goto v56f0818d59_out;
v56f0818d59_out:;
    stateful_free(v251d900aab_base);
    v251d900aab_base = stateful_malloc(0x1000, /*chained=*/false);
    uint32_t *vd2a27d8bd1 = (uint32_t *)malloc(0x1000);
    for (int i = 0; i < (0x1000) / 4; i++)
        vd2a27d8bd1[i] = (uint32_t)((uhci_qh_0 & 0xfffffffe) | 0x2);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, v251d900aab_base, 0x1000, (uint8_t *)vd2a27d8bd1);
    free(vd2a27d8bd1);
    uint64_t v3644be3862 = (v251d900aab_base | 0x0);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, get_interface_id("uhci", EVENT_TYPE_MMIO_WRITE), 0x8, 0x4, (uint8_t *)&v3644be3862);
    uint64_t va5aa382561 = (v251d900aab_base | 0x0);
    size_0 += serialize(Data, size_0, CALLBACK_MAXSIZE, get_interface_id("uhci", EVENT_TYPE_MMIO_WRITE), 0xa, 0x4, (uint8_t *)&va5aa382561);
    goto va11dea8b82_out;
va11dea8b82_out:;
    return Data;
}

static size_t get_size_0() { return size_0;}

// ==== hw/usb/hcd-ohci.c:ohci_frame_boundary:if (ohci_read_ ============================
size_t size_1 = 0;

static uint64_t ohci_hcca_0 = 0;
static uint64_t OHCI_ED_v81164b7fea = 0;
static uint64_t OHCI_TD_vf231cdc88d = 0;
static uint64_t OHCI_ISO_TD_v8393b4fa37 = 0;
static uint64_t buffer_vd68e208057 = 0;
static uint64_t buffer_v3f28aafeb0 = 0;
static uint64_t buffer_veaa162849e = 0;
static uint64_t buffer_v458b794c1f = 0;
static uint64_t buffer_v98df63c7be = 0;
static uint64_t buffer_vd24a9f270c = 0;
static uint64_t buffer_v54dbc26b2f = 0;
static uint64_t buffer_v3275f545dd = 0;
static uint64_t OHCI_ED_va879e3af45 = 0;
static uint64_t OHCI_TD_v922543458d = 0;
static uint64_t OHCI_ISO_TD_vdb92104708 = 0;
static uint64_t buffer_v9baeac771f = 0;
static uint64_t buffer_ve40371275c = 0;
static uint64_t buffer_va5486e299d = 0;
static uint64_t buffer_vb99810954e = 0;
static uint64_t buffer_vb044254cc5 = 0;
static uint64_t buffer_v11a8638f35 = 0;
static uint64_t buffer_vcc1ca0e6eb = 0;
static uint64_t buffer_v77f439caba = 0;
static uint64_t OHCI_ED_v32c8c47c4b = 0;
static uint64_t OHCI_TD_v7232ea3c7f = 0;
static uint64_t OHCI_ISO_TD_vee366973a0 = 0;
static uint64_t buffer_vf5c6b47b25 = 0;
static uint64_t buffer_v3129285d9f = 0;
static uint64_t buffer_v399e7f8d28 = 0;
static uint64_t buffer_vc37a92f9c8 = 0;
static uint64_t buffer_v8094b305ff = 0;
static uint64_t buffer_ve058428f59 = 0;
static uint64_t buffer_vd4d2dde429 = 0;
static uint64_t buffer_v77958220b8 = 0;
static uint64_t OHCI_ED_v78e7558907 = 0;
static uint64_t OHCI_TD_v629ecec2b7 = 0;
static uint64_t OHCI_ISO_TD_vf06a200357 = 0;
static uint64_t buffer_v86824d223a = 0;
static uint64_t buffer_v585420547d = 0;
static uint64_t buffer_v38a8dd4906 = 0;
static uint64_t buffer_v6bc9d9297e = 0;
static uint64_t buffer_v4423986e7f = 0;
static uint64_t buffer_vdd00a54fca = 0;
static uint64_t buffer_v1c63d43713 = 0;
static uint64_t buffer_v9d35e92dfb = 0;
static uint64_t OHCI_ED_v1285dad4a2 = 0;
static uint64_t OHCI_TD_vebff96ae49 = 0;
static uint64_t OHCI_ISO_TD_v8232aac463 = 0;
static uint64_t buffer_v6a3654d69f = 0;
static uint64_t buffer_vbc4e29bedb = 0;
static uint64_t buffer_vc120119ade = 0;
static uint64_t buffer_v6b7af89b80 = 0;
static uint64_t buffer_v5add0781e9 = 0;
static uint64_t buffer_vdea57e43a8 = 0;
static uint64_t buffer_v748e85dac8 = 0;
static uint64_t buffer_v883225308d = 0;
static uint64_t OHCI_ED_v68d1108293 = 0;
static uint64_t OHCI_TD_v29072580c5 = 0;
static uint64_t OHCI_ISO_TD_v7f6cc61337 = 0;
static uint64_t buffer_vf8531b7011 = 0;
static uint64_t buffer_ve067f760b7 = 0;
static uint64_t buffer_v6a53410a2f = 0;
static uint64_t buffer_v34058be64c = 0;
static uint64_t buffer_vef72b1bd42 = 0;
static uint64_t buffer_vca2a9e5b2f = 0;
static uint64_t buffer_v5e0a9aea92 = 0;
static uint64_t buffer_v805a2002b0 = 0;
static uint64_t OHCI_ED_vcb9e45204e = 0;
static uint64_t OHCI_TD_va959efa3c0 = 0;
static uint64_t OHCI_ISO_TD_vbf1f52814a = 0;
static uint64_t buffer_v8b5def445a = 0;
static uint64_t buffer_v69c2a446fe = 0;
static uint64_t buffer_va81bbff362 = 0;
static uint64_t buffer_vebbe6a57f8 = 0;
static uint64_t buffer_vfb79a10548 = 0;
static uint64_t buffer_v6ec3549f81 = 0;
static uint64_t buffer_v69437ff543 = 0;
static uint64_t buffer_v9aeab9bd2d = 0;
static uint64_t OHCI_ED_v1f860b5e7d = 0;
static uint64_t OHCI_TD_v47c1ab847d = 0;
static uint64_t OHCI_ISO_TD_v78de0b4614 = 0;
static uint64_t buffer_ve6bef76bbc = 0;
static uint64_t buffer_vb2baa484c3 = 0;
static uint64_t buffer_v519220479f = 0;
static uint64_t buffer_v896aa2840d = 0;
static uint64_t buffer_vba8562f2d3 = 0;
static uint64_t buffer_v5e2bd96bd2 = 0;
static uint64_t buffer_v6da84b519f = 0;
static uint64_t buffer_vb4377e0ea3 = 0;
static uint64_t OHCI_ED_v5c6208182c = 0;
static uint64_t OHCI_TD_v5e41a11de4 = 0;
static uint64_t OHCI_ISO_TD_v2107991b24 = 0;
static uint64_t buffer_va78ae40bc7 = 0;
static uint64_t buffer_ve2d9b74a66 = 0;
static uint64_t buffer_v9ae5fee8f1 = 0;
static uint64_t buffer_v9cf22a9932 = 0;
static uint64_t buffer_vf204bb78dc = 0;
static uint64_t buffer_v19476a70a9 = 0;
static uint64_t buffer_v9851eace85 = 0;
static uint64_t buffer_v8265f708c4 = 0;
static uint64_t OHCI_ED_vf35a963ded = 0;
static uint64_t OHCI_TD_v1077bac3ab = 0;
static uint64_t OHCI_ISO_TD_vf6e15c50e0 = 0;
static uint64_t buffer_vbbff95f8aa = 0;
static uint64_t buffer_va6776326b7 = 0;
static uint64_t buffer_v6a860186a0 = 0;
static uint64_t buffer_v9289fed4b0 = 0;
static uint64_t buffer_v6f222458e2 = 0;
static uint64_t buffer_v691b637c9f = 0;
static uint64_t buffer_v4c6e245696 = 0;
static uint64_t buffer_vc8a284519f = 0;
static uint64_t OHCI_ED_v59b697e67a = 0;
static uint64_t OHCI_TD_vceca893c37 = 0;
static uint64_t OHCI_ISO_TD_vdd8f0e9cb1 = 0;
static uint64_t buffer_v2d45dab201 = 0;
static uint64_t buffer_v363f288dcd = 0;
static uint64_t buffer_ve4fc1161d5 = 0;
static uint64_t buffer_vd8f1a9c6cd = 0;
static uint64_t buffer_vb930684195 = 0;
static uint64_t buffer_vf7c9ffb494 = 0;
static uint64_t buffer_vc7637892ed = 0;
static uint64_t buffer_v840e11cd91 = 0;
static uint64_t OHCI_ED_v72478fddcf = 0;
static uint64_t OHCI_TD_vdff68ad86f = 0;
static uint64_t OHCI_ISO_TD_vfb314c966c = 0;
static uint64_t buffer_v97062949d8 = 0;
static uint64_t buffer_v592f36f145 = 0;
static uint64_t buffer_vd819752f1e = 0;
static uint64_t buffer_vb99ad6f44b = 0;
static uint64_t buffer_v2fcdd422a3 = 0;
static uint64_t buffer_v73311c9ee5 = 0;
static uint64_t buffer_v25a50e82ba = 0;
static uint64_t buffer_v5d18eb6da9 = 0;
static uint64_t OHCI_ED_v5bae16dbe6 = 0;
static uint64_t OHCI_TD_vb626f3d74a = 0;
static uint64_t OHCI_ISO_TD_v56d6404857 = 0;
static uint64_t buffer_v67f9cfa38f = 0;
static uint64_t buffer_v442e9fdeeb = 0;
static uint64_t buffer_v33616977be = 0;
static uint64_t buffer_v2b4ae57211 = 0;
static uint64_t buffer_vc3a4ed43d9 = 0;
static uint64_t buffer_v99ab3aabae = 0;
static uint64_t buffer_v30dbd38cf0 = 0;
static uint64_t buffer_vbf64f01fa7 = 0;
static uint64_t OHCI_ED_vb975b0d310 = 0;
static uint64_t OHCI_TD_vf75062ddad = 0;
static uint64_t OHCI_ISO_TD_v7b065139db = 0;
static uint64_t buffer_v154ced97b6 = 0;
static uint64_t buffer_vaf7d9f29a0 = 0;
static uint64_t buffer_v6cf41f1fd1 = 0;
static uint64_t buffer_v5cf14877fa = 0;
static uint64_t buffer_ve8ef281d2a = 0;
static uint64_t buffer_v7cc77b092d = 0;
static uint64_t buffer_v2d5e19ec92 = 0;
static uint64_t buffer_v318c32de43 = 0;
static uint64_t OHCI_ED_v7c8824df8a = 0;
static uint64_t OHCI_TD_va1343e764d = 0;
static uint64_t OHCI_ISO_TD_v22ecfe7c30 = 0;
static uint64_t buffer_v9af220eeae = 0;
static uint64_t buffer_vb2eb8bd014 = 0;
static uint64_t buffer_v263f2d6bd4 = 0;
static uint64_t buffer_ve65f6258e7 = 0;
static uint64_t buffer_v103fa42755 = 0;
static uint64_t buffer_v2fc78ef9f0 = 0;
static uint64_t buffer_v580ca41b8e = 0;
static uint64_t buffer_v434f829ac7 = 0;
static uint64_t OHCI_ED_vf2168e7fcb = 0;
static uint64_t OHCI_TD_va6001fcc0b = 0;
static uint64_t OHCI_ISO_TD_v1c535a6f26 = 0;
static uint64_t buffer_v6e5073f819 = 0;
static uint64_t buffer_va07a818eff = 0;
static uint64_t buffer_v6bc52b829a = 0;
static uint64_t buffer_v8a2ad47de3 = 0;
static uint64_t buffer_v4af81f2d76 = 0;
static uint64_t buffer_v2fd1bcb88e = 0;
static uint64_t buffer_v3ef717bf53 = 0;
static uint64_t buffer_va5100cbb72 = 0;
static uint64_t OHCI_ED_vaaf673a702 = 0;
static uint64_t OHCI_TD_v5cc3f3d337 = 0;
static uint64_t OHCI_ISO_TD_v2d120dca5c = 0;
static uint64_t buffer_ved89e0536c = 0;
static uint64_t buffer_v8d5a914df2 = 0;
static uint64_t buffer_v7c42d128fa = 0;
static uint64_t buffer_v53bdb5e7b8 = 0;
static uint64_t buffer_v7b618a1265 = 0;
static uint64_t buffer_ve0ed561160 = 0;
static uint64_t buffer_vc27a8fb4e6 = 0;
static uint64_t buffer_v8489b64757 = 0;
static uint64_t OHCI_ED_v4e3dbc5834 = 0;
static uint64_t OHCI_TD_ve98748447d = 0;
static uint64_t OHCI_ISO_TD_v855001654c = 0;
static uint64_t buffer_vc6cd6e2277 = 0;
static uint64_t buffer_vc3e3e76f0c = 0;
static uint64_t buffer_v36b9344039 = 0;
static uint64_t buffer_vc08b7027b8 = 0;
static uint64_t buffer_v24d367fa23 = 0;
static uint64_t buffer_v543d2477c4 = 0;
static uint64_t buffer_v2ae1d099b4 = 0;
static uint64_t buffer_v6a593f9da8 = 0;
static uint64_t OHCI_ED_v33c56230b2 = 0;
static uint64_t OHCI_TD_v197153114f = 0;
static uint64_t OHCI_ISO_TD_v1abf68e372 = 0;
static uint64_t buffer_va177a5415b = 0;
static uint64_t buffer_v798655a910 = 0;
static uint64_t buffer_v3993bbed23 = 0;
static uint64_t buffer_va30c67dacd = 0;
static uint64_t buffer_vdc2033ea3a = 0;
static uint64_t buffer_vf82611ea27 = 0;
static uint64_t buffer_vbd8b149838 = 0;
static uint64_t buffer_v79b23b8a06 = 0;
static uint64_t OHCI_ED_v6446fb8de8 = 0;
static uint64_t OHCI_TD_vebf10d9d4d = 0;
static uint64_t OHCI_ISO_TD_vf17f1f7bd9 = 0;
static uint64_t buffer_v54d75568ea = 0;
static uint64_t buffer_vdff9677a71 = 0;
static uint64_t buffer_vf2db191ab5 = 0;
static uint64_t buffer_vd67d170a50 = 0;
static uint64_t buffer_vcc9ba7a06f = 0;
static uint64_t buffer_v779d5f4a75 = 0;
static uint64_t buffer_v6125477e8f = 0;
static uint64_t buffer_v36896dbef3 = 0;
static uint64_t OHCI_ED_va4abf435e9 = 0;
static uint64_t OHCI_TD_v78f31f879f = 0;
static uint64_t OHCI_ISO_TD_v8a7eec2666 = 0;
static uint64_t buffer_v8c821a281c = 0;
static uint64_t buffer_v572b6fb3a2 = 0;
static uint64_t buffer_v44caafc8e4 = 0;
static uint64_t buffer_v3a032c79cc = 0;
static uint64_t buffer_v720c1794f7 = 0;
static uint64_t buffer_vcd82c8f33e = 0;
static uint64_t buffer_v852a4d4146 = 0;
static uint64_t buffer_v80f666f3f1 = 0;
static uint64_t OHCI_ED_v3cece50348 = 0;
static uint64_t OHCI_TD_v7f2ad8f742 = 0;
static uint64_t OHCI_ISO_TD_v72ca86e053 = 0;
static uint64_t buffer_v7dc1df7ede = 0;
static uint64_t buffer_v930e597138 = 0;
static uint64_t buffer_v892031d9ca = 0;
static uint64_t buffer_veadb00b431 = 0;
static uint64_t buffer_v7e355427f2 = 0;
static uint64_t buffer_v3759de393a = 0;
static uint64_t buffer_v5d3b0600b1 = 0;
static uint64_t buffer_v6a8a2bbae6 = 0;
static uint64_t OHCI_ED_v4651a753b7 = 0;
static uint64_t OHCI_TD_v81bf29f647 = 0;
static uint64_t OHCI_ISO_TD_v30a3d00380 = 0;
static uint64_t buffer_vdb2be98296 = 0;
static uint64_t buffer_vec7fe3f69f = 0;
static uint64_t buffer_v4ff38b57c4 = 0;
static uint64_t buffer_v3df5b7057a = 0;
static uint64_t buffer_v453834c311 = 0;
static uint64_t buffer_va544614d80 = 0;
static uint64_t buffer_v83da76a00d = 0;
static uint64_t buffer_v36a7125b6b = 0;
static uint64_t OHCI_ED_vd230cc249a = 0;
static uint64_t OHCI_TD_v2020678ba4 = 0;
static uint64_t OHCI_ISO_TD_vba7ed8625a = 0;
static uint64_t buffer_va7044a36bd = 0;
static uint64_t buffer_vc34451aaa9 = 0;
static uint64_t buffer_vfb1b8a22d2 = 0;
static uint64_t buffer_v607f9817b5 = 0;
static uint64_t buffer_vfe67076431 = 0;
static uint64_t buffer_vb6f1937c5c = 0;
static uint64_t buffer_v3de28d37e3 = 0;
static uint64_t buffer_v116ad00384 = 0;
static uint64_t OHCI_ED_vd49b9682d1 = 0;
static uint64_t OHCI_TD_vddea1f018d = 0;
static uint64_t OHCI_ISO_TD_v42b0d4018c = 0;
static uint64_t buffer_v30d50e4d83 = 0;
static uint64_t buffer_v132c8de7fa = 0;
static uint64_t buffer_vfd99088383 = 0;
static uint64_t buffer_v8a05b7a5cc = 0;
static uint64_t buffer_vdd452386ab = 0;
static uint64_t buffer_vb83befd935 = 0;
static uint64_t buffer_v224764ab98 = 0;
static uint64_t buffer_v9b5b4a99e8 = 0;
static uint64_t OHCI_ED_v198ccf7758 = 0;
static uint64_t OHCI_TD_va2de764cb1 = 0;
static uint64_t OHCI_ISO_TD_v5787981e85 = 0;
static uint64_t buffer_v449c8ae871 = 0;
static uint64_t buffer_v6d9465c493 = 0;
static uint64_t buffer_va6570b8e9c = 0;
static uint64_t buffer_vef689c46df = 0;
static uint64_t buffer_v817ba6fb86 = 0;
static uint64_t buffer_v3025825c7b = 0;
static uint64_t buffer_v6697e75298 = 0;
static uint64_t buffer_vdaa38e0334 = 0;
static uint64_t OHCI_ED_v8addb6523f = 0;
static uint64_t OHCI_TD_v4e0e675098 = 0;
static uint64_t OHCI_ISO_TD_vad8df616a8 = 0;
static uint64_t buffer_ve203f9c388 = 0;
static uint64_t buffer_va5a5aefffe = 0;
static uint64_t buffer_va6d52a7a80 = 0;
static uint64_t buffer_vcac819637c = 0;
static uint64_t buffer_v7ec284a5a2 = 0;
static uint64_t buffer_v4d6e96ecf5 = 0;
static uint64_t buffer_vbc6fc8847d = 0;
static uint64_t buffer_v462c8f33b4 = 0;
static uint64_t OHCI_ED_ve0ae86d823 = 0;
static uint64_t OHCI_TD_vf9ad5698b7 = 0;
static uint64_t OHCI_ISO_TD_va9ca68a2cb = 0;
static uint64_t buffer_vf805d37998 = 0;
static uint64_t buffer_vc666e2bc46 = 0;
static uint64_t buffer_v859f6ccbdd = 0;
static uint64_t buffer_vcfae9f72fd = 0;
static uint64_t buffer_v1b233b6876 = 0;
static uint64_t buffer_v451e33f974 = 0;
static uint64_t buffer_v947f99a4cf = 0;
static uint64_t buffer_vaf3e52b174 = 0;
static uint64_t OHCI_ED_vfad395bd32 = 0;
static uint64_t OHCI_TD_v1f66dbaf30 = 0;
static uint64_t OHCI_ISO_TD_v5fb95bd505 = 0;
static uint64_t buffer_vcf914d86d9 = 0;
static uint64_t buffer_v97518f0275 = 0;
static uint64_t buffer_v5f495d01fa = 0;
static uint64_t buffer_v51800e3269 = 0;
static uint64_t buffer_v5f03757ad2 = 0;
static uint64_t buffer_v27940daa14 = 0;
static uint64_t buffer_v8a9e76e0ae = 0;
static uint64_t buffer_v9c0bc5300e = 0;
static uint64_t OHCI_ED_v444a2c1cf1 = 0;
static uint64_t OHCI_TD_v2b46648c8b = 0;
static uint64_t OHCI_ISO_TD_vcd0c821849 = 0;
static uint64_t buffer_v2968f68dba = 0;
static uint64_t buffer_v69bc21862b = 0;
static uint64_t buffer_v794c3fe6ae = 0;
static uint64_t buffer_ve7200484c8 = 0;
static uint64_t buffer_v3d8cb0e830 = 0;
static uint64_t buffer_v9c28316775 = 0;
static uint64_t buffer_vd0bb3cbf29 = 0;
static uint64_t buffer_v7b8e075cfe = 0;
static uint64_t OHCI_ED_v518a7f151e = 0;
static uint64_t OHCI_TD_v88fb6be7c0 = 0;
static uint64_t OHCI_ISO_TD_v775153a32a = 0;
static uint64_t buffer_v8f2a7695df = 0;
static uint64_t buffer_v3dbb8662a2 = 0;
static uint64_t buffer_v12e844ce65 = 0;
static uint64_t buffer_vd611d9988a = 0;
static uint64_t buffer_v52322488cd = 0;
static uint64_t buffer_vb4066fca2d = 0;
static uint64_t buffer_vdb199d02a9 = 0;
static uint64_t buffer_v99f7987c16 = 0;
static uint64_t OHCI_ED_v7d32b0ec10 = 0;
static uint64_t OHCI_TD_v2abd003c82 = 0;
static uint64_t OHCI_ISO_TD_v9ce15cff68 = 0;
static uint64_t buffer_v11538536aa = 0;
static uint64_t buffer_v83627d99e7 = 0;
static uint64_t buffer_v442df22c12 = 0;
static uint64_t buffer_v880eaff06a = 0;
static uint64_t buffer_ve6a30b2173 = 0;
static uint64_t buffer_ved1ad3b263 = 0;
static uint64_t buffer_vc4d81a2ef7 = 0;
static uint64_t buffer_v4410267314 = 0;

static uint8_t *get_data_1() {
    size_1 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    switch (get_data_from_pool4() % 1){ 
        case 0: goto veb1912cb14_0; break;
    }
veb1912cb14_0:;
    stateful_free(ohci_hcca_0);
    ohci_hcca_0 = stateful_malloc(0x88, /*chained=*/false);
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v46009e1ea9_0; break;
    }
v46009e1ea9_0:;
    stateful_free(OHCI_ED_v81164b7fea);
    OHCI_ED_v81164b7fea = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v488fc975fc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v488fc975fc[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v81164b7fea + 0x0, 0x4, (uint8_t *)v488fc975fc);
    free(v488fc975fc);
    uint32_t *v2ee666979d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2ee666979d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v81164b7fea + 0x4, 0x4, (uint8_t *)v2ee666979d);
    free(v2ee666979d);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto va7f13dac43_0; break;
        case 1: goto va7f13dac43_1; break;
    }
va7f13dac43_0:;
    stateful_free(OHCI_TD_vf231cdc88d);
    OHCI_TD_vf231cdc88d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v49bd15f25d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v49bd15f25d[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf231cdc88d + 0x0, 0x4, (uint8_t *)v49bd15f25d);
    free(v49bd15f25d);
    uint32_t *v731ee2fb10 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v731ee2fb10[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf231cdc88d + 0x4, 0x4, (uint8_t *)v731ee2fb10);
    free(v731ee2fb10);
    uint32_t *v29fe763bf3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v29fe763bf3[i] = (uint32_t)(OHCI_TD_vf231cdc88d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf231cdc88d + 0x8, 0x4, (uint8_t *)v29fe763bf3);
    free(v29fe763bf3);
    uint32_t *vcfa7e99a8a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcfa7e99a8a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf231cdc88d + 0xc, 0x4, (uint8_t *)vcfa7e99a8a);
    free(vcfa7e99a8a);
    uint32_t *v4eefd2f2f8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4eefd2f2f8[i] = (uint32_t)(OHCI_TD_vf231cdc88d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v81164b7fea + 0x8, 0x4, (uint8_t *)v4eefd2f2f8);
    free(v4eefd2f2f8);
    goto va7f13dac43_out;
va7f13dac43_1:;
    stateful_free(OHCI_ISO_TD_v8393b4fa37);
    OHCI_ISO_TD_v8393b4fa37 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *ve69967f4e5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve69967f4e5[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x0, 0x4, (uint8_t *)ve69967f4e5);
    free(ve69967f4e5);
    uint32_t *va40fb9efbd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va40fb9efbd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x4, 0x4, (uint8_t *)va40fb9efbd);
    free(va40fb9efbd);
    uint32_t *v296695bc56 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v296695bc56[i] = (uint32_t)(OHCI_ISO_TD_v8393b4fa37 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x8, 0x4, (uint8_t *)v296695bc56);
    free(v296695bc56);
    uint32_t *vae9e01743d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vae9e01743d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0xc, 0x4, (uint8_t *)vae9e01743d);
    free(vae9e01743d);
    stateful_free(buffer_vd68e208057);
    buffer_vd68e208057 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc585586edd = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc585586edd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd68e208057 + 0x0, 0x100, (uint8_t *)vc585586edd);
    free(vc585586edd);
    uint32_t *v9779d737f6 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9779d737f6[i] = (uint32_t)(buffer_vd68e208057 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x10, 0x2, (uint8_t *)v9779d737f6);
    free(v9779d737f6);
    stateful_free(buffer_v3f28aafeb0);
    buffer_v3f28aafeb0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v465cb8641a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v465cb8641a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3f28aafeb0 + 0x0, 0x100, (uint8_t *)v465cb8641a);
    free(v465cb8641a);
    uint32_t *vc47e4bfba3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc47e4bfba3[i] = (uint32_t)(buffer_v3f28aafeb0 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x12, 0x2, (uint8_t *)vc47e4bfba3);
    free(vc47e4bfba3);
    stateful_free(buffer_veaa162849e);
    buffer_veaa162849e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v883cd70dea = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v883cd70dea[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_veaa162849e + 0x0, 0x100, (uint8_t *)v883cd70dea);
    free(v883cd70dea);
    uint32_t *v41c73839f6 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v41c73839f6[i] = (uint32_t)(buffer_veaa162849e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x14, 0x2, (uint8_t *)v41c73839f6);
    free(v41c73839f6);
    stateful_free(buffer_v458b794c1f);
    buffer_v458b794c1f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4d0ebe8cd1 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4d0ebe8cd1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v458b794c1f + 0x0, 0x100, (uint8_t *)v4d0ebe8cd1);
    free(v4d0ebe8cd1);
    uint32_t *v7007716398 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7007716398[i] = (uint32_t)(buffer_v458b794c1f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x16, 0x2, (uint8_t *)v7007716398);
    free(v7007716398);
    stateful_free(buffer_v98df63c7be);
    buffer_v98df63c7be = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc93446de92 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc93446de92[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v98df63c7be + 0x0, 0x100, (uint8_t *)vc93446de92);
    free(vc93446de92);
    uint32_t *vbf21d04793 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vbf21d04793[i] = (uint32_t)(buffer_v98df63c7be | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x18, 0x2, (uint8_t *)vbf21d04793);
    free(vbf21d04793);
    stateful_free(buffer_vd24a9f270c);
    buffer_vd24a9f270c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vcfdf09d710 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vcfdf09d710[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd24a9f270c + 0x0, 0x100, (uint8_t *)vcfdf09d710);
    free(vcfdf09d710);
    uint32_t *v297ded6caf = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v297ded6caf[i] = (uint32_t)(buffer_vd24a9f270c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x1a, 0x2, (uint8_t *)v297ded6caf);
    free(v297ded6caf);
    stateful_free(buffer_v54dbc26b2f);
    buffer_v54dbc26b2f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va8e63f28d3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va8e63f28d3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v54dbc26b2f + 0x0, 0x100, (uint8_t *)va8e63f28d3);
    free(va8e63f28d3);
    uint32_t *v40d3859d5b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v40d3859d5b[i] = (uint32_t)(buffer_v54dbc26b2f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x1c, 0x2, (uint8_t *)v40d3859d5b);
    free(v40d3859d5b);
    stateful_free(buffer_v3275f545dd);
    buffer_v3275f545dd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v45974a8963 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v45974a8963[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3275f545dd + 0x0, 0x100, (uint8_t *)v45974a8963);
    free(v45974a8963);
    uint32_t *v45f79407b0 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v45f79407b0[i] = (uint32_t)(buffer_v3275f545dd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8393b4fa37 + 0x1e, 0x2, (uint8_t *)v45f79407b0);
    free(v45f79407b0);
    uint32_t *v677a9aa8a5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v677a9aa8a5[i] = (uint32_t)(OHCI_ISO_TD_v8393b4fa37 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v81164b7fea + 0x8, 0x4, (uint8_t *)v677a9aa8a5);
    free(v677a9aa8a5);
    goto va7f13dac43_out;
va7f13dac43_out:;
    uint32_t *v284f464521 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v284f464521[i] = (uint32_t)OHCI_ED_v81164b7fea;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v81164b7fea + 0xc, 0x4, (uint8_t *)v284f464521);
    free(v284f464521);
    uint32_t *v21b26bcf5a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v21b26bcf5a[i] = (uint32_t)OHCI_ED_v81164b7fea;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x0, 0x4, (uint8_t *)v21b26bcf5a);
    free(v21b26bcf5a);
    goto v46009e1ea9_out;
v46009e1ea9_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v433c840426_0; break;
    }
v433c840426_0:;
    stateful_free(OHCI_ED_va879e3af45);
    OHCI_ED_va879e3af45 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v1586b73d6d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1586b73d6d[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va879e3af45 + 0x0, 0x4, (uint8_t *)v1586b73d6d);
    free(v1586b73d6d);
    uint32_t *ve672b66b66 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve672b66b66[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va879e3af45 + 0x4, 0x4, (uint8_t *)ve672b66b66);
    free(ve672b66b66);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v341017f729_0; break;
        case 1: goto v341017f729_1; break;
    }
v341017f729_0:;
    stateful_free(OHCI_TD_v922543458d);
    OHCI_TD_v922543458d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v4b7c04c556 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4b7c04c556[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v922543458d + 0x0, 0x4, (uint8_t *)v4b7c04c556);
    free(v4b7c04c556);
    uint32_t *v82d3172849 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v82d3172849[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v922543458d + 0x4, 0x4, (uint8_t *)v82d3172849);
    free(v82d3172849);
    uint32_t *v85fd761ea4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v85fd761ea4[i] = (uint32_t)(OHCI_TD_v922543458d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v922543458d + 0x8, 0x4, (uint8_t *)v85fd761ea4);
    free(v85fd761ea4);
    uint32_t *ve5dce2ed73 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve5dce2ed73[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v922543458d + 0xc, 0x4, (uint8_t *)ve5dce2ed73);
    free(ve5dce2ed73);
    uint32_t *veea772f287 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        veea772f287[i] = (uint32_t)(OHCI_TD_v922543458d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va879e3af45 + 0x8, 0x4, (uint8_t *)veea772f287);
    free(veea772f287);
    goto v341017f729_out;
v341017f729_1:;
    stateful_free(OHCI_ISO_TD_vdb92104708);
    OHCI_ISO_TD_vdb92104708 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vd71d18025a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd71d18025a[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x0, 0x4, (uint8_t *)vd71d18025a);
    free(vd71d18025a);
    uint32_t *v2962534bb5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2962534bb5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x4, 0x4, (uint8_t *)v2962534bb5);
    free(v2962534bb5);
    uint32_t *v146c086dcd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v146c086dcd[i] = (uint32_t)(OHCI_ISO_TD_vdb92104708 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x8, 0x4, (uint8_t *)v146c086dcd);
    free(v146c086dcd);
    uint32_t *v13d99c2b37 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v13d99c2b37[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0xc, 0x4, (uint8_t *)v13d99c2b37);
    free(v13d99c2b37);
    stateful_free(buffer_v9baeac771f);
    buffer_v9baeac771f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc237e23b05 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc237e23b05[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9baeac771f + 0x0, 0x100, (uint8_t *)vc237e23b05);
    free(vc237e23b05);
    uint32_t *v8f8f999ac7 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8f8f999ac7[i] = (uint32_t)(buffer_v9baeac771f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x10, 0x2, (uint8_t *)v8f8f999ac7);
    free(v8f8f999ac7);
    stateful_free(buffer_ve40371275c);
    buffer_ve40371275c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3ecf90a2b3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3ecf90a2b3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve40371275c + 0x0, 0x100, (uint8_t *)v3ecf90a2b3);
    free(v3ecf90a2b3);
    uint32_t *va26e1eb3ae = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va26e1eb3ae[i] = (uint32_t)(buffer_ve40371275c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x12, 0x2, (uint8_t *)va26e1eb3ae);
    free(va26e1eb3ae);
    stateful_free(buffer_va5486e299d);
    buffer_va5486e299d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v14e5c6b835 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v14e5c6b835[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va5486e299d + 0x0, 0x100, (uint8_t *)v14e5c6b835);
    free(v14e5c6b835);
    uint32_t *v3ca139af4f = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v3ca139af4f[i] = (uint32_t)(buffer_va5486e299d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x14, 0x2, (uint8_t *)v3ca139af4f);
    free(v3ca139af4f);
    stateful_free(buffer_vb99810954e);
    buffer_vb99810954e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4d23b8d395 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4d23b8d395[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb99810954e + 0x0, 0x100, (uint8_t *)v4d23b8d395);
    free(v4d23b8d395);
    uint32_t *va7229b9f37 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va7229b9f37[i] = (uint32_t)(buffer_vb99810954e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x16, 0x2, (uint8_t *)va7229b9f37);
    free(va7229b9f37);
    stateful_free(buffer_vb044254cc5);
    buffer_vb044254cc5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2c10cbda10 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2c10cbda10[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb044254cc5 + 0x0, 0x100, (uint8_t *)v2c10cbda10);
    free(v2c10cbda10);
    uint32_t *v56c1cecb12 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v56c1cecb12[i] = (uint32_t)(buffer_vb044254cc5 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x18, 0x2, (uint8_t *)v56c1cecb12);
    free(v56c1cecb12);
    stateful_free(buffer_v11a8638f35);
    buffer_v11a8638f35 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6b6c18f174 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6b6c18f174[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v11a8638f35 + 0x0, 0x100, (uint8_t *)v6b6c18f174);
    free(v6b6c18f174);
    uint32_t *v2330827949 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v2330827949[i] = (uint32_t)(buffer_v11a8638f35 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x1a, 0x2, (uint8_t *)v2330827949);
    free(v2330827949);
    stateful_free(buffer_vcc1ca0e6eb);
    buffer_vcc1ca0e6eb = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2b8cc5f149 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2b8cc5f149[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vcc1ca0e6eb + 0x0, 0x100, (uint8_t *)v2b8cc5f149);
    free(v2b8cc5f149);
    uint32_t *v8ea11d43d8 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8ea11d43d8[i] = (uint32_t)(buffer_vcc1ca0e6eb | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x1c, 0x2, (uint8_t *)v8ea11d43d8);
    free(v8ea11d43d8);
    stateful_free(buffer_v77f439caba);
    buffer_v77f439caba = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vced855081e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vced855081e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v77f439caba + 0x0, 0x100, (uint8_t *)vced855081e);
    free(vced855081e);
    uint32_t *v882a3eb7ae = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v882a3eb7ae[i] = (uint32_t)(buffer_v77f439caba | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdb92104708 + 0x1e, 0x2, (uint8_t *)v882a3eb7ae);
    free(v882a3eb7ae);
    uint32_t *v1b4e13c991 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1b4e13c991[i] = (uint32_t)(OHCI_ISO_TD_vdb92104708 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va879e3af45 + 0x8, 0x4, (uint8_t *)v1b4e13c991);
    free(v1b4e13c991);
    goto v341017f729_out;
v341017f729_out:;
    uint32_t *v23fe483d8e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v23fe483d8e[i] = (uint32_t)OHCI_ED_va879e3af45;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va879e3af45 + 0xc, 0x4, (uint8_t *)v23fe483d8e);
    free(v23fe483d8e);
    uint32_t *vea7f3847d4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vea7f3847d4[i] = (uint32_t)OHCI_ED_va879e3af45;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x4, 0x4, (uint8_t *)vea7f3847d4);
    free(vea7f3847d4);
    goto v433c840426_out;
v433c840426_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v4f81d9a289_0; break;
    }
v4f81d9a289_0:;
    stateful_free(OHCI_ED_v32c8c47c4b);
    OHCI_ED_v32c8c47c4b = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v5deedaf324 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5deedaf324[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v32c8c47c4b + 0x0, 0x4, (uint8_t *)v5deedaf324);
    free(v5deedaf324);
    uint32_t *v7c4e857ee2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7c4e857ee2[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v32c8c47c4b + 0x4, 0x4, (uint8_t *)v7c4e857ee2);
    free(v7c4e857ee2);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v166d67a41a_0; break;
        case 1: goto v166d67a41a_1; break;
    }
v166d67a41a_0:;
    stateful_free(OHCI_TD_v7232ea3c7f);
    OHCI_TD_v7232ea3c7f = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v6f611209a2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6f611209a2[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7232ea3c7f + 0x0, 0x4, (uint8_t *)v6f611209a2);
    free(v6f611209a2);
    uint32_t *v4ad6570abb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4ad6570abb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7232ea3c7f + 0x4, 0x4, (uint8_t *)v4ad6570abb);
    free(v4ad6570abb);
    uint32_t *ve8f0bf17e6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve8f0bf17e6[i] = (uint32_t)(OHCI_TD_v7232ea3c7f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7232ea3c7f + 0x8, 0x4, (uint8_t *)ve8f0bf17e6);
    free(ve8f0bf17e6);
    uint32_t *v206527c340 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v206527c340[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7232ea3c7f + 0xc, 0x4, (uint8_t *)v206527c340);
    free(v206527c340);
    uint32_t *v144a044a4d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v144a044a4d[i] = (uint32_t)(OHCI_TD_v7232ea3c7f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v32c8c47c4b + 0x8, 0x4, (uint8_t *)v144a044a4d);
    free(v144a044a4d);
    goto v166d67a41a_out;
v166d67a41a_1:;
    stateful_free(OHCI_ISO_TD_vee366973a0);
    OHCI_ISO_TD_vee366973a0 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v21bf729c44 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v21bf729c44[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x0, 0x4, (uint8_t *)v21bf729c44);
    free(v21bf729c44);
    uint32_t *v31320e95a0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v31320e95a0[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x4, 0x4, (uint8_t *)v31320e95a0);
    free(v31320e95a0);
    uint32_t *v322ce3b525 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v322ce3b525[i] = (uint32_t)(OHCI_ISO_TD_vee366973a0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x8, 0x4, (uint8_t *)v322ce3b525);
    free(v322ce3b525);
    uint32_t *v7f91d000b9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7f91d000b9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0xc, 0x4, (uint8_t *)v7f91d000b9);
    free(v7f91d000b9);
    stateful_free(buffer_vf5c6b47b25);
    buffer_vf5c6b47b25 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v55639951ae = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v55639951ae[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf5c6b47b25 + 0x0, 0x100, (uint8_t *)v55639951ae);
    free(v55639951ae);
    uint32_t *v7942d91140 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7942d91140[i] = (uint32_t)(buffer_vf5c6b47b25 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x10, 0x2, (uint8_t *)v7942d91140);
    free(v7942d91140);
    stateful_free(buffer_v3129285d9f);
    buffer_v3129285d9f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd517638119 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd517638119[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3129285d9f + 0x0, 0x100, (uint8_t *)vd517638119);
    free(vd517638119);
    uint32_t *v9cb241f40e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9cb241f40e[i] = (uint32_t)(buffer_v3129285d9f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x12, 0x2, (uint8_t *)v9cb241f40e);
    free(v9cb241f40e);
    stateful_free(buffer_v399e7f8d28);
    buffer_v399e7f8d28 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v735714673f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v735714673f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v399e7f8d28 + 0x0, 0x100, (uint8_t *)v735714673f);
    free(v735714673f);
    uint32_t *v59a372dbbd = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v59a372dbbd[i] = (uint32_t)(buffer_v399e7f8d28 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x14, 0x2, (uint8_t *)v59a372dbbd);
    free(v59a372dbbd);
    stateful_free(buffer_vc37a92f9c8);
    buffer_vc37a92f9c8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2c6fbca797 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2c6fbca797[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc37a92f9c8 + 0x0, 0x100, (uint8_t *)v2c6fbca797);
    free(v2c6fbca797);
    uint32_t *v7b9f77bc7a = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7b9f77bc7a[i] = (uint32_t)(buffer_vc37a92f9c8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x16, 0x2, (uint8_t *)v7b9f77bc7a);
    free(v7b9f77bc7a);
    stateful_free(buffer_v8094b305ff);
    buffer_v8094b305ff = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7c294e7f10 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7c294e7f10[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8094b305ff + 0x0, 0x100, (uint8_t *)v7c294e7f10);
    free(v7c294e7f10);
    uint32_t *v9bcffa4ebd = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9bcffa4ebd[i] = (uint32_t)(buffer_v8094b305ff | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x18, 0x2, (uint8_t *)v9bcffa4ebd);
    free(v9bcffa4ebd);
    stateful_free(buffer_ve058428f59);
    buffer_ve058428f59 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v93ba227cdb = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v93ba227cdb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve058428f59 + 0x0, 0x100, (uint8_t *)v93ba227cdb);
    free(v93ba227cdb);
    uint32_t *v1b69c71919 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1b69c71919[i] = (uint32_t)(buffer_ve058428f59 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x1a, 0x2, (uint8_t *)v1b69c71919);
    free(v1b69c71919);
    stateful_free(buffer_vd4d2dde429);
    buffer_vd4d2dde429 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4727a69359 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4727a69359[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd4d2dde429 + 0x0, 0x100, (uint8_t *)v4727a69359);
    free(v4727a69359);
    uint32_t *v598f7cc631 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v598f7cc631[i] = (uint32_t)(buffer_vd4d2dde429 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x1c, 0x2, (uint8_t *)v598f7cc631);
    free(v598f7cc631);
    stateful_free(buffer_v77958220b8);
    buffer_v77958220b8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve3ef3edac5 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve3ef3edac5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v77958220b8 + 0x0, 0x100, (uint8_t *)ve3ef3edac5);
    free(ve3ef3edac5);
    uint32_t *v37c7fbb243 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v37c7fbb243[i] = (uint32_t)(buffer_v77958220b8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vee366973a0 + 0x1e, 0x2, (uint8_t *)v37c7fbb243);
    free(v37c7fbb243);
    uint32_t *vf35c5e74c3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf35c5e74c3[i] = (uint32_t)(OHCI_ISO_TD_vee366973a0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v32c8c47c4b + 0x8, 0x4, (uint8_t *)vf35c5e74c3);
    free(vf35c5e74c3);
    goto v166d67a41a_out;
v166d67a41a_out:;
    uint32_t *vafd15a4220 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vafd15a4220[i] = (uint32_t)OHCI_ED_v32c8c47c4b;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v32c8c47c4b + 0xc, 0x4, (uint8_t *)vafd15a4220);
    free(vafd15a4220);
    uint32_t *v51918eabe4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v51918eabe4[i] = (uint32_t)OHCI_ED_v32c8c47c4b;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x8, 0x4, (uint8_t *)v51918eabe4);
    free(v51918eabe4);
    goto v4f81d9a289_out;
v4f81d9a289_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vfb53b0227a_0; break;
    }
vfb53b0227a_0:;
    stateful_free(OHCI_ED_v78e7558907);
    OHCI_ED_v78e7558907 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v92e61dd686 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v92e61dd686[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v78e7558907 + 0x0, 0x4, (uint8_t *)v92e61dd686);
    free(v92e61dd686);
    uint32_t *vd5b6564028 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd5b6564028[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v78e7558907 + 0x4, 0x4, (uint8_t *)vd5b6564028);
    free(vd5b6564028);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v89c6b5365e_0; break;
        case 1: goto v89c6b5365e_1; break;
    }
v89c6b5365e_0:;
    stateful_free(OHCI_TD_v629ecec2b7);
    OHCI_TD_v629ecec2b7 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vd92b616acb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd92b616acb[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v629ecec2b7 + 0x0, 0x4, (uint8_t *)vd92b616acb);
    free(vd92b616acb);
    uint32_t *vce42718bae = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vce42718bae[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v629ecec2b7 + 0x4, 0x4, (uint8_t *)vce42718bae);
    free(vce42718bae);
    uint32_t *vf2b13caf32 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf2b13caf32[i] = (uint32_t)(OHCI_TD_v629ecec2b7 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v629ecec2b7 + 0x8, 0x4, (uint8_t *)vf2b13caf32);
    free(vf2b13caf32);
    uint32_t *vb4d01fa8dd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb4d01fa8dd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v629ecec2b7 + 0xc, 0x4, (uint8_t *)vb4d01fa8dd);
    free(vb4d01fa8dd);
    uint32_t *v7f9826d8d8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7f9826d8d8[i] = (uint32_t)(OHCI_TD_v629ecec2b7 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v78e7558907 + 0x8, 0x4, (uint8_t *)v7f9826d8d8);
    free(v7f9826d8d8);
    goto v89c6b5365e_out;
v89c6b5365e_1:;
    stateful_free(OHCI_ISO_TD_vf06a200357);
    OHCI_ISO_TD_vf06a200357 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *va142df2d93 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va142df2d93[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x0, 0x4, (uint8_t *)va142df2d93);
    free(va142df2d93);
    uint32_t *vf208f9f0d3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf208f9f0d3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x4, 0x4, (uint8_t *)vf208f9f0d3);
    free(vf208f9f0d3);
    uint32_t *v6179f39912 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6179f39912[i] = (uint32_t)(OHCI_ISO_TD_vf06a200357 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x8, 0x4, (uint8_t *)v6179f39912);
    free(v6179f39912);
    uint32_t *vb35a2a549e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb35a2a549e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0xc, 0x4, (uint8_t *)vb35a2a549e);
    free(vb35a2a549e);
    stateful_free(buffer_v86824d223a);
    buffer_v86824d223a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve77fd876a1 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve77fd876a1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v86824d223a + 0x0, 0x100, (uint8_t *)ve77fd876a1);
    free(ve77fd876a1);
    uint32_t *v2709f1b9b3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v2709f1b9b3[i] = (uint32_t)(buffer_v86824d223a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x10, 0x2, (uint8_t *)v2709f1b9b3);
    free(v2709f1b9b3);
    stateful_free(buffer_v585420547d);
    buffer_v585420547d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve218266604 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve218266604[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v585420547d + 0x0, 0x100, (uint8_t *)ve218266604);
    free(ve218266604);
    uint32_t *v459309cd52 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v459309cd52[i] = (uint32_t)(buffer_v585420547d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x12, 0x2, (uint8_t *)v459309cd52);
    free(v459309cd52);
    stateful_free(buffer_v38a8dd4906);
    buffer_v38a8dd4906 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vff18b2312c = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vff18b2312c[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v38a8dd4906 + 0x0, 0x100, (uint8_t *)vff18b2312c);
    free(vff18b2312c);
    uint32_t *v61abb66b5c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v61abb66b5c[i] = (uint32_t)(buffer_v38a8dd4906 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x14, 0x2, (uint8_t *)v61abb66b5c);
    free(v61abb66b5c);
    stateful_free(buffer_v6bc9d9297e);
    buffer_v6bc9d9297e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2ca72e53a3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2ca72e53a3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6bc9d9297e + 0x0, 0x100, (uint8_t *)v2ca72e53a3);
    free(v2ca72e53a3);
    uint32_t *v4138e95c58 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4138e95c58[i] = (uint32_t)(buffer_v6bc9d9297e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x16, 0x2, (uint8_t *)v4138e95c58);
    free(v4138e95c58);
    stateful_free(buffer_v4423986e7f);
    buffer_v4423986e7f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9f47dba25a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9f47dba25a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v4423986e7f + 0x0, 0x100, (uint8_t *)v9f47dba25a);
    free(v9f47dba25a);
    uint32_t *v3b7f0f3084 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v3b7f0f3084[i] = (uint32_t)(buffer_v4423986e7f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x18, 0x2, (uint8_t *)v3b7f0f3084);
    free(v3b7f0f3084);
    stateful_free(buffer_vdd00a54fca);
    buffer_vdd00a54fca = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v671909b7df = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v671909b7df[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdd00a54fca + 0x0, 0x100, (uint8_t *)v671909b7df);
    free(v671909b7df);
    uint32_t *v4af6ce769b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4af6ce769b[i] = (uint32_t)(buffer_vdd00a54fca | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x1a, 0x2, (uint8_t *)v4af6ce769b);
    free(v4af6ce769b);
    stateful_free(buffer_v1c63d43713);
    buffer_v1c63d43713 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v102588c4d6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v102588c4d6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v1c63d43713 + 0x0, 0x100, (uint8_t *)v102588c4d6);
    free(v102588c4d6);
    uint32_t *v43434d5203 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v43434d5203[i] = (uint32_t)(buffer_v1c63d43713 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x1c, 0x2, (uint8_t *)v43434d5203);
    free(v43434d5203);
    stateful_free(buffer_v9d35e92dfb);
    buffer_v9d35e92dfb = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve738e2d236 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve738e2d236[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9d35e92dfb + 0x0, 0x100, (uint8_t *)ve738e2d236);
    free(ve738e2d236);
    uint32_t *va14fb02ec4 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va14fb02ec4[i] = (uint32_t)(buffer_v9d35e92dfb | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf06a200357 + 0x1e, 0x2, (uint8_t *)va14fb02ec4);
    free(va14fb02ec4);
    uint32_t *va9163318a7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va9163318a7[i] = (uint32_t)(OHCI_ISO_TD_vf06a200357 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v78e7558907 + 0x8, 0x4, (uint8_t *)va9163318a7);
    free(va9163318a7);
    goto v89c6b5365e_out;
v89c6b5365e_out:;
    uint32_t *v95886d4e72 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v95886d4e72[i] = (uint32_t)OHCI_ED_v78e7558907;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v78e7558907 + 0xc, 0x4, (uint8_t *)v95886d4e72);
    free(v95886d4e72);
    uint32_t *v5f8a29dd92 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5f8a29dd92[i] = (uint32_t)OHCI_ED_v78e7558907;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0xc, 0x4, (uint8_t *)v5f8a29dd92);
    free(v5f8a29dd92);
    goto vfb53b0227a_out;
vfb53b0227a_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v4c3382969c_0; break;
    }
v4c3382969c_0:;
    stateful_free(OHCI_ED_v1285dad4a2);
    OHCI_ED_v1285dad4a2 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *ve7e962baca = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve7e962baca[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1285dad4a2 + 0x0, 0x4, (uint8_t *)ve7e962baca);
    free(ve7e962baca);
    uint32_t *v46ad97a8d3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v46ad97a8d3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1285dad4a2 + 0x4, 0x4, (uint8_t *)v46ad97a8d3);
    free(v46ad97a8d3);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto va8bc38daaf_0; break;
        case 1: goto va8bc38daaf_1; break;
    }
va8bc38daaf_0:;
    stateful_free(OHCI_TD_vebff96ae49);
    OHCI_TD_vebff96ae49 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v267554d24b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v267554d24b[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebff96ae49 + 0x0, 0x4, (uint8_t *)v267554d24b);
    free(v267554d24b);
    uint32_t *v451ff2f785 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v451ff2f785[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebff96ae49 + 0x4, 0x4, (uint8_t *)v451ff2f785);
    free(v451ff2f785);
    uint32_t *vbbf3d404ac = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbbf3d404ac[i] = (uint32_t)(OHCI_TD_vebff96ae49 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebff96ae49 + 0x8, 0x4, (uint8_t *)vbbf3d404ac);
    free(vbbf3d404ac);
    uint32_t *vdbcba548a0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdbcba548a0[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebff96ae49 + 0xc, 0x4, (uint8_t *)vdbcba548a0);
    free(vdbcba548a0);
    uint32_t *vc02531c8b6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc02531c8b6[i] = (uint32_t)(OHCI_TD_vebff96ae49 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1285dad4a2 + 0x8, 0x4, (uint8_t *)vc02531c8b6);
    free(vc02531c8b6);
    goto va8bc38daaf_out;
va8bc38daaf_1:;
    stateful_free(OHCI_ISO_TD_v8232aac463);
    OHCI_ISO_TD_v8232aac463 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v50796545a4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v50796545a4[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x0, 0x4, (uint8_t *)v50796545a4);
    free(v50796545a4);
    uint32_t *v30be72933d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v30be72933d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x4, 0x4, (uint8_t *)v30be72933d);
    free(v30be72933d);
    uint32_t *v81a0eb1452 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v81a0eb1452[i] = (uint32_t)(OHCI_ISO_TD_v8232aac463 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x8, 0x4, (uint8_t *)v81a0eb1452);
    free(v81a0eb1452);
    uint32_t *ve902e1532b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve902e1532b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0xc, 0x4, (uint8_t *)ve902e1532b);
    free(ve902e1532b);
    stateful_free(buffer_v6a3654d69f);
    buffer_v6a3654d69f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v907aaaf8e7 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v907aaaf8e7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6a3654d69f + 0x0, 0x100, (uint8_t *)v907aaaf8e7);
    free(v907aaaf8e7);
    uint32_t *ve9e951ce54 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        ve9e951ce54[i] = (uint32_t)(buffer_v6a3654d69f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x10, 0x2, (uint8_t *)ve9e951ce54);
    free(ve9e951ce54);
    stateful_free(buffer_vbc4e29bedb);
    buffer_vbc4e29bedb = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v36f612b9b7 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v36f612b9b7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vbc4e29bedb + 0x0, 0x100, (uint8_t *)v36f612b9b7);
    free(v36f612b9b7);
    uint32_t *v5f50eb00b2 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5f50eb00b2[i] = (uint32_t)(buffer_vbc4e29bedb | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x12, 0x2, (uint8_t *)v5f50eb00b2);
    free(v5f50eb00b2);
    stateful_free(buffer_vc120119ade);
    buffer_vc120119ade = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vea3d3f82be = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vea3d3f82be[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc120119ade + 0x0, 0x100, (uint8_t *)vea3d3f82be);
    free(vea3d3f82be);
    uint32_t *v94b809455d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v94b809455d[i] = (uint32_t)(buffer_vc120119ade | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x14, 0x2, (uint8_t *)v94b809455d);
    free(v94b809455d);
    stateful_free(buffer_v6b7af89b80);
    buffer_v6b7af89b80 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v863f77c5e6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v863f77c5e6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6b7af89b80 + 0x0, 0x100, (uint8_t *)v863f77c5e6);
    free(v863f77c5e6);
    uint32_t *v4091c7751c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4091c7751c[i] = (uint32_t)(buffer_v6b7af89b80 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x16, 0x2, (uint8_t *)v4091c7751c);
    free(v4091c7751c);
    stateful_free(buffer_v5add0781e9);
    buffer_v5add0781e9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7ec77d3787 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7ec77d3787[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5add0781e9 + 0x0, 0x100, (uint8_t *)v7ec77d3787);
    free(v7ec77d3787);
    uint32_t *v622a707601 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v622a707601[i] = (uint32_t)(buffer_v5add0781e9 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x18, 0x2, (uint8_t *)v622a707601);
    free(v622a707601);
    stateful_free(buffer_vdea57e43a8);
    buffer_vdea57e43a8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v624d1e9dd9 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v624d1e9dd9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdea57e43a8 + 0x0, 0x100, (uint8_t *)v624d1e9dd9);
    free(v624d1e9dd9);
    uint32_t *v67e31847dc = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v67e31847dc[i] = (uint32_t)(buffer_vdea57e43a8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x1a, 0x2, (uint8_t *)v67e31847dc);
    free(v67e31847dc);
    stateful_free(buffer_v748e85dac8);
    buffer_v748e85dac8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v484f7c16a0 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v484f7c16a0[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v748e85dac8 + 0x0, 0x100, (uint8_t *)v484f7c16a0);
    free(v484f7c16a0);
    uint32_t *va339fe0f18 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va339fe0f18[i] = (uint32_t)(buffer_v748e85dac8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x1c, 0x2, (uint8_t *)va339fe0f18);
    free(va339fe0f18);
    stateful_free(buffer_v883225308d);
    buffer_v883225308d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5c350a3325 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5c350a3325[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v883225308d + 0x0, 0x100, (uint8_t *)v5c350a3325);
    free(v5c350a3325);
    uint32_t *v4a3e067d48 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4a3e067d48[i] = (uint32_t)(buffer_v883225308d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8232aac463 + 0x1e, 0x2, (uint8_t *)v4a3e067d48);
    free(v4a3e067d48);
    uint32_t *v7696da00ba = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7696da00ba[i] = (uint32_t)(OHCI_ISO_TD_v8232aac463 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1285dad4a2 + 0x8, 0x4, (uint8_t *)v7696da00ba);
    free(v7696da00ba);
    goto va8bc38daaf_out;
va8bc38daaf_out:;
    uint32_t *v2507e70033 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2507e70033[i] = (uint32_t)OHCI_ED_v1285dad4a2;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1285dad4a2 + 0xc, 0x4, (uint8_t *)v2507e70033);
    free(v2507e70033);
    uint32_t *va38eb6c150 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va38eb6c150[i] = (uint32_t)OHCI_ED_v1285dad4a2;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x10, 0x4, (uint8_t *)va38eb6c150);
    free(va38eb6c150);
    goto v4c3382969c_out;
v4c3382969c_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vfdaef396a9_0; break;
    }
vfdaef396a9_0:;
    stateful_free(OHCI_ED_v68d1108293);
    OHCI_ED_v68d1108293 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v935e41a019 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v935e41a019[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v68d1108293 + 0x0, 0x4, (uint8_t *)v935e41a019);
    free(v935e41a019);
    uint32_t *v88cfc9379a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v88cfc9379a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v68d1108293 + 0x4, 0x4, (uint8_t *)v88cfc9379a);
    free(v88cfc9379a);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v7ca996133f_0; break;
        case 1: goto v7ca996133f_1; break;
    }
v7ca996133f_0:;
    stateful_free(OHCI_TD_v29072580c5);
    OHCI_TD_v29072580c5 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *ve143733bfb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve143733bfb[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v29072580c5 + 0x0, 0x4, (uint8_t *)ve143733bfb);
    free(ve143733bfb);
    uint32_t *v3c82e2e798 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3c82e2e798[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v29072580c5 + 0x4, 0x4, (uint8_t *)v3c82e2e798);
    free(v3c82e2e798);
    uint32_t *v8f50671f6e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8f50671f6e[i] = (uint32_t)(OHCI_TD_v29072580c5 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v29072580c5 + 0x8, 0x4, (uint8_t *)v8f50671f6e);
    free(v8f50671f6e);
    uint32_t *vb3e5dc9a93 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb3e5dc9a93[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v29072580c5 + 0xc, 0x4, (uint8_t *)vb3e5dc9a93);
    free(vb3e5dc9a93);
    uint32_t *v310473728b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v310473728b[i] = (uint32_t)(OHCI_TD_v29072580c5 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v68d1108293 + 0x8, 0x4, (uint8_t *)v310473728b);
    free(v310473728b);
    goto v7ca996133f_out;
v7ca996133f_1:;
    stateful_free(OHCI_ISO_TD_v7f6cc61337);
    OHCI_ISO_TD_v7f6cc61337 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v737440f075 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v737440f075[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x0, 0x4, (uint8_t *)v737440f075);
    free(v737440f075);
    uint32_t *v96fc5208ba = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v96fc5208ba[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x4, 0x4, (uint8_t *)v96fc5208ba);
    free(v96fc5208ba);
    uint32_t *v7b1a192e1e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7b1a192e1e[i] = (uint32_t)(OHCI_ISO_TD_v7f6cc61337 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x8, 0x4, (uint8_t *)v7b1a192e1e);
    free(v7b1a192e1e);
    uint32_t *v6c453bd8fc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6c453bd8fc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0xc, 0x4, (uint8_t *)v6c453bd8fc);
    free(v6c453bd8fc);
    stateful_free(buffer_vf8531b7011);
    buffer_vf8531b7011 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve7b7639247 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve7b7639247[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf8531b7011 + 0x0, 0x100, (uint8_t *)ve7b7639247);
    free(ve7b7639247);
    uint32_t *v2b901ba777 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v2b901ba777[i] = (uint32_t)(buffer_vf8531b7011 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x10, 0x2, (uint8_t *)v2b901ba777);
    free(v2b901ba777);
    stateful_free(buffer_ve067f760b7);
    buffer_ve067f760b7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9aaeeebfc5 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9aaeeebfc5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve067f760b7 + 0x0, 0x100, (uint8_t *)v9aaeeebfc5);
    free(v9aaeeebfc5);
    uint32_t *v4f4e577d4c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4f4e577d4c[i] = (uint32_t)(buffer_ve067f760b7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x12, 0x2, (uint8_t *)v4f4e577d4c);
    free(v4f4e577d4c);
    stateful_free(buffer_v6a53410a2f);
    buffer_v6a53410a2f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v35aa623593 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v35aa623593[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6a53410a2f + 0x0, 0x100, (uint8_t *)v35aa623593);
    free(v35aa623593);
    uint32_t *v6b35362cdf = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6b35362cdf[i] = (uint32_t)(buffer_v6a53410a2f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x14, 0x2, (uint8_t *)v6b35362cdf);
    free(v6b35362cdf);
    stateful_free(buffer_v34058be64c);
    buffer_v34058be64c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb4c0a6036e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb4c0a6036e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v34058be64c + 0x0, 0x100, (uint8_t *)vb4c0a6036e);
    free(vb4c0a6036e);
    uint32_t *ve429ff6502 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        ve429ff6502[i] = (uint32_t)(buffer_v34058be64c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x16, 0x2, (uint8_t *)ve429ff6502);
    free(ve429ff6502);
    stateful_free(buffer_vef72b1bd42);
    buffer_vef72b1bd42 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc1a3c873a3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc1a3c873a3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vef72b1bd42 + 0x0, 0x100, (uint8_t *)vc1a3c873a3);
    free(vc1a3c873a3);
    uint32_t *v13f1dec87d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v13f1dec87d[i] = (uint32_t)(buffer_vef72b1bd42 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x18, 0x2, (uint8_t *)v13f1dec87d);
    free(v13f1dec87d);
    stateful_free(buffer_vca2a9e5b2f);
    buffer_vca2a9e5b2f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1d041bc4dd = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1d041bc4dd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vca2a9e5b2f + 0x0, 0x100, (uint8_t *)v1d041bc4dd);
    free(v1d041bc4dd);
    uint32_t *v38a0297e19 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v38a0297e19[i] = (uint32_t)(buffer_vca2a9e5b2f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x1a, 0x2, (uint8_t *)v38a0297e19);
    free(v38a0297e19);
    stateful_free(buffer_v5e0a9aea92);
    buffer_v5e0a9aea92 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb176a70d66 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb176a70d66[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5e0a9aea92 + 0x0, 0x100, (uint8_t *)vb176a70d66);
    free(vb176a70d66);
    uint32_t *v6b94029dc0 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6b94029dc0[i] = (uint32_t)(buffer_v5e0a9aea92 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x1c, 0x2, (uint8_t *)v6b94029dc0);
    free(v6b94029dc0);
    stateful_free(buffer_v805a2002b0);
    buffer_v805a2002b0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5aca220fad = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5aca220fad[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v805a2002b0 + 0x0, 0x100, (uint8_t *)v5aca220fad);
    free(v5aca220fad);
    uint32_t *vc3d45a1794 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc3d45a1794[i] = (uint32_t)(buffer_v805a2002b0 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7f6cc61337 + 0x1e, 0x2, (uint8_t *)vc3d45a1794);
    free(vc3d45a1794);
    uint32_t *v97e9416e04 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v97e9416e04[i] = (uint32_t)(OHCI_ISO_TD_v7f6cc61337 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v68d1108293 + 0x8, 0x4, (uint8_t *)v97e9416e04);
    free(v97e9416e04);
    goto v7ca996133f_out;
v7ca996133f_out:;
    uint32_t *v59ac3253f8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v59ac3253f8[i] = (uint32_t)OHCI_ED_v68d1108293;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v68d1108293 + 0xc, 0x4, (uint8_t *)v59ac3253f8);
    free(v59ac3253f8);
    uint32_t *v5735a60c78 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5735a60c78[i] = (uint32_t)OHCI_ED_v68d1108293;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x14, 0x4, (uint8_t *)v5735a60c78);
    free(v5735a60c78);
    goto vfdaef396a9_out;
vfdaef396a9_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v56e6f4fdda_0; break;
    }
v56e6f4fdda_0:;
    stateful_free(OHCI_ED_vcb9e45204e);
    OHCI_ED_vcb9e45204e = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vfefa88d5b8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfefa88d5b8[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vcb9e45204e + 0x0, 0x4, (uint8_t *)vfefa88d5b8);
    free(vfefa88d5b8);
    uint32_t *v1933b2bd90 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1933b2bd90[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vcb9e45204e + 0x4, 0x4, (uint8_t *)v1933b2bd90);
    free(v1933b2bd90);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vf906c21acd_0; break;
        case 1: goto vf906c21acd_1; break;
    }
vf906c21acd_0:;
    stateful_free(OHCI_TD_va959efa3c0);
    OHCI_TD_va959efa3c0 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v9182f1bc64 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9182f1bc64[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va959efa3c0 + 0x0, 0x4, (uint8_t *)v9182f1bc64);
    free(v9182f1bc64);
    uint32_t *v9c44b8df28 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9c44b8df28[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va959efa3c0 + 0x4, 0x4, (uint8_t *)v9c44b8df28);
    free(v9c44b8df28);
    uint32_t *v639335b574 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v639335b574[i] = (uint32_t)(OHCI_TD_va959efa3c0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va959efa3c0 + 0x8, 0x4, (uint8_t *)v639335b574);
    free(v639335b574);
    uint32_t *vf10cdb37aa = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf10cdb37aa[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va959efa3c0 + 0xc, 0x4, (uint8_t *)vf10cdb37aa);
    free(vf10cdb37aa);
    uint32_t *v78f3d91324 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v78f3d91324[i] = (uint32_t)(OHCI_TD_va959efa3c0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vcb9e45204e + 0x8, 0x4, (uint8_t *)v78f3d91324);
    free(v78f3d91324);
    goto vf906c21acd_out;
vf906c21acd_1:;
    stateful_free(OHCI_ISO_TD_vbf1f52814a);
    OHCI_ISO_TD_vbf1f52814a = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v31e3ce7d57 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v31e3ce7d57[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x0, 0x4, (uint8_t *)v31e3ce7d57);
    free(v31e3ce7d57);
    uint32_t *v8b117e706a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8b117e706a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x4, 0x4, (uint8_t *)v8b117e706a);
    free(v8b117e706a);
    uint32_t *va8347a933a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va8347a933a[i] = (uint32_t)(OHCI_ISO_TD_vbf1f52814a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x8, 0x4, (uint8_t *)va8347a933a);
    free(va8347a933a);
    uint32_t *v53e2c916f2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v53e2c916f2[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0xc, 0x4, (uint8_t *)v53e2c916f2);
    free(v53e2c916f2);
    stateful_free(buffer_v8b5def445a);
    buffer_v8b5def445a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6d03cad02b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6d03cad02b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8b5def445a + 0x0, 0x100, (uint8_t *)v6d03cad02b);
    free(v6d03cad02b);
    uint32_t *v5f5d2035d8 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5f5d2035d8[i] = (uint32_t)(buffer_v8b5def445a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x10, 0x2, (uint8_t *)v5f5d2035d8);
    free(v5f5d2035d8);
    stateful_free(buffer_v69c2a446fe);
    buffer_v69c2a446fe = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v365002ee7c = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v365002ee7c[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v69c2a446fe + 0x0, 0x100, (uint8_t *)v365002ee7c);
    free(v365002ee7c);
    uint32_t *vb1e14f1721 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb1e14f1721[i] = (uint32_t)(buffer_v69c2a446fe | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x12, 0x2, (uint8_t *)vb1e14f1721);
    free(vb1e14f1721);
    stateful_free(buffer_va81bbff362);
    buffer_va81bbff362 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v161aa4b818 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v161aa4b818[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va81bbff362 + 0x0, 0x100, (uint8_t *)v161aa4b818);
    free(v161aa4b818);
    uint32_t *v249d02942c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v249d02942c[i] = (uint32_t)(buffer_va81bbff362 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x14, 0x2, (uint8_t *)v249d02942c);
    free(v249d02942c);
    stateful_free(buffer_vebbe6a57f8);
    buffer_vebbe6a57f8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v761096973b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v761096973b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vebbe6a57f8 + 0x0, 0x100, (uint8_t *)v761096973b);
    free(v761096973b);
    uint32_t *vc8386b7af2 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc8386b7af2[i] = (uint32_t)(buffer_vebbe6a57f8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x16, 0x2, (uint8_t *)vc8386b7af2);
    free(vc8386b7af2);
    stateful_free(buffer_vfb79a10548);
    buffer_vfb79a10548 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v63a1e1de86 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v63a1e1de86[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vfb79a10548 + 0x0, 0x100, (uint8_t *)v63a1e1de86);
    free(v63a1e1de86);
    uint32_t *v68a0c421c7 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v68a0c421c7[i] = (uint32_t)(buffer_vfb79a10548 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x18, 0x2, (uint8_t *)v68a0c421c7);
    free(v68a0c421c7);
    stateful_free(buffer_v6ec3549f81);
    buffer_v6ec3549f81 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb83f69342f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb83f69342f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6ec3549f81 + 0x0, 0x100, (uint8_t *)vb83f69342f);
    free(vb83f69342f);
    uint32_t *v980b628321 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v980b628321[i] = (uint32_t)(buffer_v6ec3549f81 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x1a, 0x2, (uint8_t *)v980b628321);
    free(v980b628321);
    stateful_free(buffer_v69437ff543);
    buffer_v69437ff543 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2fa9855042 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2fa9855042[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v69437ff543 + 0x0, 0x100, (uint8_t *)v2fa9855042);
    free(v2fa9855042);
    uint32_t *v186c241beb = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v186c241beb[i] = (uint32_t)(buffer_v69437ff543 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x1c, 0x2, (uint8_t *)v186c241beb);
    free(v186c241beb);
    stateful_free(buffer_v9aeab9bd2d);
    buffer_v9aeab9bd2d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v18d8b8eb11 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v18d8b8eb11[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9aeab9bd2d + 0x0, 0x100, (uint8_t *)v18d8b8eb11);
    free(v18d8b8eb11);
    uint32_t *vcd7331f4a3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vcd7331f4a3[i] = (uint32_t)(buffer_v9aeab9bd2d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vbf1f52814a + 0x1e, 0x2, (uint8_t *)vcd7331f4a3);
    free(vcd7331f4a3);
    uint32_t *vd5d9b46286 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd5d9b46286[i] = (uint32_t)(OHCI_ISO_TD_vbf1f52814a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vcb9e45204e + 0x8, 0x4, (uint8_t *)vd5d9b46286);
    free(vd5d9b46286);
    goto vf906c21acd_out;
vf906c21acd_out:;
    uint32_t *vc69d6c0f81 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc69d6c0f81[i] = (uint32_t)OHCI_ED_vcb9e45204e;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vcb9e45204e + 0xc, 0x4, (uint8_t *)vc69d6c0f81);
    free(vc69d6c0f81);
    uint32_t *v48546fea18 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v48546fea18[i] = (uint32_t)OHCI_ED_vcb9e45204e;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x18, 0x4, (uint8_t *)v48546fea18);
    free(v48546fea18);
    goto v56e6f4fdda_out;
v56e6f4fdda_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto va0e2542fdf_0; break;
    }
va0e2542fdf_0:;
    stateful_free(OHCI_ED_v1f860b5e7d);
    OHCI_ED_v1f860b5e7d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v5bd4e751c4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5bd4e751c4[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1f860b5e7d + 0x0, 0x4, (uint8_t *)v5bd4e751c4);
    free(v5bd4e751c4);
    uint32_t *va47087a8b4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va47087a8b4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1f860b5e7d + 0x4, 0x4, (uint8_t *)va47087a8b4);
    free(va47087a8b4);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v9040884d12_0; break;
        case 1: goto v9040884d12_1; break;
    }
v9040884d12_0:;
    stateful_free(OHCI_TD_v47c1ab847d);
    OHCI_TD_v47c1ab847d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v9470ec66f5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9470ec66f5[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v47c1ab847d + 0x0, 0x4, (uint8_t *)v9470ec66f5);
    free(v9470ec66f5);
    uint32_t *v66806110d1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v66806110d1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v47c1ab847d + 0x4, 0x4, (uint8_t *)v66806110d1);
    free(v66806110d1);
    uint32_t *v5fcab83c06 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5fcab83c06[i] = (uint32_t)(OHCI_TD_v47c1ab847d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v47c1ab847d + 0x8, 0x4, (uint8_t *)v5fcab83c06);
    free(v5fcab83c06);
    uint32_t *v1de9de6373 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1de9de6373[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v47c1ab847d + 0xc, 0x4, (uint8_t *)v1de9de6373);
    free(v1de9de6373);
    uint32_t *v1d6b5ecd81 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1d6b5ecd81[i] = (uint32_t)(OHCI_TD_v47c1ab847d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1f860b5e7d + 0x8, 0x4, (uint8_t *)v1d6b5ecd81);
    free(v1d6b5ecd81);
    goto v9040884d12_out;
v9040884d12_1:;
    stateful_free(OHCI_ISO_TD_v78de0b4614);
    OHCI_ISO_TD_v78de0b4614 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *ve87f48696a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve87f48696a[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x0, 0x4, (uint8_t *)ve87f48696a);
    free(ve87f48696a);
    uint32_t *v9d3e118066 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9d3e118066[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x4, 0x4, (uint8_t *)v9d3e118066);
    free(v9d3e118066);
    uint32_t *v282e36fc3a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v282e36fc3a[i] = (uint32_t)(OHCI_ISO_TD_v78de0b4614 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x8, 0x4, (uint8_t *)v282e36fc3a);
    free(v282e36fc3a);
    uint32_t *v41e82da1dd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v41e82da1dd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0xc, 0x4, (uint8_t *)v41e82da1dd);
    free(v41e82da1dd);
    stateful_free(buffer_ve6bef76bbc);
    buffer_ve6bef76bbc = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v56941c2237 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v56941c2237[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve6bef76bbc + 0x0, 0x100, (uint8_t *)v56941c2237);
    free(v56941c2237);
    uint32_t *v41dad03c01 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v41dad03c01[i] = (uint32_t)(buffer_ve6bef76bbc | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x10, 0x2, (uint8_t *)v41dad03c01);
    free(v41dad03c01);
    stateful_free(buffer_vb2baa484c3);
    buffer_vb2baa484c3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd3e32f982f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd3e32f982f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb2baa484c3 + 0x0, 0x100, (uint8_t *)vd3e32f982f);
    free(vd3e32f982f);
    uint32_t *v743663cc32 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v743663cc32[i] = (uint32_t)(buffer_vb2baa484c3 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x12, 0x2, (uint8_t *)v743663cc32);
    free(v743663cc32);
    stateful_free(buffer_v519220479f);
    buffer_v519220479f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v714be0dab8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v714be0dab8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v519220479f + 0x0, 0x100, (uint8_t *)v714be0dab8);
    free(v714be0dab8);
    uint32_t *vfb19c272b4 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vfb19c272b4[i] = (uint32_t)(buffer_v519220479f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x14, 0x2, (uint8_t *)vfb19c272b4);
    free(vfb19c272b4);
    stateful_free(buffer_v896aa2840d);
    buffer_v896aa2840d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vce28534db9 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vce28534db9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v896aa2840d + 0x0, 0x100, (uint8_t *)vce28534db9);
    free(vce28534db9);
    uint32_t *v7d41a07c90 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7d41a07c90[i] = (uint32_t)(buffer_v896aa2840d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x16, 0x2, (uint8_t *)v7d41a07c90);
    free(v7d41a07c90);
    stateful_free(buffer_vba8562f2d3);
    buffer_vba8562f2d3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3ed26211ae = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3ed26211ae[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vba8562f2d3 + 0x0, 0x100, (uint8_t *)v3ed26211ae);
    free(v3ed26211ae);
    uint32_t *vec7d54b64b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vec7d54b64b[i] = (uint32_t)(buffer_vba8562f2d3 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x18, 0x2, (uint8_t *)vec7d54b64b);
    free(vec7d54b64b);
    stateful_free(buffer_v5e2bd96bd2);
    buffer_v5e2bd96bd2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4fceca11cc = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4fceca11cc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5e2bd96bd2 + 0x0, 0x100, (uint8_t *)v4fceca11cc);
    free(v4fceca11cc);
    uint32_t *v79dd693e33 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v79dd693e33[i] = (uint32_t)(buffer_v5e2bd96bd2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x1a, 0x2, (uint8_t *)v79dd693e33);
    free(v79dd693e33);
    stateful_free(buffer_v6da84b519f);
    buffer_v6da84b519f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v845a5b3906 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v845a5b3906[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6da84b519f + 0x0, 0x100, (uint8_t *)v845a5b3906);
    free(v845a5b3906);
    uint32_t *vc9fcccb826 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc9fcccb826[i] = (uint32_t)(buffer_v6da84b519f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x1c, 0x2, (uint8_t *)vc9fcccb826);
    free(vc9fcccb826);
    stateful_free(buffer_vb4377e0ea3);
    buffer_vb4377e0ea3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7a501a0d03 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7a501a0d03[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb4377e0ea3 + 0x0, 0x100, (uint8_t *)v7a501a0d03);
    free(v7a501a0d03);
    uint32_t *vc354f207c6 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc354f207c6[i] = (uint32_t)(buffer_vb4377e0ea3 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v78de0b4614 + 0x1e, 0x2, (uint8_t *)vc354f207c6);
    free(vc354f207c6);
    uint32_t *v36be852d23 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v36be852d23[i] = (uint32_t)(OHCI_ISO_TD_v78de0b4614 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1f860b5e7d + 0x8, 0x4, (uint8_t *)v36be852d23);
    free(v36be852d23);
    goto v9040884d12_out;
v9040884d12_out:;
    uint32_t *ve7e7e9d6c5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve7e7e9d6c5[i] = (uint32_t)OHCI_ED_v1f860b5e7d;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v1f860b5e7d + 0xc, 0x4, (uint8_t *)ve7e7e9d6c5);
    free(ve7e7e9d6c5);
    uint32_t *v995b2c02ff = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v995b2c02ff[i] = (uint32_t)OHCI_ED_v1f860b5e7d;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x1c, 0x4, (uint8_t *)v995b2c02ff);
    free(v995b2c02ff);
    goto va0e2542fdf_out;
va0e2542fdf_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v39091ba34b_0; break;
    }
v39091ba34b_0:;
    stateful_free(OHCI_ED_v5c6208182c);
    OHCI_ED_v5c6208182c = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vfdd428737d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfdd428737d[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5c6208182c + 0x0, 0x4, (uint8_t *)vfdd428737d);
    free(vfdd428737d);
    uint32_t *v3d9c2b9b98 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3d9c2b9b98[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5c6208182c + 0x4, 0x4, (uint8_t *)v3d9c2b9b98);
    free(v3d9c2b9b98);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v4c6df2b5c1_0; break;
        case 1: goto v4c6df2b5c1_1; break;
    }
v4c6df2b5c1_0:;
    stateful_free(OHCI_TD_v5e41a11de4);
    OHCI_TD_v5e41a11de4 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vafda7496b8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vafda7496b8[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5e41a11de4 + 0x0, 0x4, (uint8_t *)vafda7496b8);
    free(vafda7496b8);
    uint32_t *v651c03e742 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v651c03e742[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5e41a11de4 + 0x4, 0x4, (uint8_t *)v651c03e742);
    free(v651c03e742);
    uint32_t *v760a2c9a54 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v760a2c9a54[i] = (uint32_t)(OHCI_TD_v5e41a11de4 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5e41a11de4 + 0x8, 0x4, (uint8_t *)v760a2c9a54);
    free(v760a2c9a54);
    uint32_t *v4c29f52dbc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4c29f52dbc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5e41a11de4 + 0xc, 0x4, (uint8_t *)v4c29f52dbc);
    free(v4c29f52dbc);
    uint32_t *v520851e4d2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v520851e4d2[i] = (uint32_t)(OHCI_TD_v5e41a11de4 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5c6208182c + 0x8, 0x4, (uint8_t *)v520851e4d2);
    free(v520851e4d2);
    goto v4c6df2b5c1_out;
v4c6df2b5c1_1:;
    stateful_free(OHCI_ISO_TD_v2107991b24);
    OHCI_ISO_TD_v2107991b24 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v97c1b07738 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v97c1b07738[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x0, 0x4, (uint8_t *)v97c1b07738);
    free(v97c1b07738);
    uint32_t *vb88aa6c261 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb88aa6c261[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x4, 0x4, (uint8_t *)vb88aa6c261);
    free(vb88aa6c261);
    uint32_t *v56b626440b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v56b626440b[i] = (uint32_t)(OHCI_ISO_TD_v2107991b24 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x8, 0x4, (uint8_t *)v56b626440b);
    free(v56b626440b);
    uint32_t *v9b7f4295cb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9b7f4295cb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0xc, 0x4, (uint8_t *)v9b7f4295cb);
    free(v9b7f4295cb);
    stateful_free(buffer_va78ae40bc7);
    buffer_va78ae40bc7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v270b8d0b03 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v270b8d0b03[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va78ae40bc7 + 0x0, 0x100, (uint8_t *)v270b8d0b03);
    free(v270b8d0b03);
    uint32_t *vb3338073b5 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb3338073b5[i] = (uint32_t)(buffer_va78ae40bc7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x10, 0x2, (uint8_t *)vb3338073b5);
    free(vb3338073b5);
    stateful_free(buffer_ve2d9b74a66);
    buffer_ve2d9b74a66 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vcf4123e8ba = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vcf4123e8ba[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve2d9b74a66 + 0x0, 0x100, (uint8_t *)vcf4123e8ba);
    free(vcf4123e8ba);
    uint32_t *vf765ed17a3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf765ed17a3[i] = (uint32_t)(buffer_ve2d9b74a66 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x12, 0x2, (uint8_t *)vf765ed17a3);
    free(vf765ed17a3);
    stateful_free(buffer_v9ae5fee8f1);
    buffer_v9ae5fee8f1 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9a7bf7c483 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9a7bf7c483[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9ae5fee8f1 + 0x0, 0x100, (uint8_t *)v9a7bf7c483);
    free(v9a7bf7c483);
    uint32_t *vfe550fa688 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vfe550fa688[i] = (uint32_t)(buffer_v9ae5fee8f1 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x14, 0x2, (uint8_t *)vfe550fa688);
    free(vfe550fa688);
    stateful_free(buffer_v9cf22a9932);
    buffer_v9cf22a9932 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v36f0f1991f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v36f0f1991f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9cf22a9932 + 0x0, 0x100, (uint8_t *)v36f0f1991f);
    free(v36f0f1991f);
    uint32_t *vcf07648337 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vcf07648337[i] = (uint32_t)(buffer_v9cf22a9932 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x16, 0x2, (uint8_t *)vcf07648337);
    free(vcf07648337);
    stateful_free(buffer_vf204bb78dc);
    buffer_vf204bb78dc = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5801c7fdb7 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5801c7fdb7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf204bb78dc + 0x0, 0x100, (uint8_t *)v5801c7fdb7);
    free(v5801c7fdb7);
    uint32_t *vf9cd9f4563 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf9cd9f4563[i] = (uint32_t)(buffer_vf204bb78dc | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x18, 0x2, (uint8_t *)vf9cd9f4563);
    free(vf9cd9f4563);
    stateful_free(buffer_v19476a70a9);
    buffer_v19476a70a9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf8adf97b38 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf8adf97b38[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v19476a70a9 + 0x0, 0x100, (uint8_t *)vf8adf97b38);
    free(vf8adf97b38);
    uint32_t *vb1ade2426b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb1ade2426b[i] = (uint32_t)(buffer_v19476a70a9 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x1a, 0x2, (uint8_t *)vb1ade2426b);
    free(vb1ade2426b);
    stateful_free(buffer_v9851eace85);
    buffer_v9851eace85 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va4a7ad1594 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va4a7ad1594[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9851eace85 + 0x0, 0x100, (uint8_t *)va4a7ad1594);
    free(va4a7ad1594);
    uint32_t *v547ddbb48e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v547ddbb48e[i] = (uint32_t)(buffer_v9851eace85 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x1c, 0x2, (uint8_t *)v547ddbb48e);
    free(v547ddbb48e);
    stateful_free(buffer_v8265f708c4);
    buffer_v8265f708c4 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v12227f4ccf = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v12227f4ccf[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8265f708c4 + 0x0, 0x100, (uint8_t *)v12227f4ccf);
    free(v12227f4ccf);
    uint32_t *vcd62f51f67 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vcd62f51f67[i] = (uint32_t)(buffer_v8265f708c4 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2107991b24 + 0x1e, 0x2, (uint8_t *)vcd62f51f67);
    free(vcd62f51f67);
    uint32_t *v2a8648c51d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2a8648c51d[i] = (uint32_t)(OHCI_ISO_TD_v2107991b24 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5c6208182c + 0x8, 0x4, (uint8_t *)v2a8648c51d);
    free(v2a8648c51d);
    goto v4c6df2b5c1_out;
v4c6df2b5c1_out:;
    uint32_t *v996ed9bbda = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v996ed9bbda[i] = (uint32_t)OHCI_ED_v5c6208182c;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5c6208182c + 0xc, 0x4, (uint8_t *)v996ed9bbda);
    free(v996ed9bbda);
    uint32_t *va7ad6277fd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va7ad6277fd[i] = (uint32_t)OHCI_ED_v5c6208182c;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x20, 0x4, (uint8_t *)va7ad6277fd);
    free(va7ad6277fd);
    goto v39091ba34b_out;
v39091ba34b_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto va0c61359d7_0; break;
    }
va0c61359d7_0:;
    stateful_free(OHCI_ED_vf35a963ded);
    OHCI_ED_vf35a963ded = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v1f658f1891 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1f658f1891[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf35a963ded + 0x0, 0x4, (uint8_t *)v1f658f1891);
    free(v1f658f1891);
    uint32_t *v141f25b993 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v141f25b993[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf35a963ded + 0x4, 0x4, (uint8_t *)v141f25b993);
    free(v141f25b993);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v6df77006f2_0; break;
        case 1: goto v6df77006f2_1; break;
    }
v6df77006f2_0:;
    stateful_free(OHCI_TD_v1077bac3ab);
    OHCI_TD_v1077bac3ab = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v2b39bf9547 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2b39bf9547[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1077bac3ab + 0x0, 0x4, (uint8_t *)v2b39bf9547);
    free(v2b39bf9547);
    uint32_t *vcce6207a4d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcce6207a4d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1077bac3ab + 0x4, 0x4, (uint8_t *)vcce6207a4d);
    free(vcce6207a4d);
    uint32_t *vb6e341315d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb6e341315d[i] = (uint32_t)(OHCI_TD_v1077bac3ab & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1077bac3ab + 0x8, 0x4, (uint8_t *)vb6e341315d);
    free(vb6e341315d);
    uint32_t *v106689ac7d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v106689ac7d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1077bac3ab + 0xc, 0x4, (uint8_t *)v106689ac7d);
    free(v106689ac7d);
    uint32_t *vfda81160fb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfda81160fb[i] = (uint32_t)(OHCI_TD_v1077bac3ab & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf35a963ded + 0x8, 0x4, (uint8_t *)vfda81160fb);
    free(vfda81160fb);
    goto v6df77006f2_out;
v6df77006f2_1:;
    stateful_free(OHCI_ISO_TD_vf6e15c50e0);
    OHCI_ISO_TD_vf6e15c50e0 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v747b096282 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v747b096282[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x0, 0x4, (uint8_t *)v747b096282);
    free(v747b096282);
    uint32_t *v1d8b971766 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1d8b971766[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x4, 0x4, (uint8_t *)v1d8b971766);
    free(v1d8b971766);
    uint32_t *v7184fe96f3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7184fe96f3[i] = (uint32_t)(OHCI_ISO_TD_vf6e15c50e0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x8, 0x4, (uint8_t *)v7184fe96f3);
    free(v7184fe96f3);
    uint32_t *v10f856bfdf = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v10f856bfdf[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0xc, 0x4, (uint8_t *)v10f856bfdf);
    free(v10f856bfdf);
    stateful_free(buffer_vbbff95f8aa);
    buffer_vbbff95f8aa = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6c81716196 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6c81716196[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vbbff95f8aa + 0x0, 0x100, (uint8_t *)v6c81716196);
    free(v6c81716196);
    uint32_t *ve61d41a76b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        ve61d41a76b[i] = (uint32_t)(buffer_vbbff95f8aa | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x10, 0x2, (uint8_t *)ve61d41a76b);
    free(ve61d41a76b);
    stateful_free(buffer_va6776326b7);
    buffer_va6776326b7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1d873b41e9 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1d873b41e9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va6776326b7 + 0x0, 0x100, (uint8_t *)v1d873b41e9);
    free(v1d873b41e9);
    uint32_t *vc64424f7a7 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc64424f7a7[i] = (uint32_t)(buffer_va6776326b7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x12, 0x2, (uint8_t *)vc64424f7a7);
    free(vc64424f7a7);
    stateful_free(buffer_v6a860186a0);
    buffer_v6a860186a0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1d9efadfaf = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1d9efadfaf[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6a860186a0 + 0x0, 0x100, (uint8_t *)v1d9efadfaf);
    free(v1d9efadfaf);
    uint32_t *v79e82f0857 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v79e82f0857[i] = (uint32_t)(buffer_v6a860186a0 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x14, 0x2, (uint8_t *)v79e82f0857);
    free(v79e82f0857);
    stateful_free(buffer_v9289fed4b0);
    buffer_v9289fed4b0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v59cb97d907 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v59cb97d907[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9289fed4b0 + 0x0, 0x100, (uint8_t *)v59cb97d907);
    free(v59cb97d907);
    uint32_t *v4363a6e55c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4363a6e55c[i] = (uint32_t)(buffer_v9289fed4b0 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x16, 0x2, (uint8_t *)v4363a6e55c);
    free(v4363a6e55c);
    stateful_free(buffer_v6f222458e2);
    buffer_v6f222458e2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve1a44a2083 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve1a44a2083[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6f222458e2 + 0x0, 0x100, (uint8_t *)ve1a44a2083);
    free(ve1a44a2083);
    uint32_t *v21d41ceac4 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v21d41ceac4[i] = (uint32_t)(buffer_v6f222458e2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x18, 0x2, (uint8_t *)v21d41ceac4);
    free(v21d41ceac4);
    stateful_free(buffer_v691b637c9f);
    buffer_v691b637c9f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2f87a3e92b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2f87a3e92b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v691b637c9f + 0x0, 0x100, (uint8_t *)v2f87a3e92b);
    free(v2f87a3e92b);
    uint32_t *v5722457505 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5722457505[i] = (uint32_t)(buffer_v691b637c9f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x1a, 0x2, (uint8_t *)v5722457505);
    free(v5722457505);
    stateful_free(buffer_v4c6e245696);
    buffer_v4c6e245696 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vff75548a1d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vff75548a1d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v4c6e245696 + 0x0, 0x100, (uint8_t *)vff75548a1d);
    free(vff75548a1d);
    uint32_t *v3bf970b6c3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v3bf970b6c3[i] = (uint32_t)(buffer_v4c6e245696 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x1c, 0x2, (uint8_t *)v3bf970b6c3);
    free(v3bf970b6c3);
    stateful_free(buffer_vc8a284519f);
    buffer_vc8a284519f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd6a1e6d6e5 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd6a1e6d6e5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc8a284519f + 0x0, 0x100, (uint8_t *)vd6a1e6d6e5);
    free(vd6a1e6d6e5);
    uint32_t *vee5a8001da = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vee5a8001da[i] = (uint32_t)(buffer_vc8a284519f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf6e15c50e0 + 0x1e, 0x2, (uint8_t *)vee5a8001da);
    free(vee5a8001da);
    uint32_t *vcc7aeb9fc2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcc7aeb9fc2[i] = (uint32_t)(OHCI_ISO_TD_vf6e15c50e0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf35a963ded + 0x8, 0x4, (uint8_t *)vcc7aeb9fc2);
    free(vcc7aeb9fc2);
    goto v6df77006f2_out;
v6df77006f2_out:;
    uint32_t *vbe27a5bd58 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbe27a5bd58[i] = (uint32_t)OHCI_ED_vf35a963ded;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf35a963ded + 0xc, 0x4, (uint8_t *)vbe27a5bd58);
    free(vbe27a5bd58);
    uint32_t *vc19bdad295 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc19bdad295[i] = (uint32_t)OHCI_ED_vf35a963ded;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x24, 0x4, (uint8_t *)vc19bdad295);
    free(vc19bdad295);
    goto va0c61359d7_out;
va0c61359d7_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v69e5b33856_0; break;
    }
v69e5b33856_0:;
    stateful_free(OHCI_ED_v59b697e67a);
    OHCI_ED_v59b697e67a = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v18d6e59a6e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v18d6e59a6e[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v59b697e67a + 0x0, 0x4, (uint8_t *)v18d6e59a6e);
    free(v18d6e59a6e);
    uint32_t *vff879a9d20 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vff879a9d20[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v59b697e67a + 0x4, 0x4, (uint8_t *)vff879a9d20);
    free(vff879a9d20);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto ve89d268251_0; break;
        case 1: goto ve89d268251_1; break;
    }
ve89d268251_0:;
    stateful_free(OHCI_TD_vceca893c37);
    OHCI_TD_vceca893c37 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v895184fd28 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v895184fd28[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vceca893c37 + 0x0, 0x4, (uint8_t *)v895184fd28);
    free(v895184fd28);
    uint32_t *vfe470620b2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfe470620b2[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vceca893c37 + 0x4, 0x4, (uint8_t *)vfe470620b2);
    free(vfe470620b2);
    uint32_t *vb8d1363592 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb8d1363592[i] = (uint32_t)(OHCI_TD_vceca893c37 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vceca893c37 + 0x8, 0x4, (uint8_t *)vb8d1363592);
    free(vb8d1363592);
    uint32_t *vc7dcd75f19 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc7dcd75f19[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vceca893c37 + 0xc, 0x4, (uint8_t *)vc7dcd75f19);
    free(vc7dcd75f19);
    uint32_t *vc3e9b03d3c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc3e9b03d3c[i] = (uint32_t)(OHCI_TD_vceca893c37 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v59b697e67a + 0x8, 0x4, (uint8_t *)vc3e9b03d3c);
    free(vc3e9b03d3c);
    goto ve89d268251_out;
ve89d268251_1:;
    stateful_free(OHCI_ISO_TD_vdd8f0e9cb1);
    OHCI_ISO_TD_vdd8f0e9cb1 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vd95d620502 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd95d620502[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x0, 0x4, (uint8_t *)vd95d620502);
    free(vd95d620502);
    uint32_t *vdab76e51f6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdab76e51f6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x4, 0x4, (uint8_t *)vdab76e51f6);
    free(vdab76e51f6);
    uint32_t *v1d31217333 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1d31217333[i] = (uint32_t)(OHCI_ISO_TD_vdd8f0e9cb1 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x8, 0x4, (uint8_t *)v1d31217333);
    free(v1d31217333);
    uint32_t *v26ba617897 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v26ba617897[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0xc, 0x4, (uint8_t *)v26ba617897);
    free(v26ba617897);
    stateful_free(buffer_v2d45dab201);
    buffer_v2d45dab201 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1b131c9f40 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1b131c9f40[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2d45dab201 + 0x0, 0x100, (uint8_t *)v1b131c9f40);
    free(v1b131c9f40);
    uint32_t *vd8ee23a5fa = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vd8ee23a5fa[i] = (uint32_t)(buffer_v2d45dab201 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x10, 0x2, (uint8_t *)vd8ee23a5fa);
    free(vd8ee23a5fa);
    stateful_free(buffer_v363f288dcd);
    buffer_v363f288dcd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v18d922fd2d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v18d922fd2d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v363f288dcd + 0x0, 0x100, (uint8_t *)v18d922fd2d);
    free(v18d922fd2d);
    uint32_t *v5f7e4dfc97 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5f7e4dfc97[i] = (uint32_t)(buffer_v363f288dcd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x12, 0x2, (uint8_t *)v5f7e4dfc97);
    free(v5f7e4dfc97);
    stateful_free(buffer_ve4fc1161d5);
    buffer_ve4fc1161d5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v634561e11a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v634561e11a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve4fc1161d5 + 0x0, 0x100, (uint8_t *)v634561e11a);
    free(v634561e11a);
    uint32_t *vcf5e77fb46 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vcf5e77fb46[i] = (uint32_t)(buffer_ve4fc1161d5 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x14, 0x2, (uint8_t *)vcf5e77fb46);
    free(vcf5e77fb46);
    stateful_free(buffer_vd8f1a9c6cd);
    buffer_vd8f1a9c6cd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc0f912c965 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc0f912c965[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd8f1a9c6cd + 0x0, 0x100, (uint8_t *)vc0f912c965);
    free(vc0f912c965);
    uint32_t *vb82d1bdff5 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb82d1bdff5[i] = (uint32_t)(buffer_vd8f1a9c6cd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x16, 0x2, (uint8_t *)vb82d1bdff5);
    free(vb82d1bdff5);
    stateful_free(buffer_vb930684195);
    buffer_vb930684195 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vba2a135ea1 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vba2a135ea1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb930684195 + 0x0, 0x100, (uint8_t *)vba2a135ea1);
    free(vba2a135ea1);
    uint32_t *v63c62b9e06 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v63c62b9e06[i] = (uint32_t)(buffer_vb930684195 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x18, 0x2, (uint8_t *)v63c62b9e06);
    free(v63c62b9e06);
    stateful_free(buffer_vf7c9ffb494);
    buffer_vf7c9ffb494 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3c9d79402d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3c9d79402d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf7c9ffb494 + 0x0, 0x100, (uint8_t *)v3c9d79402d);
    free(v3c9d79402d);
    uint32_t *v7fcf7a8526 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7fcf7a8526[i] = (uint32_t)(buffer_vf7c9ffb494 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x1a, 0x2, (uint8_t *)v7fcf7a8526);
    free(v7fcf7a8526);
    stateful_free(buffer_vc7637892ed);
    buffer_vc7637892ed = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va91dd7295d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va91dd7295d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc7637892ed + 0x0, 0x100, (uint8_t *)va91dd7295d);
    free(va91dd7295d);
    uint32_t *v91090b5111 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v91090b5111[i] = (uint32_t)(buffer_vc7637892ed | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x1c, 0x2, (uint8_t *)v91090b5111);
    free(v91090b5111);
    stateful_free(buffer_v840e11cd91);
    buffer_v840e11cd91 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf16164722c = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf16164722c[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v840e11cd91 + 0x0, 0x100, (uint8_t *)vf16164722c);
    free(vf16164722c);
    uint32_t *v702c154bdb = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v702c154bdb[i] = (uint32_t)(buffer_v840e11cd91 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vdd8f0e9cb1 + 0x1e, 0x2, (uint8_t *)v702c154bdb);
    free(v702c154bdb);
    uint32_t *vb6da75bf04 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb6da75bf04[i] = (uint32_t)(OHCI_ISO_TD_vdd8f0e9cb1 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v59b697e67a + 0x8, 0x4, (uint8_t *)vb6da75bf04);
    free(vb6da75bf04);
    goto ve89d268251_out;
ve89d268251_out:;
    uint32_t *v7e7bc70920 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7e7bc70920[i] = (uint32_t)OHCI_ED_v59b697e67a;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v59b697e67a + 0xc, 0x4, (uint8_t *)v7e7bc70920);
    free(v7e7bc70920);
    uint32_t *v88df7924c7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v88df7924c7[i] = (uint32_t)OHCI_ED_v59b697e67a;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x28, 0x4, (uint8_t *)v88df7924c7);
    free(v88df7924c7);
    goto v69e5b33856_out;
v69e5b33856_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vbd7e5d0a0b_0; break;
    }
vbd7e5d0a0b_0:;
    stateful_free(OHCI_ED_v72478fddcf);
    OHCI_ED_v72478fddcf = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *va4bd389b79 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va4bd389b79[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v72478fddcf + 0x0, 0x4, (uint8_t *)va4bd389b79);
    free(va4bd389b79);
    uint32_t *vd6be396a9d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd6be396a9d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v72478fddcf + 0x4, 0x4, (uint8_t *)vd6be396a9d);
    free(vd6be396a9d);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vd25836a842_0; break;
        case 1: goto vd25836a842_1; break;
    }
vd25836a842_0:;
    stateful_free(OHCI_TD_vdff68ad86f);
    OHCI_TD_vdff68ad86f = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vf21295cf22 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf21295cf22[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vdff68ad86f + 0x0, 0x4, (uint8_t *)vf21295cf22);
    free(vf21295cf22);
    uint32_t *v1d5a7041fd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1d5a7041fd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vdff68ad86f + 0x4, 0x4, (uint8_t *)v1d5a7041fd);
    free(v1d5a7041fd);
    uint32_t *v3d7dd848e9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3d7dd848e9[i] = (uint32_t)(OHCI_TD_vdff68ad86f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vdff68ad86f + 0x8, 0x4, (uint8_t *)v3d7dd848e9);
    free(v3d7dd848e9);
    uint32_t *v4dd2811cec = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4dd2811cec[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vdff68ad86f + 0xc, 0x4, (uint8_t *)v4dd2811cec);
    free(v4dd2811cec);
    uint32_t *v725cbde9d1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v725cbde9d1[i] = (uint32_t)(OHCI_TD_vdff68ad86f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v72478fddcf + 0x8, 0x4, (uint8_t *)v725cbde9d1);
    free(v725cbde9d1);
    goto vd25836a842_out;
vd25836a842_1:;
    stateful_free(OHCI_ISO_TD_vfb314c966c);
    OHCI_ISO_TD_vfb314c966c = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v26b989f34d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v26b989f34d[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x0, 0x4, (uint8_t *)v26b989f34d);
    free(v26b989f34d);
    uint32_t *v2aa5205049 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2aa5205049[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x4, 0x4, (uint8_t *)v2aa5205049);
    free(v2aa5205049);
    uint32_t *v4923f68158 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4923f68158[i] = (uint32_t)(OHCI_ISO_TD_vfb314c966c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x8, 0x4, (uint8_t *)v4923f68158);
    free(v4923f68158);
    uint32_t *v2be888482e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2be888482e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0xc, 0x4, (uint8_t *)v2be888482e);
    free(v2be888482e);
    stateful_free(buffer_v97062949d8);
    buffer_v97062949d8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v32e528fab3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v32e528fab3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v97062949d8 + 0x0, 0x100, (uint8_t *)v32e528fab3);
    free(v32e528fab3);
    uint32_t *v656f2645d1 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v656f2645d1[i] = (uint32_t)(buffer_v97062949d8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x10, 0x2, (uint8_t *)v656f2645d1);
    free(v656f2645d1);
    stateful_free(buffer_v592f36f145);
    buffer_v592f36f145 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc18ee20a22 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc18ee20a22[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v592f36f145 + 0x0, 0x100, (uint8_t *)vc18ee20a22);
    free(vc18ee20a22);
    uint32_t *v95a8f1281d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v95a8f1281d[i] = (uint32_t)(buffer_v592f36f145 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x12, 0x2, (uint8_t *)v95a8f1281d);
    free(v95a8f1281d);
    stateful_free(buffer_vd819752f1e);
    buffer_vd819752f1e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vecc10b7b70 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vecc10b7b70[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd819752f1e + 0x0, 0x100, (uint8_t *)vecc10b7b70);
    free(vecc10b7b70);
    uint32_t *v7531b4cce0 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7531b4cce0[i] = (uint32_t)(buffer_vd819752f1e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x14, 0x2, (uint8_t *)v7531b4cce0);
    free(v7531b4cce0);
    stateful_free(buffer_vb99ad6f44b);
    buffer_vb99ad6f44b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9866c53488 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9866c53488[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb99ad6f44b + 0x0, 0x100, (uint8_t *)v9866c53488);
    free(v9866c53488);
    uint32_t *ve9ec8cfa06 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        ve9ec8cfa06[i] = (uint32_t)(buffer_vb99ad6f44b | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x16, 0x2, (uint8_t *)ve9ec8cfa06);
    free(ve9ec8cfa06);
    stateful_free(buffer_v2fcdd422a3);
    buffer_v2fcdd422a3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vba62e31acc = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vba62e31acc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2fcdd422a3 + 0x0, 0x100, (uint8_t *)vba62e31acc);
    free(vba62e31acc);
    uint32_t *vb88048d7a1 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb88048d7a1[i] = (uint32_t)(buffer_v2fcdd422a3 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x18, 0x2, (uint8_t *)vb88048d7a1);
    free(vb88048d7a1);
    stateful_free(buffer_v73311c9ee5);
    buffer_v73311c9ee5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va18bd0f90e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va18bd0f90e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v73311c9ee5 + 0x0, 0x100, (uint8_t *)va18bd0f90e);
    free(va18bd0f90e);
    uint32_t *vc181b1f48e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc181b1f48e[i] = (uint32_t)(buffer_v73311c9ee5 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x1a, 0x2, (uint8_t *)vc181b1f48e);
    free(vc181b1f48e);
    stateful_free(buffer_v25a50e82ba);
    buffer_v25a50e82ba = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v51480f2e48 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v51480f2e48[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v25a50e82ba + 0x0, 0x100, (uint8_t *)v51480f2e48);
    free(v51480f2e48);
    uint32_t *vc158c79271 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc158c79271[i] = (uint32_t)(buffer_v25a50e82ba | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x1c, 0x2, (uint8_t *)vc158c79271);
    free(vc158c79271);
    stateful_free(buffer_v5d18eb6da9);
    buffer_v5d18eb6da9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3e753a7657 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3e753a7657[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5d18eb6da9 + 0x0, 0x100, (uint8_t *)v3e753a7657);
    free(v3e753a7657);
    uint32_t *vf66b8a2d4c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf66b8a2d4c[i] = (uint32_t)(buffer_v5d18eb6da9 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vfb314c966c + 0x1e, 0x2, (uint8_t *)vf66b8a2d4c);
    free(vf66b8a2d4c);
    uint32_t *vaee342de20 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vaee342de20[i] = (uint32_t)(OHCI_ISO_TD_vfb314c966c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v72478fddcf + 0x8, 0x4, (uint8_t *)vaee342de20);
    free(vaee342de20);
    goto vd25836a842_out;
vd25836a842_out:;
    uint32_t *v5bafd5c13a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5bafd5c13a[i] = (uint32_t)OHCI_ED_v72478fddcf;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v72478fddcf + 0xc, 0x4, (uint8_t *)v5bafd5c13a);
    free(v5bafd5c13a);
    uint32_t *v5aeed9583a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5aeed9583a[i] = (uint32_t)OHCI_ED_v72478fddcf;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x2c, 0x4, (uint8_t *)v5aeed9583a);
    free(v5aeed9583a);
    goto vbd7e5d0a0b_out;
vbd7e5d0a0b_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v2ea4e6db05_0; break;
    }
v2ea4e6db05_0:;
    stateful_free(OHCI_ED_v5bae16dbe6);
    OHCI_ED_v5bae16dbe6 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *ved181fc5df = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ved181fc5df[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5bae16dbe6 + 0x0, 0x4, (uint8_t *)ved181fc5df);
    free(ved181fc5df);
    uint32_t *v708c7913cb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v708c7913cb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5bae16dbe6 + 0x4, 0x4, (uint8_t *)v708c7913cb);
    free(v708c7913cb);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v24634a0839_0; break;
        case 1: goto v24634a0839_1; break;
    }
v24634a0839_0:;
    stateful_free(OHCI_TD_vb626f3d74a);
    OHCI_TD_vb626f3d74a = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vce4fef9c01 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vce4fef9c01[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vb626f3d74a + 0x0, 0x4, (uint8_t *)vce4fef9c01);
    free(vce4fef9c01);
    uint32_t *v23ca7144a3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v23ca7144a3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vb626f3d74a + 0x4, 0x4, (uint8_t *)v23ca7144a3);
    free(v23ca7144a3);
    uint32_t *ve8e3968ba7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve8e3968ba7[i] = (uint32_t)(OHCI_TD_vb626f3d74a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vb626f3d74a + 0x8, 0x4, (uint8_t *)ve8e3968ba7);
    free(ve8e3968ba7);
    uint32_t *vf36640a3cd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf36640a3cd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vb626f3d74a + 0xc, 0x4, (uint8_t *)vf36640a3cd);
    free(vf36640a3cd);
    uint32_t *vd879c0906b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd879c0906b[i] = (uint32_t)(OHCI_TD_vb626f3d74a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5bae16dbe6 + 0x8, 0x4, (uint8_t *)vd879c0906b);
    free(vd879c0906b);
    goto v24634a0839_out;
v24634a0839_1:;
    stateful_free(OHCI_ISO_TD_v56d6404857);
    OHCI_ISO_TD_v56d6404857 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *ve6c3fc2817 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve6c3fc2817[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x0, 0x4, (uint8_t *)ve6c3fc2817);
    free(ve6c3fc2817);
    uint32_t *veb730ef6e0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        veb730ef6e0[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x4, 0x4, (uint8_t *)veb730ef6e0);
    free(veb730ef6e0);
    uint32_t *v9e28c98a1e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9e28c98a1e[i] = (uint32_t)(OHCI_ISO_TD_v56d6404857 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x8, 0x4, (uint8_t *)v9e28c98a1e);
    free(v9e28c98a1e);
    uint32_t *v8e2a55b0f9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8e2a55b0f9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0xc, 0x4, (uint8_t *)v8e2a55b0f9);
    free(v8e2a55b0f9);
    stateful_free(buffer_v67f9cfa38f);
    buffer_v67f9cfa38f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc71c4de261 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc71c4de261[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v67f9cfa38f + 0x0, 0x100, (uint8_t *)vc71c4de261);
    free(vc71c4de261);
    uint32_t *vf8e8ef806a = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf8e8ef806a[i] = (uint32_t)(buffer_v67f9cfa38f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x10, 0x2, (uint8_t *)vf8e8ef806a);
    free(vf8e8ef806a);
    stateful_free(buffer_v442e9fdeeb);
    buffer_v442e9fdeeb = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8686753a06 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8686753a06[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v442e9fdeeb + 0x0, 0x100, (uint8_t *)v8686753a06);
    free(v8686753a06);
    uint32_t *vfa4d324223 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vfa4d324223[i] = (uint32_t)(buffer_v442e9fdeeb | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x12, 0x2, (uint8_t *)vfa4d324223);
    free(vfa4d324223);
    stateful_free(buffer_v33616977be);
    buffer_v33616977be = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve65528a812 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve65528a812[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v33616977be + 0x0, 0x100, (uint8_t *)ve65528a812);
    free(ve65528a812);
    uint32_t *va4715fb24e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va4715fb24e[i] = (uint32_t)(buffer_v33616977be | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x14, 0x2, (uint8_t *)va4715fb24e);
    free(va4715fb24e);
    stateful_free(buffer_v2b4ae57211);
    buffer_v2b4ae57211 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc08c3a04c3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc08c3a04c3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2b4ae57211 + 0x0, 0x100, (uint8_t *)vc08c3a04c3);
    free(vc08c3a04c3);
    uint32_t *v79aaa4d395 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v79aaa4d395[i] = (uint32_t)(buffer_v2b4ae57211 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x16, 0x2, (uint8_t *)v79aaa4d395);
    free(v79aaa4d395);
    stateful_free(buffer_vc3a4ed43d9);
    buffer_vc3a4ed43d9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc42ec2e737 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc42ec2e737[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc3a4ed43d9 + 0x0, 0x100, (uint8_t *)vc42ec2e737);
    free(vc42ec2e737);
    uint32_t *v2d1c213951 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v2d1c213951[i] = (uint32_t)(buffer_vc3a4ed43d9 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x18, 0x2, (uint8_t *)v2d1c213951);
    free(v2d1c213951);
    stateful_free(buffer_v99ab3aabae);
    buffer_v99ab3aabae = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3b86483ead = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3b86483ead[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v99ab3aabae + 0x0, 0x100, (uint8_t *)v3b86483ead);
    free(v3b86483ead);
    uint32_t *vb7fb082bd3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb7fb082bd3[i] = (uint32_t)(buffer_v99ab3aabae | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x1a, 0x2, (uint8_t *)vb7fb082bd3);
    free(vb7fb082bd3);
    stateful_free(buffer_v30dbd38cf0);
    buffer_v30dbd38cf0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v17742dab27 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v17742dab27[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v30dbd38cf0 + 0x0, 0x100, (uint8_t *)v17742dab27);
    free(v17742dab27);
    uint32_t *v4c8066e487 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4c8066e487[i] = (uint32_t)(buffer_v30dbd38cf0 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x1c, 0x2, (uint8_t *)v4c8066e487);
    free(v4c8066e487);
    stateful_free(buffer_vbf64f01fa7);
    buffer_vbf64f01fa7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v725577955b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v725577955b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vbf64f01fa7 + 0x0, 0x100, (uint8_t *)v725577955b);
    free(v725577955b);
    uint32_t *vff38bad9fc = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vff38bad9fc[i] = (uint32_t)(buffer_vbf64f01fa7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v56d6404857 + 0x1e, 0x2, (uint8_t *)vff38bad9fc);
    free(vff38bad9fc);
    uint32_t *vc8a01e42d8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc8a01e42d8[i] = (uint32_t)(OHCI_ISO_TD_v56d6404857 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5bae16dbe6 + 0x8, 0x4, (uint8_t *)vc8a01e42d8);
    free(vc8a01e42d8);
    goto v24634a0839_out;
v24634a0839_out:;
    uint32_t *v99094aa1dc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v99094aa1dc[i] = (uint32_t)OHCI_ED_v5bae16dbe6;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v5bae16dbe6 + 0xc, 0x4, (uint8_t *)v99094aa1dc);
    free(v99094aa1dc);
    uint32_t *v1b09ab5772 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1b09ab5772[i] = (uint32_t)OHCI_ED_v5bae16dbe6;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x30, 0x4, (uint8_t *)v1b09ab5772);
    free(v1b09ab5772);
    goto v2ea4e6db05_out;
v2ea4e6db05_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vcec3360a74_0; break;
    }
vcec3360a74_0:;
    stateful_free(OHCI_ED_vb975b0d310);
    OHCI_ED_vb975b0d310 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vcb2ec0a44d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcb2ec0a44d[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vb975b0d310 + 0x0, 0x4, (uint8_t *)vcb2ec0a44d);
    free(vcb2ec0a44d);
    uint32_t *vbd7a7372ea = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbd7a7372ea[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vb975b0d310 + 0x4, 0x4, (uint8_t *)vbd7a7372ea);
    free(vbd7a7372ea);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vadb351a4b5_0; break;
        case 1: goto vadb351a4b5_1; break;
    }
vadb351a4b5_0:;
    stateful_free(OHCI_TD_vf75062ddad);
    OHCI_TD_vf75062ddad = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v4bb252ab0e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4bb252ab0e[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf75062ddad + 0x0, 0x4, (uint8_t *)v4bb252ab0e);
    free(v4bb252ab0e);
    uint32_t *v18f3e9c9c7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v18f3e9c9c7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf75062ddad + 0x4, 0x4, (uint8_t *)v18f3e9c9c7);
    free(v18f3e9c9c7);
    uint32_t *vc5326d7afc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc5326d7afc[i] = (uint32_t)(OHCI_TD_vf75062ddad & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf75062ddad + 0x8, 0x4, (uint8_t *)vc5326d7afc);
    free(vc5326d7afc);
    uint32_t *v89637842ea = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v89637842ea[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf75062ddad + 0xc, 0x4, (uint8_t *)v89637842ea);
    free(v89637842ea);
    uint32_t *vf9ab306d23 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf9ab306d23[i] = (uint32_t)(OHCI_TD_vf75062ddad & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vb975b0d310 + 0x8, 0x4, (uint8_t *)vf9ab306d23);
    free(vf9ab306d23);
    goto vadb351a4b5_out;
vadb351a4b5_1:;
    stateful_free(OHCI_ISO_TD_v7b065139db);
    OHCI_ISO_TD_v7b065139db = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v546e2ce64c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v546e2ce64c[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x0, 0x4, (uint8_t *)v546e2ce64c);
    free(v546e2ce64c);
    uint32_t *v118cb1eac1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v118cb1eac1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x4, 0x4, (uint8_t *)v118cb1eac1);
    free(v118cb1eac1);
    uint32_t *ve4f6bbaa79 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve4f6bbaa79[i] = (uint32_t)(OHCI_ISO_TD_v7b065139db & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x8, 0x4, (uint8_t *)ve4f6bbaa79);
    free(ve4f6bbaa79);
    uint32_t *vbaf244e4e1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbaf244e4e1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0xc, 0x4, (uint8_t *)vbaf244e4e1);
    free(vbaf244e4e1);
    stateful_free(buffer_v154ced97b6);
    buffer_v154ced97b6 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf59bc78d9f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf59bc78d9f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v154ced97b6 + 0x0, 0x100, (uint8_t *)vf59bc78d9f);
    free(vf59bc78d9f);
    uint32_t *va985d2b6e0 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va985d2b6e0[i] = (uint32_t)(buffer_v154ced97b6 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x10, 0x2, (uint8_t *)va985d2b6e0);
    free(va985d2b6e0);
    stateful_free(buffer_vaf7d9f29a0);
    buffer_vaf7d9f29a0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1f5a8ca961 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1f5a8ca961[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vaf7d9f29a0 + 0x0, 0x100, (uint8_t *)v1f5a8ca961);
    free(v1f5a8ca961);
    uint32_t *v9c90d9559a = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9c90d9559a[i] = (uint32_t)(buffer_vaf7d9f29a0 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x12, 0x2, (uint8_t *)v9c90d9559a);
    free(v9c90d9559a);
    stateful_free(buffer_v6cf41f1fd1);
    buffer_v6cf41f1fd1 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v70ef404e69 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v70ef404e69[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6cf41f1fd1 + 0x0, 0x100, (uint8_t *)v70ef404e69);
    free(v70ef404e69);
    uint32_t *v4cac4d3c81 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4cac4d3c81[i] = (uint32_t)(buffer_v6cf41f1fd1 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x14, 0x2, (uint8_t *)v4cac4d3c81);
    free(v4cac4d3c81);
    stateful_free(buffer_v5cf14877fa);
    buffer_v5cf14877fa = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vee55305ec4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vee55305ec4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5cf14877fa + 0x0, 0x100, (uint8_t *)vee55305ec4);
    free(vee55305ec4);
    uint32_t *vb4a046078d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb4a046078d[i] = (uint32_t)(buffer_v5cf14877fa | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x16, 0x2, (uint8_t *)vb4a046078d);
    free(vb4a046078d);
    stateful_free(buffer_ve8ef281d2a);
    buffer_ve8ef281d2a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc94313647e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc94313647e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve8ef281d2a + 0x0, 0x100, (uint8_t *)vc94313647e);
    free(vc94313647e);
    uint32_t *v39fa65ced5 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v39fa65ced5[i] = (uint32_t)(buffer_ve8ef281d2a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x18, 0x2, (uint8_t *)v39fa65ced5);
    free(v39fa65ced5);
    stateful_free(buffer_v7cc77b092d);
    buffer_v7cc77b092d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf79a69c60e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf79a69c60e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7cc77b092d + 0x0, 0x100, (uint8_t *)vf79a69c60e);
    free(vf79a69c60e);
    uint32_t *v49fd88fe90 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v49fd88fe90[i] = (uint32_t)(buffer_v7cc77b092d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x1a, 0x2, (uint8_t *)v49fd88fe90);
    free(v49fd88fe90);
    stateful_free(buffer_v2d5e19ec92);
    buffer_v2d5e19ec92 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vecea2c52bb = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vecea2c52bb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2d5e19ec92 + 0x0, 0x100, (uint8_t *)vecea2c52bb);
    free(vecea2c52bb);
    uint32_t *v8489bba336 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8489bba336[i] = (uint32_t)(buffer_v2d5e19ec92 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x1c, 0x2, (uint8_t *)v8489bba336);
    free(v8489bba336);
    stateful_free(buffer_v318c32de43);
    buffer_v318c32de43 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vae1d442584 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vae1d442584[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v318c32de43 + 0x0, 0x100, (uint8_t *)vae1d442584);
    free(vae1d442584);
    uint32_t *v623ee8df92 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v623ee8df92[i] = (uint32_t)(buffer_v318c32de43 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v7b065139db + 0x1e, 0x2, (uint8_t *)v623ee8df92);
    free(v623ee8df92);
    uint32_t *vb02429c71c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb02429c71c[i] = (uint32_t)(OHCI_ISO_TD_v7b065139db & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vb975b0d310 + 0x8, 0x4, (uint8_t *)vb02429c71c);
    free(vb02429c71c);
    goto vadb351a4b5_out;
vadb351a4b5_out:;
    uint32_t *ve8c905eeee = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve8c905eeee[i] = (uint32_t)OHCI_ED_vb975b0d310;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vb975b0d310 + 0xc, 0x4, (uint8_t *)ve8c905eeee);
    free(ve8c905eeee);
    uint32_t *vf3d919c672 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf3d919c672[i] = (uint32_t)OHCI_ED_vb975b0d310;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x34, 0x4, (uint8_t *)vf3d919c672);
    free(vf3d919c672);
    goto vcec3360a74_out;
vcec3360a74_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vdabccc8bab_0; break;
    }
vdabccc8bab_0:;
    stateful_free(OHCI_ED_v7c8824df8a);
    OHCI_ED_v7c8824df8a = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v4d10531072 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4d10531072[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7c8824df8a + 0x0, 0x4, (uint8_t *)v4d10531072);
    free(v4d10531072);
    uint32_t *v483ddff022 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v483ddff022[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7c8824df8a + 0x4, 0x4, (uint8_t *)v483ddff022);
    free(v483ddff022);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v9a3771fd7e_0; break;
        case 1: goto v9a3771fd7e_1; break;
    }
v9a3771fd7e_0:;
    stateful_free(OHCI_TD_va1343e764d);
    OHCI_TD_va1343e764d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vcccf1a40dc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcccf1a40dc[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va1343e764d + 0x0, 0x4, (uint8_t *)vcccf1a40dc);
    free(vcccf1a40dc);
    uint32_t *v4b5bd07a72 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4b5bd07a72[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va1343e764d + 0x4, 0x4, (uint8_t *)v4b5bd07a72);
    free(v4b5bd07a72);
    uint32_t *v90f52803ea = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v90f52803ea[i] = (uint32_t)(OHCI_TD_va1343e764d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va1343e764d + 0x8, 0x4, (uint8_t *)v90f52803ea);
    free(v90f52803ea);
    uint32_t *v948e0aed7f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v948e0aed7f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va1343e764d + 0xc, 0x4, (uint8_t *)v948e0aed7f);
    free(v948e0aed7f);
    uint32_t *vbf10c3ad65 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbf10c3ad65[i] = (uint32_t)(OHCI_TD_va1343e764d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7c8824df8a + 0x8, 0x4, (uint8_t *)vbf10c3ad65);
    free(vbf10c3ad65);
    goto v9a3771fd7e_out;
v9a3771fd7e_1:;
    stateful_free(OHCI_ISO_TD_v22ecfe7c30);
    OHCI_ISO_TD_v22ecfe7c30 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v1bd067bfc1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1bd067bfc1[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x0, 0x4, (uint8_t *)v1bd067bfc1);
    free(v1bd067bfc1);
    uint32_t *vb1664047d4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb1664047d4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x4, 0x4, (uint8_t *)vb1664047d4);
    free(vb1664047d4);
    uint32_t *vbc048c8307 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbc048c8307[i] = (uint32_t)(OHCI_ISO_TD_v22ecfe7c30 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x8, 0x4, (uint8_t *)vbc048c8307);
    free(vbc048c8307);
    uint32_t *v4cb16a57fc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4cb16a57fc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0xc, 0x4, (uint8_t *)v4cb16a57fc);
    free(v4cb16a57fc);
    stateful_free(buffer_v9af220eeae);
    buffer_v9af220eeae = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4d64435e52 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4d64435e52[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9af220eeae + 0x0, 0x100, (uint8_t *)v4d64435e52);
    free(v4d64435e52);
    uint32_t *v224a8edc86 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v224a8edc86[i] = (uint32_t)(buffer_v9af220eeae | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x10, 0x2, (uint8_t *)v224a8edc86);
    free(v224a8edc86);
    stateful_free(buffer_vb2eb8bd014);
    buffer_vb2eb8bd014 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf6b98e67ad = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf6b98e67ad[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb2eb8bd014 + 0x0, 0x100, (uint8_t *)vf6b98e67ad);
    free(vf6b98e67ad);
    uint32_t *vaa5738d280 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vaa5738d280[i] = (uint32_t)(buffer_vb2eb8bd014 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x12, 0x2, (uint8_t *)vaa5738d280);
    free(vaa5738d280);
    stateful_free(buffer_v263f2d6bd4);
    buffer_v263f2d6bd4 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v686e9a9f16 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v686e9a9f16[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v263f2d6bd4 + 0x0, 0x100, (uint8_t *)v686e9a9f16);
    free(v686e9a9f16);
    uint32_t *v3b0ff64c9a = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v3b0ff64c9a[i] = (uint32_t)(buffer_v263f2d6bd4 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x14, 0x2, (uint8_t *)v3b0ff64c9a);
    free(v3b0ff64c9a);
    stateful_free(buffer_ve65f6258e7);
    buffer_ve65f6258e7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v51994489cb = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v51994489cb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve65f6258e7 + 0x0, 0x100, (uint8_t *)v51994489cb);
    free(v51994489cb);
    uint32_t *v791894da77 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v791894da77[i] = (uint32_t)(buffer_ve65f6258e7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x16, 0x2, (uint8_t *)v791894da77);
    free(v791894da77);
    stateful_free(buffer_v103fa42755);
    buffer_v103fa42755 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v665a3ce89f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v665a3ce89f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v103fa42755 + 0x0, 0x100, (uint8_t *)v665a3ce89f);
    free(v665a3ce89f);
    uint32_t *vd8e297eaee = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vd8e297eaee[i] = (uint32_t)(buffer_v103fa42755 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x18, 0x2, (uint8_t *)vd8e297eaee);
    free(vd8e297eaee);
    stateful_free(buffer_v2fc78ef9f0);
    buffer_v2fc78ef9f0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1729e65b7a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1729e65b7a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2fc78ef9f0 + 0x0, 0x100, (uint8_t *)v1729e65b7a);
    free(v1729e65b7a);
    uint32_t *vf6f747c8fe = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf6f747c8fe[i] = (uint32_t)(buffer_v2fc78ef9f0 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x1a, 0x2, (uint8_t *)vf6f747c8fe);
    free(vf6f747c8fe);
    stateful_free(buffer_v580ca41b8e);
    buffer_v580ca41b8e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7af1dd3079 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7af1dd3079[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v580ca41b8e + 0x0, 0x100, (uint8_t *)v7af1dd3079);
    free(v7af1dd3079);
    uint32_t *v1f660771f0 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1f660771f0[i] = (uint32_t)(buffer_v580ca41b8e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x1c, 0x2, (uint8_t *)v1f660771f0);
    free(v1f660771f0);
    stateful_free(buffer_v434f829ac7);
    buffer_v434f829ac7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vef4aa7d752 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vef4aa7d752[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v434f829ac7 + 0x0, 0x100, (uint8_t *)vef4aa7d752);
    free(vef4aa7d752);
    uint32_t *v38b6c7cb04 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v38b6c7cb04[i] = (uint32_t)(buffer_v434f829ac7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v22ecfe7c30 + 0x1e, 0x2, (uint8_t *)v38b6c7cb04);
    free(v38b6c7cb04);
    uint32_t *vdf26602947 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdf26602947[i] = (uint32_t)(OHCI_ISO_TD_v22ecfe7c30 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7c8824df8a + 0x8, 0x4, (uint8_t *)vdf26602947);
    free(vdf26602947);
    goto v9a3771fd7e_out;
v9a3771fd7e_out:;
    uint32_t *v174ba2fb40 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v174ba2fb40[i] = (uint32_t)OHCI_ED_v7c8824df8a;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7c8824df8a + 0xc, 0x4, (uint8_t *)v174ba2fb40);
    free(v174ba2fb40);
    uint32_t *vb0517e5311 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb0517e5311[i] = (uint32_t)OHCI_ED_v7c8824df8a;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x38, 0x4, (uint8_t *)vb0517e5311);
    free(vb0517e5311);
    goto vdabccc8bab_out;
vdabccc8bab_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vce1776cc55_0; break;
    }
vce1776cc55_0:;
    stateful_free(OHCI_ED_vf2168e7fcb);
    OHCI_ED_vf2168e7fcb = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v42df10174e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v42df10174e[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf2168e7fcb + 0x0, 0x4, (uint8_t *)v42df10174e);
    free(v42df10174e);
    uint32_t *v50863f64ca = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v50863f64ca[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf2168e7fcb + 0x4, 0x4, (uint8_t *)v50863f64ca);
    free(v50863f64ca);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v98bdb2f9da_0; break;
        case 1: goto v98bdb2f9da_1; break;
    }
v98bdb2f9da_0:;
    stateful_free(OHCI_TD_va6001fcc0b);
    OHCI_TD_va6001fcc0b = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v11571285c6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v11571285c6[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va6001fcc0b + 0x0, 0x4, (uint8_t *)v11571285c6);
    free(v11571285c6);
    uint32_t *v23ae4b7711 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v23ae4b7711[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va6001fcc0b + 0x4, 0x4, (uint8_t *)v23ae4b7711);
    free(v23ae4b7711);
    uint32_t *v5d7645c5a9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5d7645c5a9[i] = (uint32_t)(OHCI_TD_va6001fcc0b & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va6001fcc0b + 0x8, 0x4, (uint8_t *)v5d7645c5a9);
    free(v5d7645c5a9);
    uint32_t *vff971a5fc2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vff971a5fc2[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va6001fcc0b + 0xc, 0x4, (uint8_t *)vff971a5fc2);
    free(vff971a5fc2);
    uint32_t *v1c3fe7fe96 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1c3fe7fe96[i] = (uint32_t)(OHCI_TD_va6001fcc0b & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf2168e7fcb + 0x8, 0x4, (uint8_t *)v1c3fe7fe96);
    free(v1c3fe7fe96);
    goto v98bdb2f9da_out;
v98bdb2f9da_1:;
    stateful_free(OHCI_ISO_TD_v1c535a6f26);
    OHCI_ISO_TD_v1c535a6f26 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vbe16683575 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbe16683575[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x0, 0x4, (uint8_t *)vbe16683575);
    free(vbe16683575);
    uint32_t *v742e93c351 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v742e93c351[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x4, 0x4, (uint8_t *)v742e93c351);
    free(v742e93c351);
    uint32_t *v150873fb5f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v150873fb5f[i] = (uint32_t)(OHCI_ISO_TD_v1c535a6f26 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x8, 0x4, (uint8_t *)v150873fb5f);
    free(v150873fb5f);
    uint32_t *v2c8720d496 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2c8720d496[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0xc, 0x4, (uint8_t *)v2c8720d496);
    free(v2c8720d496);
    stateful_free(buffer_v6e5073f819);
    buffer_v6e5073f819 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5cbf6a89b8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5cbf6a89b8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6e5073f819 + 0x0, 0x100, (uint8_t *)v5cbf6a89b8);
    free(v5cbf6a89b8);
    uint32_t *v405889cc68 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v405889cc68[i] = (uint32_t)(buffer_v6e5073f819 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x10, 0x2, (uint8_t *)v405889cc68);
    free(v405889cc68);
    stateful_free(buffer_va07a818eff);
    buffer_va07a818eff = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd17b9de27c = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd17b9de27c[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va07a818eff + 0x0, 0x100, (uint8_t *)vd17b9de27c);
    free(vd17b9de27c);
    uint32_t *vcdf22669b2 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vcdf22669b2[i] = (uint32_t)(buffer_va07a818eff | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x12, 0x2, (uint8_t *)vcdf22669b2);
    free(vcdf22669b2);
    stateful_free(buffer_v6bc52b829a);
    buffer_v6bc52b829a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8e6d8d4c35 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8e6d8d4c35[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6bc52b829a + 0x0, 0x100, (uint8_t *)v8e6d8d4c35);
    free(v8e6d8d4c35);
    uint32_t *v6d6149e617 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6d6149e617[i] = (uint32_t)(buffer_v6bc52b829a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x14, 0x2, (uint8_t *)v6d6149e617);
    free(v6d6149e617);
    stateful_free(buffer_v8a2ad47de3);
    buffer_v8a2ad47de3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v27fe1d5e47 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v27fe1d5e47[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8a2ad47de3 + 0x0, 0x100, (uint8_t *)v27fe1d5e47);
    free(v27fe1d5e47);
    uint32_t *va68e5166be = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va68e5166be[i] = (uint32_t)(buffer_v8a2ad47de3 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x16, 0x2, (uint8_t *)va68e5166be);
    free(va68e5166be);
    stateful_free(buffer_v4af81f2d76);
    buffer_v4af81f2d76 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9087d80589 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9087d80589[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v4af81f2d76 + 0x0, 0x100, (uint8_t *)v9087d80589);
    free(v9087d80589);
    uint32_t *v8cec15c4a9 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8cec15c4a9[i] = (uint32_t)(buffer_v4af81f2d76 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x18, 0x2, (uint8_t *)v8cec15c4a9);
    free(v8cec15c4a9);
    stateful_free(buffer_v2fd1bcb88e);
    buffer_v2fd1bcb88e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve3feb260a8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve3feb260a8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2fd1bcb88e + 0x0, 0x100, (uint8_t *)ve3feb260a8);
    free(ve3feb260a8);
    uint32_t *v332aae5293 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v332aae5293[i] = (uint32_t)(buffer_v2fd1bcb88e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x1a, 0x2, (uint8_t *)v332aae5293);
    free(v332aae5293);
    stateful_free(buffer_v3ef717bf53);
    buffer_v3ef717bf53 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v45ae2568e8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v45ae2568e8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3ef717bf53 + 0x0, 0x100, (uint8_t *)v45ae2568e8);
    free(v45ae2568e8);
    uint32_t *v539fffa80b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v539fffa80b[i] = (uint32_t)(buffer_v3ef717bf53 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x1c, 0x2, (uint8_t *)v539fffa80b);
    free(v539fffa80b);
    stateful_free(buffer_va5100cbb72);
    buffer_va5100cbb72 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4e7171bd41 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4e7171bd41[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va5100cbb72 + 0x0, 0x100, (uint8_t *)v4e7171bd41);
    free(v4e7171bd41);
    uint32_t *v880d1a358c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v880d1a358c[i] = (uint32_t)(buffer_va5100cbb72 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1c535a6f26 + 0x1e, 0x2, (uint8_t *)v880d1a358c);
    free(v880d1a358c);
    uint32_t *v3a115c0af8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3a115c0af8[i] = (uint32_t)(OHCI_ISO_TD_v1c535a6f26 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf2168e7fcb + 0x8, 0x4, (uint8_t *)v3a115c0af8);
    free(v3a115c0af8);
    goto v98bdb2f9da_out;
v98bdb2f9da_out:;
    uint32_t *v37064377b5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v37064377b5[i] = (uint32_t)OHCI_ED_vf2168e7fcb;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vf2168e7fcb + 0xc, 0x4, (uint8_t *)v37064377b5);
    free(v37064377b5);
    uint32_t *v1da9ec0c7c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1da9ec0c7c[i] = (uint32_t)OHCI_ED_vf2168e7fcb;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x3c, 0x4, (uint8_t *)v1da9ec0c7c);
    free(v1da9ec0c7c);
    goto vce1776cc55_out;
vce1776cc55_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vdadb9415f4_0; break;
    }
vdadb9415f4_0:;
    stateful_free(OHCI_ED_vaaf673a702);
    OHCI_ED_vaaf673a702 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v38808274da = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v38808274da[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vaaf673a702 + 0x0, 0x4, (uint8_t *)v38808274da);
    free(v38808274da);
    uint32_t *vbc17ab5cd1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbc17ab5cd1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vaaf673a702 + 0x4, 0x4, (uint8_t *)vbc17ab5cd1);
    free(vbc17ab5cd1);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v162bb3e445_0; break;
        case 1: goto v162bb3e445_1; break;
    }
v162bb3e445_0:;
    stateful_free(OHCI_TD_v5cc3f3d337);
    OHCI_TD_v5cc3f3d337 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v205a00502e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v205a00502e[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5cc3f3d337 + 0x0, 0x4, (uint8_t *)v205a00502e);
    free(v205a00502e);
    uint32_t *vfe3872e72d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfe3872e72d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5cc3f3d337 + 0x4, 0x4, (uint8_t *)vfe3872e72d);
    free(vfe3872e72d);
    uint32_t *v5f7e7cef49 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5f7e7cef49[i] = (uint32_t)(OHCI_TD_v5cc3f3d337 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5cc3f3d337 + 0x8, 0x4, (uint8_t *)v5f7e7cef49);
    free(v5f7e7cef49);
    uint32_t *vdac1b1eb45 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdac1b1eb45[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v5cc3f3d337 + 0xc, 0x4, (uint8_t *)vdac1b1eb45);
    free(vdac1b1eb45);
    uint32_t *v3e6d4342bc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3e6d4342bc[i] = (uint32_t)(OHCI_TD_v5cc3f3d337 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vaaf673a702 + 0x8, 0x4, (uint8_t *)v3e6d4342bc);
    free(v3e6d4342bc);
    goto v162bb3e445_out;
v162bb3e445_1:;
    stateful_free(OHCI_ISO_TD_v2d120dca5c);
    OHCI_ISO_TD_v2d120dca5c = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v9ecf6537b3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9ecf6537b3[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x0, 0x4, (uint8_t *)v9ecf6537b3);
    free(v9ecf6537b3);
    uint32_t *v9a5f138184 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9a5f138184[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x4, 0x4, (uint8_t *)v9a5f138184);
    free(v9a5f138184);
    uint32_t *ve069b1ed7a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve069b1ed7a[i] = (uint32_t)(OHCI_ISO_TD_v2d120dca5c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x8, 0x4, (uint8_t *)ve069b1ed7a);
    free(ve069b1ed7a);
    uint32_t *vd4d7d6087d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd4d7d6087d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0xc, 0x4, (uint8_t *)vd4d7d6087d);
    free(vd4d7d6087d);
    stateful_free(buffer_ved89e0536c);
    buffer_ved89e0536c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v59348ffc45 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v59348ffc45[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ved89e0536c + 0x0, 0x100, (uint8_t *)v59348ffc45);
    free(v59348ffc45);
    uint32_t *v7ce9d54c60 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7ce9d54c60[i] = (uint32_t)(buffer_ved89e0536c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x10, 0x2, (uint8_t *)v7ce9d54c60);
    free(v7ce9d54c60);
    stateful_free(buffer_v8d5a914df2);
    buffer_v8d5a914df2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf0061df7ed = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf0061df7ed[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8d5a914df2 + 0x0, 0x100, (uint8_t *)vf0061df7ed);
    free(vf0061df7ed);
    uint32_t *v1edaddfa34 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1edaddfa34[i] = (uint32_t)(buffer_v8d5a914df2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x12, 0x2, (uint8_t *)v1edaddfa34);
    free(v1edaddfa34);
    stateful_free(buffer_v7c42d128fa);
    buffer_v7c42d128fa = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v42ca9e07ff = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v42ca9e07ff[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7c42d128fa + 0x0, 0x100, (uint8_t *)v42ca9e07ff);
    free(v42ca9e07ff);
    uint32_t *vf1362868fc = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf1362868fc[i] = (uint32_t)(buffer_v7c42d128fa | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x14, 0x2, (uint8_t *)vf1362868fc);
    free(vf1362868fc);
    stateful_free(buffer_v53bdb5e7b8);
    buffer_v53bdb5e7b8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7a79987623 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7a79987623[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v53bdb5e7b8 + 0x0, 0x100, (uint8_t *)v7a79987623);
    free(v7a79987623);
    uint32_t *vfb900a8878 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vfb900a8878[i] = (uint32_t)(buffer_v53bdb5e7b8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x16, 0x2, (uint8_t *)vfb900a8878);
    free(vfb900a8878);
    stateful_free(buffer_v7b618a1265);
    buffer_v7b618a1265 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1062c870e8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1062c870e8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7b618a1265 + 0x0, 0x100, (uint8_t *)v1062c870e8);
    free(v1062c870e8);
    uint32_t *vcf68b3b709 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vcf68b3b709[i] = (uint32_t)(buffer_v7b618a1265 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x18, 0x2, (uint8_t *)vcf68b3b709);
    free(vcf68b3b709);
    stateful_free(buffer_ve0ed561160);
    buffer_ve0ed561160 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7d4f2b9bc4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7d4f2b9bc4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve0ed561160 + 0x0, 0x100, (uint8_t *)v7d4f2b9bc4);
    free(v7d4f2b9bc4);
    uint32_t *v6421109497 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6421109497[i] = (uint32_t)(buffer_ve0ed561160 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x1a, 0x2, (uint8_t *)v6421109497);
    free(v6421109497);
    stateful_free(buffer_vc27a8fb4e6);
    buffer_vc27a8fb4e6 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vdb64e22d42 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vdb64e22d42[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc27a8fb4e6 + 0x0, 0x100, (uint8_t *)vdb64e22d42);
    free(vdb64e22d42);
    uint32_t *vd381cff338 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vd381cff338[i] = (uint32_t)(buffer_vc27a8fb4e6 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x1c, 0x2, (uint8_t *)vd381cff338);
    free(vd381cff338);
    stateful_free(buffer_v8489b64757);
    buffer_v8489b64757 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v535cc1c822 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v535cc1c822[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8489b64757 + 0x0, 0x100, (uint8_t *)v535cc1c822);
    free(v535cc1c822);
    uint32_t *v4e427cbea7 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4e427cbea7[i] = (uint32_t)(buffer_v8489b64757 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v2d120dca5c + 0x1e, 0x2, (uint8_t *)v4e427cbea7);
    free(v4e427cbea7);
    uint32_t *v7b37d9845c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7b37d9845c[i] = (uint32_t)(OHCI_ISO_TD_v2d120dca5c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vaaf673a702 + 0x8, 0x4, (uint8_t *)v7b37d9845c);
    free(v7b37d9845c);
    goto v162bb3e445_out;
v162bb3e445_out:;
    uint32_t *v2ad58d2b30 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2ad58d2b30[i] = (uint32_t)OHCI_ED_vaaf673a702;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vaaf673a702 + 0xc, 0x4, (uint8_t *)v2ad58d2b30);
    free(v2ad58d2b30);
    uint32_t *ved426e37cd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ved426e37cd[i] = (uint32_t)OHCI_ED_vaaf673a702;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x40, 0x4, (uint8_t *)ved426e37cd);
    free(ved426e37cd);
    goto vdadb9415f4_out;
vdadb9415f4_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vf5509f90ed_0; break;
    }
vf5509f90ed_0:;
    stateful_free(OHCI_ED_v4e3dbc5834);
    OHCI_ED_v4e3dbc5834 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v321c5d36aa = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v321c5d36aa[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4e3dbc5834 + 0x0, 0x4, (uint8_t *)v321c5d36aa);
    free(v321c5d36aa);
    uint32_t *vd2b7284e60 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd2b7284e60[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4e3dbc5834 + 0x4, 0x4, (uint8_t *)vd2b7284e60);
    free(vd2b7284e60);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vcf4c37d7ef_0; break;
        case 1: goto vcf4c37d7ef_1; break;
    }
vcf4c37d7ef_0:;
    stateful_free(OHCI_TD_ve98748447d);
    OHCI_TD_ve98748447d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v880b36b39c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v880b36b39c[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_ve98748447d + 0x0, 0x4, (uint8_t *)v880b36b39c);
    free(v880b36b39c);
    uint32_t *v2acb078fa7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2acb078fa7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_ve98748447d + 0x4, 0x4, (uint8_t *)v2acb078fa7);
    free(v2acb078fa7);
    uint32_t *v5009f8120e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5009f8120e[i] = (uint32_t)(OHCI_TD_ve98748447d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_ve98748447d + 0x8, 0x4, (uint8_t *)v5009f8120e);
    free(v5009f8120e);
    uint32_t *v92de715901 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v92de715901[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_ve98748447d + 0xc, 0x4, (uint8_t *)v92de715901);
    free(v92de715901);
    uint32_t *vdd3f153d65 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdd3f153d65[i] = (uint32_t)(OHCI_TD_ve98748447d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4e3dbc5834 + 0x8, 0x4, (uint8_t *)vdd3f153d65);
    free(vdd3f153d65);
    goto vcf4c37d7ef_out;
vcf4c37d7ef_1:;
    stateful_free(OHCI_ISO_TD_v855001654c);
    OHCI_ISO_TD_v855001654c = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v5414fa2adc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5414fa2adc[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x0, 0x4, (uint8_t *)v5414fa2adc);
    free(v5414fa2adc);
    uint32_t *v76c8f230e5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v76c8f230e5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x4, 0x4, (uint8_t *)v76c8f230e5);
    free(v76c8f230e5);
    uint32_t *vb08364331d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb08364331d[i] = (uint32_t)(OHCI_ISO_TD_v855001654c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x8, 0x4, (uint8_t *)vb08364331d);
    free(vb08364331d);
    uint32_t *v40993c6592 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v40993c6592[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0xc, 0x4, (uint8_t *)v40993c6592);
    free(v40993c6592);
    stateful_free(buffer_vc6cd6e2277);
    buffer_vc6cd6e2277 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb13413f7bc = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb13413f7bc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc6cd6e2277 + 0x0, 0x100, (uint8_t *)vb13413f7bc);
    free(vb13413f7bc);
    uint32_t *v75e90e7534 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v75e90e7534[i] = (uint32_t)(buffer_vc6cd6e2277 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x10, 0x2, (uint8_t *)v75e90e7534);
    free(v75e90e7534);
    stateful_free(buffer_vc3e3e76f0c);
    buffer_vc3e3e76f0c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vcf9a762a43 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vcf9a762a43[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc3e3e76f0c + 0x0, 0x100, (uint8_t *)vcf9a762a43);
    free(vcf9a762a43);
    uint32_t *v30cc87902c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v30cc87902c[i] = (uint32_t)(buffer_vc3e3e76f0c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x12, 0x2, (uint8_t *)v30cc87902c);
    free(v30cc87902c);
    stateful_free(buffer_v36b9344039);
    buffer_v36b9344039 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc4b8cc8596 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc4b8cc8596[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v36b9344039 + 0x0, 0x100, (uint8_t *)vc4b8cc8596);
    free(vc4b8cc8596);
    uint32_t *vf80cf550cf = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf80cf550cf[i] = (uint32_t)(buffer_v36b9344039 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x14, 0x2, (uint8_t *)vf80cf550cf);
    free(vf80cf550cf);
    stateful_free(buffer_vc08b7027b8);
    buffer_vc08b7027b8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ved3a3126c5 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ved3a3126c5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc08b7027b8 + 0x0, 0x100, (uint8_t *)ved3a3126c5);
    free(ved3a3126c5);
    uint32_t *vce34d90b43 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vce34d90b43[i] = (uint32_t)(buffer_vc08b7027b8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x16, 0x2, (uint8_t *)vce34d90b43);
    free(vce34d90b43);
    stateful_free(buffer_v24d367fa23);
    buffer_v24d367fa23 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc964b10e7e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc964b10e7e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v24d367fa23 + 0x0, 0x100, (uint8_t *)vc964b10e7e);
    free(vc964b10e7e);
    uint32_t *va29ffeec67 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va29ffeec67[i] = (uint32_t)(buffer_v24d367fa23 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x18, 0x2, (uint8_t *)va29ffeec67);
    free(va29ffeec67);
    stateful_free(buffer_v543d2477c4);
    buffer_v543d2477c4 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v407e22ef92 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v407e22ef92[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v543d2477c4 + 0x0, 0x100, (uint8_t *)v407e22ef92);
    free(v407e22ef92);
    uint32_t *vff7bc2957c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vff7bc2957c[i] = (uint32_t)(buffer_v543d2477c4 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x1a, 0x2, (uint8_t *)vff7bc2957c);
    free(vff7bc2957c);
    stateful_free(buffer_v2ae1d099b4);
    buffer_v2ae1d099b4 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc3b9798b44 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc3b9798b44[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2ae1d099b4 + 0x0, 0x100, (uint8_t *)vc3b9798b44);
    free(vc3b9798b44);
    uint32_t *vebc6b92e63 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vebc6b92e63[i] = (uint32_t)(buffer_v2ae1d099b4 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x1c, 0x2, (uint8_t *)vebc6b92e63);
    free(vebc6b92e63);
    stateful_free(buffer_v6a593f9da8);
    buffer_v6a593f9da8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2827def9e1 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2827def9e1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6a593f9da8 + 0x0, 0x100, (uint8_t *)v2827def9e1);
    free(v2827def9e1);
    uint32_t *vbd74ccba4b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vbd74ccba4b[i] = (uint32_t)(buffer_v6a593f9da8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v855001654c + 0x1e, 0x2, (uint8_t *)vbd74ccba4b);
    free(vbd74ccba4b);
    uint32_t *v8f24b7a54f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8f24b7a54f[i] = (uint32_t)(OHCI_ISO_TD_v855001654c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4e3dbc5834 + 0x8, 0x4, (uint8_t *)v8f24b7a54f);
    free(v8f24b7a54f);
    goto vcf4c37d7ef_out;
vcf4c37d7ef_out:;
    uint32_t *v617271482b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v617271482b[i] = (uint32_t)OHCI_ED_v4e3dbc5834;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4e3dbc5834 + 0xc, 0x4, (uint8_t *)v617271482b);
    free(v617271482b);
    uint32_t *v58caf4ca95 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v58caf4ca95[i] = (uint32_t)OHCI_ED_v4e3dbc5834;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x44, 0x4, (uint8_t *)v58caf4ca95);
    free(v58caf4ca95);
    goto vf5509f90ed_out;
vf5509f90ed_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vb2eaa2fa54_0; break;
    }
vb2eaa2fa54_0:;
    stateful_free(OHCI_ED_v33c56230b2);
    OHCI_ED_v33c56230b2 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v1f44216901 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1f44216901[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v33c56230b2 + 0x0, 0x4, (uint8_t *)v1f44216901);
    free(v1f44216901);
    uint32_t *vad6ef23a71 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vad6ef23a71[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v33c56230b2 + 0x4, 0x4, (uint8_t *)vad6ef23a71);
    free(vad6ef23a71);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vc79b641cfd_0; break;
        case 1: goto vc79b641cfd_1; break;
    }
vc79b641cfd_0:;
    stateful_free(OHCI_TD_v197153114f);
    OHCI_TD_v197153114f = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vfdbb78af52 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfdbb78af52[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v197153114f + 0x0, 0x4, (uint8_t *)vfdbb78af52);
    free(vfdbb78af52);
    uint32_t *v8a2fb0455e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8a2fb0455e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v197153114f + 0x4, 0x4, (uint8_t *)v8a2fb0455e);
    free(v8a2fb0455e);
    uint32_t *vb837532660 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb837532660[i] = (uint32_t)(OHCI_TD_v197153114f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v197153114f + 0x8, 0x4, (uint8_t *)vb837532660);
    free(vb837532660);
    uint32_t *vc3aad4d327 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc3aad4d327[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v197153114f + 0xc, 0x4, (uint8_t *)vc3aad4d327);
    free(vc3aad4d327);
    uint32_t *v650d4f71ba = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v650d4f71ba[i] = (uint32_t)(OHCI_TD_v197153114f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v33c56230b2 + 0x8, 0x4, (uint8_t *)v650d4f71ba);
    free(v650d4f71ba);
    goto vc79b641cfd_out;
vc79b641cfd_1:;
    stateful_free(OHCI_ISO_TD_v1abf68e372);
    OHCI_ISO_TD_v1abf68e372 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *va4ec271c64 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va4ec271c64[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x0, 0x4, (uint8_t *)va4ec271c64);
    free(va4ec271c64);
    uint32_t *va71da35c38 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va71da35c38[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x4, 0x4, (uint8_t *)va71da35c38);
    free(va71da35c38);
    uint32_t *vddf5132482 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vddf5132482[i] = (uint32_t)(OHCI_ISO_TD_v1abf68e372 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x8, 0x4, (uint8_t *)vddf5132482);
    free(vddf5132482);
    uint32_t *v11707dad73 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v11707dad73[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0xc, 0x4, (uint8_t *)v11707dad73);
    free(v11707dad73);
    stateful_free(buffer_va177a5415b);
    buffer_va177a5415b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v86970dcd94 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v86970dcd94[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va177a5415b + 0x0, 0x100, (uint8_t *)v86970dcd94);
    free(v86970dcd94);
    uint32_t *v1281d72c5b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1281d72c5b[i] = (uint32_t)(buffer_va177a5415b | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x10, 0x2, (uint8_t *)v1281d72c5b);
    free(v1281d72c5b);
    stateful_free(buffer_v798655a910);
    buffer_v798655a910 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5de0444306 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5de0444306[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v798655a910 + 0x0, 0x100, (uint8_t *)v5de0444306);
    free(v5de0444306);
    uint32_t *v8ec2a28911 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8ec2a28911[i] = (uint32_t)(buffer_v798655a910 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x12, 0x2, (uint8_t *)v8ec2a28911);
    free(v8ec2a28911);
    stateful_free(buffer_v3993bbed23);
    buffer_v3993bbed23 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf01814a1ab = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf01814a1ab[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3993bbed23 + 0x0, 0x100, (uint8_t *)vf01814a1ab);
    free(vf01814a1ab);
    uint32_t *v8abdf2292b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8abdf2292b[i] = (uint32_t)(buffer_v3993bbed23 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x14, 0x2, (uint8_t *)v8abdf2292b);
    free(v8abdf2292b);
    stateful_free(buffer_va30c67dacd);
    buffer_va30c67dacd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va8b69a0d2e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va8b69a0d2e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va30c67dacd + 0x0, 0x100, (uint8_t *)va8b69a0d2e);
    free(va8b69a0d2e);
    uint32_t *v812030adbb = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v812030adbb[i] = (uint32_t)(buffer_va30c67dacd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x16, 0x2, (uint8_t *)v812030adbb);
    free(v812030adbb);
    stateful_free(buffer_vdc2033ea3a);
    buffer_vdc2033ea3a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *veedc166b18 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        veedc166b18[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdc2033ea3a + 0x0, 0x100, (uint8_t *)veedc166b18);
    free(veedc166b18);
    uint32_t *vef402c1fd9 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vef402c1fd9[i] = (uint32_t)(buffer_vdc2033ea3a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x18, 0x2, (uint8_t *)vef402c1fd9);
    free(vef402c1fd9);
    stateful_free(buffer_vf82611ea27);
    buffer_vf82611ea27 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va07300a1aa = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va07300a1aa[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf82611ea27 + 0x0, 0x100, (uint8_t *)va07300a1aa);
    free(va07300a1aa);
    uint32_t *v68b53b906d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v68b53b906d[i] = (uint32_t)(buffer_vf82611ea27 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x1a, 0x2, (uint8_t *)v68b53b906d);
    free(v68b53b906d);
    stateful_free(buffer_vbd8b149838);
    buffer_vbd8b149838 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vdebbfbb462 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vdebbfbb462[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vbd8b149838 + 0x0, 0x100, (uint8_t *)vdebbfbb462);
    free(vdebbfbb462);
    uint32_t *v6bf70c9b8e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6bf70c9b8e[i] = (uint32_t)(buffer_vbd8b149838 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x1c, 0x2, (uint8_t *)v6bf70c9b8e);
    free(v6bf70c9b8e);
    stateful_free(buffer_v79b23b8a06);
    buffer_v79b23b8a06 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v59602ff2cf = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v59602ff2cf[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v79b23b8a06 + 0x0, 0x100, (uint8_t *)v59602ff2cf);
    free(v59602ff2cf);
    uint32_t *vafe6fc0b91 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vafe6fc0b91[i] = (uint32_t)(buffer_v79b23b8a06 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v1abf68e372 + 0x1e, 0x2, (uint8_t *)vafe6fc0b91);
    free(vafe6fc0b91);
    uint32_t *v4de1d91396 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4de1d91396[i] = (uint32_t)(OHCI_ISO_TD_v1abf68e372 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v33c56230b2 + 0x8, 0x4, (uint8_t *)v4de1d91396);
    free(v4de1d91396);
    goto vc79b641cfd_out;
vc79b641cfd_out:;
    uint32_t *v622c93c952 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v622c93c952[i] = (uint32_t)OHCI_ED_v33c56230b2;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v33c56230b2 + 0xc, 0x4, (uint8_t *)v622c93c952);
    free(v622c93c952);
    uint32_t *v7de5c1a4f4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7de5c1a4f4[i] = (uint32_t)OHCI_ED_v33c56230b2;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x48, 0x4, (uint8_t *)v7de5c1a4f4);
    free(v7de5c1a4f4);
    goto vb2eaa2fa54_out;
vb2eaa2fa54_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v917f2264b2_0; break;
    }
v917f2264b2_0:;
    stateful_free(OHCI_ED_v6446fb8de8);
    OHCI_ED_v6446fb8de8 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v8f64a4bf63 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8f64a4bf63[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v6446fb8de8 + 0x0, 0x4, (uint8_t *)v8f64a4bf63);
    free(v8f64a4bf63);
    uint32_t *v8f9c21779d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8f9c21779d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v6446fb8de8 + 0x4, 0x4, (uint8_t *)v8f9c21779d);
    free(v8f9c21779d);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v18456911a3_0; break;
        case 1: goto v18456911a3_1; break;
    }
v18456911a3_0:;
    stateful_free(OHCI_TD_vebf10d9d4d);
    OHCI_TD_vebf10d9d4d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v7c0b237eb2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7c0b237eb2[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebf10d9d4d + 0x0, 0x4, (uint8_t *)v7c0b237eb2);
    free(v7c0b237eb2);
    uint32_t *v7b459c941e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7b459c941e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebf10d9d4d + 0x4, 0x4, (uint8_t *)v7b459c941e);
    free(v7b459c941e);
    uint32_t *v69f7d39d3a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v69f7d39d3a[i] = (uint32_t)(OHCI_TD_vebf10d9d4d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebf10d9d4d + 0x8, 0x4, (uint8_t *)v69f7d39d3a);
    free(v69f7d39d3a);
    uint32_t *v57a5c96547 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v57a5c96547[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vebf10d9d4d + 0xc, 0x4, (uint8_t *)v57a5c96547);
    free(v57a5c96547);
    uint32_t *v5fba3da9be = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5fba3da9be[i] = (uint32_t)(OHCI_TD_vebf10d9d4d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v6446fb8de8 + 0x8, 0x4, (uint8_t *)v5fba3da9be);
    free(v5fba3da9be);
    goto v18456911a3_out;
v18456911a3_1:;
    stateful_free(OHCI_ISO_TD_vf17f1f7bd9);
    OHCI_ISO_TD_vf17f1f7bd9 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v6b553b3483 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6b553b3483[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x0, 0x4, (uint8_t *)v6b553b3483);
    free(v6b553b3483);
    uint32_t *vcf1902c993 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcf1902c993[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x4, 0x4, (uint8_t *)vcf1902c993);
    free(vcf1902c993);
    uint32_t *ve427859371 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve427859371[i] = (uint32_t)(OHCI_ISO_TD_vf17f1f7bd9 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x8, 0x4, (uint8_t *)ve427859371);
    free(ve427859371);
    uint32_t *v154d6a81b1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v154d6a81b1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0xc, 0x4, (uint8_t *)v154d6a81b1);
    free(v154d6a81b1);
    stateful_free(buffer_v54d75568ea);
    buffer_v54d75568ea = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6b02209f34 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6b02209f34[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v54d75568ea + 0x0, 0x100, (uint8_t *)v6b02209f34);
    free(v6b02209f34);
    uint32_t *v414d303b29 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v414d303b29[i] = (uint32_t)(buffer_v54d75568ea | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x10, 0x2, (uint8_t *)v414d303b29);
    free(v414d303b29);
    stateful_free(buffer_vdff9677a71);
    buffer_vdff9677a71 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7c8f2ad4a7 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7c8f2ad4a7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdff9677a71 + 0x0, 0x100, (uint8_t *)v7c8f2ad4a7);
    free(v7c8f2ad4a7);
    uint32_t *v8fb3430483 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8fb3430483[i] = (uint32_t)(buffer_vdff9677a71 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x12, 0x2, (uint8_t *)v8fb3430483);
    free(v8fb3430483);
    stateful_free(buffer_vf2db191ab5);
    buffer_vf2db191ab5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va94e5440fe = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va94e5440fe[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf2db191ab5 + 0x0, 0x100, (uint8_t *)va94e5440fe);
    free(va94e5440fe);
    uint32_t *vdc5bb0839f = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vdc5bb0839f[i] = (uint32_t)(buffer_vf2db191ab5 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x14, 0x2, (uint8_t *)vdc5bb0839f);
    free(vdc5bb0839f);
    stateful_free(buffer_vd67d170a50);
    buffer_vd67d170a50 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4c1ffea547 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4c1ffea547[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd67d170a50 + 0x0, 0x100, (uint8_t *)v4c1ffea547);
    free(v4c1ffea547);
    uint32_t *veab03bfd94 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        veab03bfd94[i] = (uint32_t)(buffer_vd67d170a50 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x16, 0x2, (uint8_t *)veab03bfd94);
    free(veab03bfd94);
    stateful_free(buffer_vcc9ba7a06f);
    buffer_vcc9ba7a06f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb7c3186ca8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb7c3186ca8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vcc9ba7a06f + 0x0, 0x100, (uint8_t *)vb7c3186ca8);
    free(vb7c3186ca8);
    uint32_t *v94f7e2c386 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v94f7e2c386[i] = (uint32_t)(buffer_vcc9ba7a06f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x18, 0x2, (uint8_t *)v94f7e2c386);
    free(v94f7e2c386);
    stateful_free(buffer_v779d5f4a75);
    buffer_v779d5f4a75 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf2fbccf64f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf2fbccf64f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v779d5f4a75 + 0x0, 0x100, (uint8_t *)vf2fbccf64f);
    free(vf2fbccf64f);
    uint32_t *v7afd479d44 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7afd479d44[i] = (uint32_t)(buffer_v779d5f4a75 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x1a, 0x2, (uint8_t *)v7afd479d44);
    free(v7afd479d44);
    stateful_free(buffer_v6125477e8f);
    buffer_v6125477e8f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v13b9de465c = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v13b9de465c[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6125477e8f + 0x0, 0x100, (uint8_t *)v13b9de465c);
    free(v13b9de465c);
    uint32_t *vfe6e6f7068 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vfe6e6f7068[i] = (uint32_t)(buffer_v6125477e8f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x1c, 0x2, (uint8_t *)vfe6e6f7068);
    free(vfe6e6f7068);
    stateful_free(buffer_v36896dbef3);
    buffer_v36896dbef3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf9564013c6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf9564013c6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v36896dbef3 + 0x0, 0x100, (uint8_t *)vf9564013c6);
    free(vf9564013c6);
    uint32_t *vf29c8250d2 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vf29c8250d2[i] = (uint32_t)(buffer_v36896dbef3 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vf17f1f7bd9 + 0x1e, 0x2, (uint8_t *)vf29c8250d2);
    free(vf29c8250d2);
    uint32_t *vd51d7ba391 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd51d7ba391[i] = (uint32_t)(OHCI_ISO_TD_vf17f1f7bd9 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v6446fb8de8 + 0x8, 0x4, (uint8_t *)vd51d7ba391);
    free(vd51d7ba391);
    goto v18456911a3_out;
v18456911a3_out:;
    uint32_t *v67c132d7fe = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v67c132d7fe[i] = (uint32_t)OHCI_ED_v6446fb8de8;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v6446fb8de8 + 0xc, 0x4, (uint8_t *)v67c132d7fe);
    free(v67c132d7fe);
    uint32_t *v25700fb404 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v25700fb404[i] = (uint32_t)OHCI_ED_v6446fb8de8;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x4c, 0x4, (uint8_t *)v25700fb404);
    free(v25700fb404);
    goto v917f2264b2_out;
v917f2264b2_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vf242b8c2ba_0; break;
    }
vf242b8c2ba_0:;
    stateful_free(OHCI_ED_va4abf435e9);
    OHCI_ED_va4abf435e9 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vdc49cbdc27 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdc49cbdc27[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va4abf435e9 + 0x0, 0x4, (uint8_t *)vdc49cbdc27);
    free(vdc49cbdc27);
    uint32_t *v9c4a3aa7c9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9c4a3aa7c9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va4abf435e9 + 0x4, 0x4, (uint8_t *)v9c4a3aa7c9);
    free(v9c4a3aa7c9);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto ve3b3a13a2e_0; break;
        case 1: goto ve3b3a13a2e_1; break;
    }
ve3b3a13a2e_0:;
    stateful_free(OHCI_TD_v78f31f879f);
    OHCI_TD_v78f31f879f = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v9acb24c0e5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9acb24c0e5[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v78f31f879f + 0x0, 0x4, (uint8_t *)v9acb24c0e5);
    free(v9acb24c0e5);
    uint32_t *v80d983dbee = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v80d983dbee[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v78f31f879f + 0x4, 0x4, (uint8_t *)v80d983dbee);
    free(v80d983dbee);
    uint32_t *vd57ac7f9b1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd57ac7f9b1[i] = (uint32_t)(OHCI_TD_v78f31f879f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v78f31f879f + 0x8, 0x4, (uint8_t *)vd57ac7f9b1);
    free(vd57ac7f9b1);
    uint32_t *vcbbb534cd6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcbbb534cd6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v78f31f879f + 0xc, 0x4, (uint8_t *)vcbbb534cd6);
    free(vcbbb534cd6);
    uint32_t *v8557486551 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8557486551[i] = (uint32_t)(OHCI_TD_v78f31f879f & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va4abf435e9 + 0x8, 0x4, (uint8_t *)v8557486551);
    free(v8557486551);
    goto ve3b3a13a2e_out;
ve3b3a13a2e_1:;
    stateful_free(OHCI_ISO_TD_v8a7eec2666);
    OHCI_ISO_TD_v8a7eec2666 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vc3365c2df6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc3365c2df6[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x0, 0x4, (uint8_t *)vc3365c2df6);
    free(vc3365c2df6);
    uint32_t *v528d999b4c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v528d999b4c[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x4, 0x4, (uint8_t *)v528d999b4c);
    free(v528d999b4c);
    uint32_t *v146490eaa7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v146490eaa7[i] = (uint32_t)(OHCI_ISO_TD_v8a7eec2666 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x8, 0x4, (uint8_t *)v146490eaa7);
    free(v146490eaa7);
    uint32_t *v5426cd7418 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5426cd7418[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0xc, 0x4, (uint8_t *)v5426cd7418);
    free(v5426cd7418);
    stateful_free(buffer_v8c821a281c);
    buffer_v8c821a281c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4d88f85755 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4d88f85755[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8c821a281c + 0x0, 0x100, (uint8_t *)v4d88f85755);
    free(v4d88f85755);
    uint32_t *v467962302c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v467962302c[i] = (uint32_t)(buffer_v8c821a281c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x10, 0x2, (uint8_t *)v467962302c);
    free(v467962302c);
    stateful_free(buffer_v572b6fb3a2);
    buffer_v572b6fb3a2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v168caed2b3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v168caed2b3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v572b6fb3a2 + 0x0, 0x100, (uint8_t *)v168caed2b3);
    free(v168caed2b3);
    uint32_t *vc98fa9f91b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc98fa9f91b[i] = (uint32_t)(buffer_v572b6fb3a2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x12, 0x2, (uint8_t *)vc98fa9f91b);
    free(vc98fa9f91b);
    stateful_free(buffer_v44caafc8e4);
    buffer_v44caafc8e4 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vadd133dd04 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vadd133dd04[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v44caafc8e4 + 0x0, 0x100, (uint8_t *)vadd133dd04);
    free(vadd133dd04);
    uint32_t *v77ac0013f7 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v77ac0013f7[i] = (uint32_t)(buffer_v44caafc8e4 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x14, 0x2, (uint8_t *)v77ac0013f7);
    free(v77ac0013f7);
    stateful_free(buffer_v3a032c79cc);
    buffer_v3a032c79cc = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1039eeb9b9 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1039eeb9b9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3a032c79cc + 0x0, 0x100, (uint8_t *)v1039eeb9b9);
    free(v1039eeb9b9);
    uint32_t *v4ddd003c40 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4ddd003c40[i] = (uint32_t)(buffer_v3a032c79cc | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x16, 0x2, (uint8_t *)v4ddd003c40);
    free(v4ddd003c40);
    stateful_free(buffer_v720c1794f7);
    buffer_v720c1794f7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4ef21a71ff = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4ef21a71ff[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v720c1794f7 + 0x0, 0x100, (uint8_t *)v4ef21a71ff);
    free(v4ef21a71ff);
    uint32_t *vff82c6374c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vff82c6374c[i] = (uint32_t)(buffer_v720c1794f7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x18, 0x2, (uint8_t *)vff82c6374c);
    free(vff82c6374c);
    stateful_free(buffer_vcd82c8f33e);
    buffer_vcd82c8f33e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v36136ee5ad = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v36136ee5ad[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vcd82c8f33e + 0x0, 0x100, (uint8_t *)v36136ee5ad);
    free(v36136ee5ad);
    uint32_t *v735f78de3c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v735f78de3c[i] = (uint32_t)(buffer_vcd82c8f33e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x1a, 0x2, (uint8_t *)v735f78de3c);
    free(v735f78de3c);
    stateful_free(buffer_v852a4d4146);
    buffer_v852a4d4146 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve867a05d73 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve867a05d73[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v852a4d4146 + 0x0, 0x100, (uint8_t *)ve867a05d73);
    free(ve867a05d73);
    uint32_t *v9112eb1497 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9112eb1497[i] = (uint32_t)(buffer_v852a4d4146 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x1c, 0x2, (uint8_t *)v9112eb1497);
    free(v9112eb1497);
    stateful_free(buffer_v80f666f3f1);
    buffer_v80f666f3f1 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4a3f370a4e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4a3f370a4e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v80f666f3f1 + 0x0, 0x100, (uint8_t *)v4a3f370a4e);
    free(v4a3f370a4e);
    uint32_t *vfce0c19e8f = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vfce0c19e8f[i] = (uint32_t)(buffer_v80f666f3f1 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v8a7eec2666 + 0x1e, 0x2, (uint8_t *)vfce0c19e8f);
    free(vfce0c19e8f);
    uint32_t *vf7a651a728 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf7a651a728[i] = (uint32_t)(OHCI_ISO_TD_v8a7eec2666 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va4abf435e9 + 0x8, 0x4, (uint8_t *)vf7a651a728);
    free(vf7a651a728);
    goto ve3b3a13a2e_out;
ve3b3a13a2e_out:;
    uint32_t *vf661e7d913 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf661e7d913[i] = (uint32_t)OHCI_ED_va4abf435e9;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_va4abf435e9 + 0xc, 0x4, (uint8_t *)vf661e7d913);
    free(vf661e7d913);
    uint32_t *vfdd34c2f46 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfdd34c2f46[i] = (uint32_t)OHCI_ED_va4abf435e9;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x50, 0x4, (uint8_t *)vfdd34c2f46);
    free(vfdd34c2f46);
    goto vf242b8c2ba_out;
vf242b8c2ba_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v8b9445b0dc_0; break;
    }
v8b9445b0dc_0:;
    stateful_free(OHCI_ED_v3cece50348);
    OHCI_ED_v3cece50348 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v580710db13 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v580710db13[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v3cece50348 + 0x0, 0x4, (uint8_t *)v580710db13);
    free(v580710db13);
    uint32_t *ve3dc561d4e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve3dc561d4e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v3cece50348 + 0x4, 0x4, (uint8_t *)ve3dc561d4e);
    free(ve3dc561d4e);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v12226abffe_0; break;
        case 1: goto v12226abffe_1; break;
    }
v12226abffe_0:;
    stateful_free(OHCI_TD_v7f2ad8f742);
    OHCI_TD_v7f2ad8f742 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vdfdf76e091 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdfdf76e091[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7f2ad8f742 + 0x0, 0x4, (uint8_t *)vdfdf76e091);
    free(vdfdf76e091);
    uint32_t *v90723532d1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v90723532d1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7f2ad8f742 + 0x4, 0x4, (uint8_t *)v90723532d1);
    free(v90723532d1);
    uint32_t *v14f616d699 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v14f616d699[i] = (uint32_t)(OHCI_TD_v7f2ad8f742 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7f2ad8f742 + 0x8, 0x4, (uint8_t *)v14f616d699);
    free(v14f616d699);
    uint32_t *v7e54d4bfe3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7e54d4bfe3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v7f2ad8f742 + 0xc, 0x4, (uint8_t *)v7e54d4bfe3);
    free(v7e54d4bfe3);
    uint32_t *v3bbee89b4a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3bbee89b4a[i] = (uint32_t)(OHCI_TD_v7f2ad8f742 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v3cece50348 + 0x8, 0x4, (uint8_t *)v3bbee89b4a);
    free(v3bbee89b4a);
    goto v12226abffe_out;
v12226abffe_1:;
    stateful_free(OHCI_ISO_TD_v72ca86e053);
    OHCI_ISO_TD_v72ca86e053 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v3564183c41 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3564183c41[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x0, 0x4, (uint8_t *)v3564183c41);
    free(v3564183c41);
    uint32_t *va93117fd73 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va93117fd73[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x4, 0x4, (uint8_t *)va93117fd73);
    free(va93117fd73);
    uint32_t *v6fcc40a893 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6fcc40a893[i] = (uint32_t)(OHCI_ISO_TD_v72ca86e053 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x8, 0x4, (uint8_t *)v6fcc40a893);
    free(v6fcc40a893);
    uint32_t *v5f598ccbd2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5f598ccbd2[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0xc, 0x4, (uint8_t *)v5f598ccbd2);
    free(v5f598ccbd2);
    stateful_free(buffer_v7dc1df7ede);
    buffer_v7dc1df7ede = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf80d26141d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf80d26141d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7dc1df7ede + 0x0, 0x100, (uint8_t *)vf80d26141d);
    free(vf80d26141d);
    uint32_t *v6de9e514a4 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6de9e514a4[i] = (uint32_t)(buffer_v7dc1df7ede | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x10, 0x2, (uint8_t *)v6de9e514a4);
    free(v6de9e514a4);
    stateful_free(buffer_v930e597138);
    buffer_v930e597138 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3d2e6be08a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3d2e6be08a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v930e597138 + 0x0, 0x100, (uint8_t *)v3d2e6be08a);
    free(v3d2e6be08a);
    uint32_t *v6683cc720a = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6683cc720a[i] = (uint32_t)(buffer_v930e597138 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x12, 0x2, (uint8_t *)v6683cc720a);
    free(v6683cc720a);
    stateful_free(buffer_v892031d9ca);
    buffer_v892031d9ca = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v28b77bebc3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v28b77bebc3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v892031d9ca + 0x0, 0x100, (uint8_t *)v28b77bebc3);
    free(v28b77bebc3);
    uint32_t *v8b86606663 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8b86606663[i] = (uint32_t)(buffer_v892031d9ca | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x14, 0x2, (uint8_t *)v8b86606663);
    free(v8b86606663);
    stateful_free(buffer_veadb00b431);
    buffer_veadb00b431 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve499adc45a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve499adc45a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_veadb00b431 + 0x0, 0x100, (uint8_t *)ve499adc45a);
    free(ve499adc45a);
    uint32_t *vefc704ac0c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vefc704ac0c[i] = (uint32_t)(buffer_veadb00b431 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x16, 0x2, (uint8_t *)vefc704ac0c);
    free(vefc704ac0c);
    stateful_free(buffer_v7e355427f2);
    buffer_v7e355427f2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5873d7dcc6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5873d7dcc6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7e355427f2 + 0x0, 0x100, (uint8_t *)v5873d7dcc6);
    free(v5873d7dcc6);
    uint32_t *v855cfbc371 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v855cfbc371[i] = (uint32_t)(buffer_v7e355427f2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x18, 0x2, (uint8_t *)v855cfbc371);
    free(v855cfbc371);
    stateful_free(buffer_v3759de393a);
    buffer_v3759de393a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7a249dc724 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7a249dc724[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3759de393a + 0x0, 0x100, (uint8_t *)v7a249dc724);
    free(v7a249dc724);
    uint32_t *v4c7cde29e9 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4c7cde29e9[i] = (uint32_t)(buffer_v3759de393a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x1a, 0x2, (uint8_t *)v4c7cde29e9);
    free(v4c7cde29e9);
    stateful_free(buffer_v5d3b0600b1);
    buffer_v5d3b0600b1 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v35a76b6ecd = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v35a76b6ecd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5d3b0600b1 + 0x0, 0x100, (uint8_t *)v35a76b6ecd);
    free(v35a76b6ecd);
    uint32_t *v7265ec6850 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7265ec6850[i] = (uint32_t)(buffer_v5d3b0600b1 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x1c, 0x2, (uint8_t *)v7265ec6850);
    free(v7265ec6850);
    stateful_free(buffer_v6a8a2bbae6);
    buffer_v6a8a2bbae6 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v328c9d3607 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v328c9d3607[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6a8a2bbae6 + 0x0, 0x100, (uint8_t *)v328c9d3607);
    free(v328c9d3607);
    uint32_t *v7dc0aa3769 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7dc0aa3769[i] = (uint32_t)(buffer_v6a8a2bbae6 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v72ca86e053 + 0x1e, 0x2, (uint8_t *)v7dc0aa3769);
    free(v7dc0aa3769);
    uint32_t *vaf0555c207 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vaf0555c207[i] = (uint32_t)(OHCI_ISO_TD_v72ca86e053 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v3cece50348 + 0x8, 0x4, (uint8_t *)vaf0555c207);
    free(vaf0555c207);
    goto v12226abffe_out;
v12226abffe_out:;
    uint32_t *vf53c476759 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf53c476759[i] = (uint32_t)OHCI_ED_v3cece50348;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v3cece50348 + 0xc, 0x4, (uint8_t *)vf53c476759);
    free(vf53c476759);
    uint32_t *v469483da6d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v469483da6d[i] = (uint32_t)OHCI_ED_v3cece50348;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x54, 0x4, (uint8_t *)v469483da6d);
    free(v469483da6d);
    goto v8b9445b0dc_out;
v8b9445b0dc_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v79ce8060f0_0; break;
    }
v79ce8060f0_0:;
    stateful_free(OHCI_ED_v4651a753b7);
    OHCI_ED_v4651a753b7 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v61e7d3a1fc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v61e7d3a1fc[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4651a753b7 + 0x0, 0x4, (uint8_t *)v61e7d3a1fc);
    free(v61e7d3a1fc);
    uint32_t *v2acf4cc7a6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2acf4cc7a6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4651a753b7 + 0x4, 0x4, (uint8_t *)v2acf4cc7a6);
    free(v2acf4cc7a6);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vf91640413b_0; break;
        case 1: goto vf91640413b_1; break;
    }
vf91640413b_0:;
    stateful_free(OHCI_TD_v81bf29f647);
    OHCI_TD_v81bf29f647 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vc40c8b3934 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc40c8b3934[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v81bf29f647 + 0x0, 0x4, (uint8_t *)vc40c8b3934);
    free(vc40c8b3934);
    uint32_t *vd5a55e952d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd5a55e952d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v81bf29f647 + 0x4, 0x4, (uint8_t *)vd5a55e952d);
    free(vd5a55e952d);
    uint32_t *va0ff09bc18 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va0ff09bc18[i] = (uint32_t)(OHCI_TD_v81bf29f647 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v81bf29f647 + 0x8, 0x4, (uint8_t *)va0ff09bc18);
    free(va0ff09bc18);
    uint32_t *v4166d79574 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4166d79574[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v81bf29f647 + 0xc, 0x4, (uint8_t *)v4166d79574);
    free(v4166d79574);
    uint32_t *v8348071b62 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8348071b62[i] = (uint32_t)(OHCI_TD_v81bf29f647 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4651a753b7 + 0x8, 0x4, (uint8_t *)v8348071b62);
    free(v8348071b62);
    goto vf91640413b_out;
vf91640413b_1:;
    stateful_free(OHCI_ISO_TD_v30a3d00380);
    OHCI_ISO_TD_v30a3d00380 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vfcc2a13c95 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfcc2a13c95[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x0, 0x4, (uint8_t *)vfcc2a13c95);
    free(vfcc2a13c95);
    uint32_t *v7faec3ea7d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7faec3ea7d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x4, 0x4, (uint8_t *)v7faec3ea7d);
    free(v7faec3ea7d);
    uint32_t *vdbd16e383c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdbd16e383c[i] = (uint32_t)(OHCI_ISO_TD_v30a3d00380 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x8, 0x4, (uint8_t *)vdbd16e383c);
    free(vdbd16e383c);
    uint32_t *v459adf34e7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v459adf34e7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0xc, 0x4, (uint8_t *)v459adf34e7);
    free(v459adf34e7);
    stateful_free(buffer_vdb2be98296);
    buffer_vdb2be98296 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v59b322d766 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v59b322d766[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdb2be98296 + 0x0, 0x100, (uint8_t *)v59b322d766);
    free(v59b322d766);
    uint32_t *v1ce000f1e9 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1ce000f1e9[i] = (uint32_t)(buffer_vdb2be98296 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x10, 0x2, (uint8_t *)v1ce000f1e9);
    free(v1ce000f1e9);
    stateful_free(buffer_vec7fe3f69f);
    buffer_vec7fe3f69f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vae3da129a8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vae3da129a8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vec7fe3f69f + 0x0, 0x100, (uint8_t *)vae3da129a8);
    free(vae3da129a8);
    uint32_t *v53eaf309fb = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v53eaf309fb[i] = (uint32_t)(buffer_vec7fe3f69f | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x12, 0x2, (uint8_t *)v53eaf309fb);
    free(v53eaf309fb);
    stateful_free(buffer_v4ff38b57c4);
    buffer_v4ff38b57c4 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vdcd1613150 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vdcd1613150[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v4ff38b57c4 + 0x0, 0x100, (uint8_t *)vdcd1613150);
    free(vdcd1613150);
    uint32_t *v7a986548ec = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7a986548ec[i] = (uint32_t)(buffer_v4ff38b57c4 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x14, 0x2, (uint8_t *)v7a986548ec);
    free(v7a986548ec);
    stateful_free(buffer_v3df5b7057a);
    buffer_v3df5b7057a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v75875b551e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v75875b551e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3df5b7057a + 0x0, 0x100, (uint8_t *)v75875b551e);
    free(v75875b551e);
    uint32_t *v3546f0e932 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v3546f0e932[i] = (uint32_t)(buffer_v3df5b7057a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x16, 0x2, (uint8_t *)v3546f0e932);
    free(v3546f0e932);
    stateful_free(buffer_v453834c311);
    buffer_v453834c311 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v973e4b2e12 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v973e4b2e12[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v453834c311 + 0x0, 0x100, (uint8_t *)v973e4b2e12);
    free(v973e4b2e12);
    uint32_t *v4bf4e22d7b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4bf4e22d7b[i] = (uint32_t)(buffer_v453834c311 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x18, 0x2, (uint8_t *)v4bf4e22d7b);
    free(v4bf4e22d7b);
    stateful_free(buffer_va544614d80);
    buffer_va544614d80 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf894e613fc = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf894e613fc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va544614d80 + 0x0, 0x100, (uint8_t *)vf894e613fc);
    free(vf894e613fc);
    uint32_t *v12dab7a7f4 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v12dab7a7f4[i] = (uint32_t)(buffer_va544614d80 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x1a, 0x2, (uint8_t *)v12dab7a7f4);
    free(v12dab7a7f4);
    stateful_free(buffer_v83da76a00d);
    buffer_v83da76a00d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3d9bc759b5 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3d9bc759b5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v83da76a00d + 0x0, 0x100, (uint8_t *)v3d9bc759b5);
    free(v3d9bc759b5);
    uint32_t *v65d8f31bce = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v65d8f31bce[i] = (uint32_t)(buffer_v83da76a00d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x1c, 0x2, (uint8_t *)v65d8f31bce);
    free(v65d8f31bce);
    stateful_free(buffer_v36a7125b6b);
    buffer_v36a7125b6b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v71da6bda58 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v71da6bda58[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v36a7125b6b + 0x0, 0x100, (uint8_t *)v71da6bda58);
    free(v71da6bda58);
    uint32_t *ve44d557a93 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        ve44d557a93[i] = (uint32_t)(buffer_v36a7125b6b | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v30a3d00380 + 0x1e, 0x2, (uint8_t *)ve44d557a93);
    free(ve44d557a93);
    uint32_t *vc234d1ba95 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc234d1ba95[i] = (uint32_t)(OHCI_ISO_TD_v30a3d00380 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4651a753b7 + 0x8, 0x4, (uint8_t *)vc234d1ba95);
    free(vc234d1ba95);
    goto vf91640413b_out;
vf91640413b_out:;
    uint32_t *v32ee6eb3f6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v32ee6eb3f6[i] = (uint32_t)OHCI_ED_v4651a753b7;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v4651a753b7 + 0xc, 0x4, (uint8_t *)v32ee6eb3f6);
    free(v32ee6eb3f6);
    uint32_t *v7424a109d2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7424a109d2[i] = (uint32_t)OHCI_ED_v4651a753b7;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x58, 0x4, (uint8_t *)v7424a109d2);
    free(v7424a109d2);
    goto v79ce8060f0_out;
v79ce8060f0_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vc8fc4621be_0; break;
    }
vc8fc4621be_0:;
    stateful_free(OHCI_ED_vd230cc249a);
    OHCI_ED_vd230cc249a = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vd9c4022c5b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd9c4022c5b[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd230cc249a + 0x0, 0x4, (uint8_t *)vd9c4022c5b);
    free(vd9c4022c5b);
    uint32_t *vc20cabe644 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc20cabe644[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd230cc249a + 0x4, 0x4, (uint8_t *)vc20cabe644);
    free(vc20cabe644);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vbf905ec63b_0; break;
        case 1: goto vbf905ec63b_1; break;
    }
vbf905ec63b_0:;
    stateful_free(OHCI_TD_v2020678ba4);
    OHCI_TD_v2020678ba4 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vff480fa609 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vff480fa609[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2020678ba4 + 0x0, 0x4, (uint8_t *)vff480fa609);
    free(vff480fa609);
    uint32_t *vbfc736bb05 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbfc736bb05[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2020678ba4 + 0x4, 0x4, (uint8_t *)vbfc736bb05);
    free(vbfc736bb05);
    uint32_t *v8769ceb611 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8769ceb611[i] = (uint32_t)(OHCI_TD_v2020678ba4 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2020678ba4 + 0x8, 0x4, (uint8_t *)v8769ceb611);
    free(v8769ceb611);
    uint32_t *vf97bdeb136 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf97bdeb136[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2020678ba4 + 0xc, 0x4, (uint8_t *)vf97bdeb136);
    free(vf97bdeb136);
    uint32_t *ve9a76532b7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve9a76532b7[i] = (uint32_t)(OHCI_TD_v2020678ba4 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd230cc249a + 0x8, 0x4, (uint8_t *)ve9a76532b7);
    free(ve9a76532b7);
    goto vbf905ec63b_out;
vbf905ec63b_1:;
    stateful_free(OHCI_ISO_TD_vba7ed8625a);
    OHCI_ISO_TD_vba7ed8625a = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v31cc086aba = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v31cc086aba[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x0, 0x4, (uint8_t *)v31cc086aba);
    free(v31cc086aba);
    uint32_t *v543e68809c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v543e68809c[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x4, 0x4, (uint8_t *)v543e68809c);
    free(v543e68809c);
    uint32_t *v303a8ff64f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v303a8ff64f[i] = (uint32_t)(OHCI_ISO_TD_vba7ed8625a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x8, 0x4, (uint8_t *)v303a8ff64f);
    free(v303a8ff64f);
    uint32_t *v2c6fb7a29d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2c6fb7a29d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0xc, 0x4, (uint8_t *)v2c6fb7a29d);
    free(v2c6fb7a29d);
    stateful_free(buffer_va7044a36bd);
    buffer_va7044a36bd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vfb18e54e29 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vfb18e54e29[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va7044a36bd + 0x0, 0x100, (uint8_t *)vfb18e54e29);
    free(vfb18e54e29);
    uint32_t *v9e5ac45f54 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9e5ac45f54[i] = (uint32_t)(buffer_va7044a36bd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x10, 0x2, (uint8_t *)v9e5ac45f54);
    free(v9e5ac45f54);
    stateful_free(buffer_vc34451aaa9);
    buffer_vc34451aaa9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8adfeb12fc = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8adfeb12fc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc34451aaa9 + 0x0, 0x100, (uint8_t *)v8adfeb12fc);
    free(v8adfeb12fc);
    uint32_t *vd78d39d428 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vd78d39d428[i] = (uint32_t)(buffer_vc34451aaa9 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x12, 0x2, (uint8_t *)vd78d39d428);
    free(vd78d39d428);
    stateful_free(buffer_vfb1b8a22d2);
    buffer_vfb1b8a22d2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v53ad6d901a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v53ad6d901a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vfb1b8a22d2 + 0x0, 0x100, (uint8_t *)v53ad6d901a);
    free(v53ad6d901a);
    uint32_t *vba12fbbaa8 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vba12fbbaa8[i] = (uint32_t)(buffer_vfb1b8a22d2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x14, 0x2, (uint8_t *)vba12fbbaa8);
    free(vba12fbbaa8);
    stateful_free(buffer_v607f9817b5);
    buffer_v607f9817b5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8486297278 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8486297278[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v607f9817b5 + 0x0, 0x100, (uint8_t *)v8486297278);
    free(v8486297278);
    uint32_t *v13b468cb69 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v13b468cb69[i] = (uint32_t)(buffer_v607f9817b5 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x16, 0x2, (uint8_t *)v13b468cb69);
    free(v13b468cb69);
    stateful_free(buffer_vfe67076431);
    buffer_vfe67076431 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v55c2e7184d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v55c2e7184d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vfe67076431 + 0x0, 0x100, (uint8_t *)v55c2e7184d);
    free(v55c2e7184d);
    uint32_t *v4096c90949 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4096c90949[i] = (uint32_t)(buffer_vfe67076431 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x18, 0x2, (uint8_t *)v4096c90949);
    free(v4096c90949);
    stateful_free(buffer_vb6f1937c5c);
    buffer_vb6f1937c5c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6250f5801b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6250f5801b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb6f1937c5c + 0x0, 0x100, (uint8_t *)v6250f5801b);
    free(v6250f5801b);
    uint32_t *v5ffff5877d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5ffff5877d[i] = (uint32_t)(buffer_vb6f1937c5c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x1a, 0x2, (uint8_t *)v5ffff5877d);
    free(v5ffff5877d);
    stateful_free(buffer_v3de28d37e3);
    buffer_v3de28d37e3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4d9bdf4bf8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4d9bdf4bf8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3de28d37e3 + 0x0, 0x100, (uint8_t *)v4d9bdf4bf8);
    free(v4d9bdf4bf8);
    uint32_t *v35c08c0ea5 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v35c08c0ea5[i] = (uint32_t)(buffer_v3de28d37e3 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x1c, 0x2, (uint8_t *)v35c08c0ea5);
    free(v35c08c0ea5);
    stateful_free(buffer_v116ad00384);
    buffer_v116ad00384 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v897f636b87 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v897f636b87[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v116ad00384 + 0x0, 0x100, (uint8_t *)v897f636b87);
    free(v897f636b87);
    uint32_t *va67ce5ae4e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va67ce5ae4e[i] = (uint32_t)(buffer_v116ad00384 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vba7ed8625a + 0x1e, 0x2, (uint8_t *)va67ce5ae4e);
    free(va67ce5ae4e);
    uint32_t *v3989daadc3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3989daadc3[i] = (uint32_t)(OHCI_ISO_TD_vba7ed8625a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd230cc249a + 0x8, 0x4, (uint8_t *)v3989daadc3);
    free(v3989daadc3);
    goto vbf905ec63b_out;
vbf905ec63b_out:;
    uint32_t *v5af4d57892 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5af4d57892[i] = (uint32_t)OHCI_ED_vd230cc249a;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd230cc249a + 0xc, 0x4, (uint8_t *)v5af4d57892);
    free(v5af4d57892);
    uint32_t *v3e22e1e32e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3e22e1e32e[i] = (uint32_t)OHCI_ED_vd230cc249a;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x5c, 0x4, (uint8_t *)v3e22e1e32e);
    free(v3e22e1e32e);
    goto vc8fc4621be_out;
vc8fc4621be_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v703ed5b245_0; break;
    }
v703ed5b245_0:;
    stateful_free(OHCI_ED_vd49b9682d1);
    OHCI_ED_vd49b9682d1 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vc517a05fe0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc517a05fe0[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd49b9682d1 + 0x0, 0x4, (uint8_t *)vc517a05fe0);
    free(vc517a05fe0);
    uint32_t *v28313eaae8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v28313eaae8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd49b9682d1 + 0x4, 0x4, (uint8_t *)v28313eaae8);
    free(v28313eaae8);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v67c8031da5_0; break;
        case 1: goto v67c8031da5_1; break;
    }
v67c8031da5_0:;
    stateful_free(OHCI_TD_vddea1f018d);
    OHCI_TD_vddea1f018d = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v8b656a9595 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8b656a9595[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vddea1f018d + 0x0, 0x4, (uint8_t *)v8b656a9595);
    free(v8b656a9595);
    uint32_t *v20913668d3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v20913668d3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vddea1f018d + 0x4, 0x4, (uint8_t *)v20913668d3);
    free(v20913668d3);
    uint32_t *v8e579de890 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8e579de890[i] = (uint32_t)(OHCI_TD_vddea1f018d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vddea1f018d + 0x8, 0x4, (uint8_t *)v8e579de890);
    free(v8e579de890);
    uint32_t *v2706c9e802 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2706c9e802[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vddea1f018d + 0xc, 0x4, (uint8_t *)v2706c9e802);
    free(v2706c9e802);
    uint32_t *v8b06495bb4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8b06495bb4[i] = (uint32_t)(OHCI_TD_vddea1f018d & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd49b9682d1 + 0x8, 0x4, (uint8_t *)v8b06495bb4);
    free(v8b06495bb4);
    goto v67c8031da5_out;
v67c8031da5_1:;
    stateful_free(OHCI_ISO_TD_v42b0d4018c);
    OHCI_ISO_TD_v42b0d4018c = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v805385924e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v805385924e[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x0, 0x4, (uint8_t *)v805385924e);
    free(v805385924e);
    uint32_t *vac027db3a3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vac027db3a3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x4, 0x4, (uint8_t *)vac027db3a3);
    free(vac027db3a3);
    uint32_t *vdafa6f8daf = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdafa6f8daf[i] = (uint32_t)(OHCI_ISO_TD_v42b0d4018c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x8, 0x4, (uint8_t *)vdafa6f8daf);
    free(vdafa6f8daf);
    uint32_t *v5bbd2c0348 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5bbd2c0348[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0xc, 0x4, (uint8_t *)v5bbd2c0348);
    free(v5bbd2c0348);
    stateful_free(buffer_v30d50e4d83);
    buffer_v30d50e4d83 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v904d758703 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v904d758703[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v30d50e4d83 + 0x0, 0x100, (uint8_t *)v904d758703);
    free(v904d758703);
    uint32_t *v39aa6ce524 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v39aa6ce524[i] = (uint32_t)(buffer_v30d50e4d83 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x10, 0x2, (uint8_t *)v39aa6ce524);
    free(v39aa6ce524);
    stateful_free(buffer_v132c8de7fa);
    buffer_v132c8de7fa = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8b8521a548 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8b8521a548[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v132c8de7fa + 0x0, 0x100, (uint8_t *)v8b8521a548);
    free(v8b8521a548);
    uint32_t *va873032c3b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va873032c3b[i] = (uint32_t)(buffer_v132c8de7fa | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x12, 0x2, (uint8_t *)va873032c3b);
    free(va873032c3b);
    stateful_free(buffer_vfd99088383);
    buffer_vfd99088383 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6aae6115da = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6aae6115da[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vfd99088383 + 0x0, 0x100, (uint8_t *)v6aae6115da);
    free(v6aae6115da);
    uint32_t *v9a09e94a76 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9a09e94a76[i] = (uint32_t)(buffer_vfd99088383 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x14, 0x2, (uint8_t *)v9a09e94a76);
    free(v9a09e94a76);
    stateful_free(buffer_v8a05b7a5cc);
    buffer_v8a05b7a5cc = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va39ec2a1e3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va39ec2a1e3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8a05b7a5cc + 0x0, 0x100, (uint8_t *)va39ec2a1e3);
    free(va39ec2a1e3);
    uint32_t *v5563e45213 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5563e45213[i] = (uint32_t)(buffer_v8a05b7a5cc | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x16, 0x2, (uint8_t *)v5563e45213);
    free(v5563e45213);
    stateful_free(buffer_vdd452386ab);
    buffer_vdd452386ab = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vbbad57c155 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vbbad57c155[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdd452386ab + 0x0, 0x100, (uint8_t *)vbbad57c155);
    free(vbbad57c155);
    uint32_t *v378d6662d0 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v378d6662d0[i] = (uint32_t)(buffer_vdd452386ab | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x18, 0x2, (uint8_t *)v378d6662d0);
    free(v378d6662d0);
    stateful_free(buffer_vb83befd935);
    buffer_vb83befd935 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vef9b7be402 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vef9b7be402[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb83befd935 + 0x0, 0x100, (uint8_t *)vef9b7be402);
    free(vef9b7be402);
    uint32_t *va9361aa4f5 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va9361aa4f5[i] = (uint32_t)(buffer_vb83befd935 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x1a, 0x2, (uint8_t *)va9361aa4f5);
    free(va9361aa4f5);
    stateful_free(buffer_v224764ab98);
    buffer_v224764ab98 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf0cde3f6f6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf0cde3f6f6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v224764ab98 + 0x0, 0x100, (uint8_t *)vf0cde3f6f6);
    free(vf0cde3f6f6);
    uint32_t *vd23b8e0b91 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vd23b8e0b91[i] = (uint32_t)(buffer_v224764ab98 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x1c, 0x2, (uint8_t *)vd23b8e0b91);
    free(vd23b8e0b91);
    stateful_free(buffer_v9b5b4a99e8);
    buffer_v9b5b4a99e8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v87729f9805 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v87729f9805[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9b5b4a99e8 + 0x0, 0x100, (uint8_t *)v87729f9805);
    free(v87729f9805);
    uint32_t *v1190b6f4a4 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1190b6f4a4[i] = (uint32_t)(buffer_v9b5b4a99e8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v42b0d4018c + 0x1e, 0x2, (uint8_t *)v1190b6f4a4);
    free(v1190b6f4a4);
    uint32_t *vffe51196f3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vffe51196f3[i] = (uint32_t)(OHCI_ISO_TD_v42b0d4018c & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd49b9682d1 + 0x8, 0x4, (uint8_t *)vffe51196f3);
    free(vffe51196f3);
    goto v67c8031da5_out;
v67c8031da5_out:;
    uint32_t *ve83c1ccf51 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve83c1ccf51[i] = (uint32_t)OHCI_ED_vd49b9682d1;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vd49b9682d1 + 0xc, 0x4, (uint8_t *)ve83c1ccf51);
    free(ve83c1ccf51);
    uint32_t *v2d56cedcb3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2d56cedcb3[i] = (uint32_t)OHCI_ED_vd49b9682d1;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x60, 0x4, (uint8_t *)v2d56cedcb3);
    free(v2d56cedcb3);
    goto v703ed5b245_out;
v703ed5b245_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto ve83f24f342_0; break;
    }
ve83f24f342_0:;
    stateful_free(OHCI_ED_v198ccf7758);
    OHCI_ED_v198ccf7758 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v57789d1329 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v57789d1329[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v198ccf7758 + 0x0, 0x4, (uint8_t *)v57789d1329);
    free(v57789d1329);
    uint32_t *v2fced21410 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2fced21410[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v198ccf7758 + 0x4, 0x4, (uint8_t *)v2fced21410);
    free(v2fced21410);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v919d2dadcf_0; break;
        case 1: goto v919d2dadcf_1; break;
    }
v919d2dadcf_0:;
    stateful_free(OHCI_TD_va2de764cb1);
    OHCI_TD_va2de764cb1 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v699c8d2aec = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v699c8d2aec[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va2de764cb1 + 0x0, 0x4, (uint8_t *)v699c8d2aec);
    free(v699c8d2aec);
    uint32_t *v5c1defec13 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5c1defec13[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va2de764cb1 + 0x4, 0x4, (uint8_t *)v5c1defec13);
    free(v5c1defec13);
    uint32_t *ve3f77db3d5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve3f77db3d5[i] = (uint32_t)(OHCI_TD_va2de764cb1 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va2de764cb1 + 0x8, 0x4, (uint8_t *)ve3f77db3d5);
    free(ve3f77db3d5);
    uint32_t *v52504e1f89 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v52504e1f89[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_va2de764cb1 + 0xc, 0x4, (uint8_t *)v52504e1f89);
    free(v52504e1f89);
    uint32_t *vcc6bf5758f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcc6bf5758f[i] = (uint32_t)(OHCI_TD_va2de764cb1 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v198ccf7758 + 0x8, 0x4, (uint8_t *)vcc6bf5758f);
    free(vcc6bf5758f);
    goto v919d2dadcf_out;
v919d2dadcf_1:;
    stateful_free(OHCI_ISO_TD_v5787981e85);
    OHCI_ISO_TD_v5787981e85 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vaad37c52c5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vaad37c52c5[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x0, 0x4, (uint8_t *)vaad37c52c5);
    free(vaad37c52c5);
    uint32_t *v810ad697e4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v810ad697e4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x4, 0x4, (uint8_t *)v810ad697e4);
    free(v810ad697e4);
    uint32_t *v529d0a4025 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v529d0a4025[i] = (uint32_t)(OHCI_ISO_TD_v5787981e85 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x8, 0x4, (uint8_t *)v529d0a4025);
    free(v529d0a4025);
    uint32_t *vfc18fc2ab5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfc18fc2ab5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0xc, 0x4, (uint8_t *)vfc18fc2ab5);
    free(vfc18fc2ab5);
    stateful_free(buffer_v449c8ae871);
    buffer_v449c8ae871 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6757300d2d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6757300d2d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v449c8ae871 + 0x0, 0x100, (uint8_t *)v6757300d2d);
    free(v6757300d2d);
    uint32_t *v64b48964f7 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v64b48964f7[i] = (uint32_t)(buffer_v449c8ae871 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x10, 0x2, (uint8_t *)v64b48964f7);
    free(v64b48964f7);
    stateful_free(buffer_v6d9465c493);
    buffer_v6d9465c493 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2f92ec6200 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2f92ec6200[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6d9465c493 + 0x0, 0x100, (uint8_t *)v2f92ec6200);
    free(v2f92ec6200);
    uint32_t *v5eaa0b86fc = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5eaa0b86fc[i] = (uint32_t)(buffer_v6d9465c493 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x12, 0x2, (uint8_t *)v5eaa0b86fc);
    free(v5eaa0b86fc);
    stateful_free(buffer_va6570b8e9c);
    buffer_va6570b8e9c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd579ff0707 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd579ff0707[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va6570b8e9c + 0x0, 0x100, (uint8_t *)vd579ff0707);
    free(vd579ff0707);
    uint32_t *v32cf10fbc5 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v32cf10fbc5[i] = (uint32_t)(buffer_va6570b8e9c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x14, 0x2, (uint8_t *)v32cf10fbc5);
    free(v32cf10fbc5);
    stateful_free(buffer_vef689c46df);
    buffer_vef689c46df = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4ae7a23d11 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4ae7a23d11[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vef689c46df + 0x0, 0x100, (uint8_t *)v4ae7a23d11);
    free(v4ae7a23d11);
    uint32_t *vaaf60df0f0 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vaaf60df0f0[i] = (uint32_t)(buffer_vef689c46df | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x16, 0x2, (uint8_t *)vaaf60df0f0);
    free(vaaf60df0f0);
    stateful_free(buffer_v817ba6fb86);
    buffer_v817ba6fb86 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v735edef26e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v735edef26e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v817ba6fb86 + 0x0, 0x100, (uint8_t *)v735edef26e);
    free(v735edef26e);
    uint32_t *v997867a099 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v997867a099[i] = (uint32_t)(buffer_v817ba6fb86 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x18, 0x2, (uint8_t *)v997867a099);
    free(v997867a099);
    stateful_free(buffer_v3025825c7b);
    buffer_v3025825c7b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9f341d5858 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9f341d5858[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3025825c7b + 0x0, 0x100, (uint8_t *)v9f341d5858);
    free(v9f341d5858);
    uint32_t *v4408a55f33 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4408a55f33[i] = (uint32_t)(buffer_v3025825c7b | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x1a, 0x2, (uint8_t *)v4408a55f33);
    free(v4408a55f33);
    stateful_free(buffer_v6697e75298);
    buffer_v6697e75298 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va3e624b620 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va3e624b620[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6697e75298 + 0x0, 0x100, (uint8_t *)va3e624b620);
    free(va3e624b620);
    uint32_t *va57a902469 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va57a902469[i] = (uint32_t)(buffer_v6697e75298 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x1c, 0x2, (uint8_t *)va57a902469);
    free(va57a902469);
    stateful_free(buffer_vdaa38e0334);
    buffer_vdaa38e0334 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v788628fec4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v788628fec4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdaa38e0334 + 0x0, 0x100, (uint8_t *)v788628fec4);
    free(v788628fec4);
    uint32_t *v75c7f2f1cf = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v75c7f2f1cf[i] = (uint32_t)(buffer_vdaa38e0334 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5787981e85 + 0x1e, 0x2, (uint8_t *)v75c7f2f1cf);
    free(v75c7f2f1cf);
    uint32_t *vf6d707df3d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf6d707df3d[i] = (uint32_t)(OHCI_ISO_TD_v5787981e85 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v198ccf7758 + 0x8, 0x4, (uint8_t *)vf6d707df3d);
    free(vf6d707df3d);
    goto v919d2dadcf_out;
v919d2dadcf_out:;
    uint32_t *v1017a4a74f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1017a4a74f[i] = (uint32_t)OHCI_ED_v198ccf7758;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v198ccf7758 + 0xc, 0x4, (uint8_t *)v1017a4a74f);
    free(v1017a4a74f);
    uint32_t *v9427af7f00 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9427af7f00[i] = (uint32_t)OHCI_ED_v198ccf7758;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x64, 0x4, (uint8_t *)v9427af7f00);
    free(v9427af7f00);
    goto ve83f24f342_out;
ve83f24f342_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v7910dac4d5_0; break;
    }
v7910dac4d5_0:;
    stateful_free(OHCI_ED_v8addb6523f);
    OHCI_ED_v8addb6523f = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v4a72427e6f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4a72427e6f[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v8addb6523f + 0x0, 0x4, (uint8_t *)v4a72427e6f);
    free(v4a72427e6f);
    uint32_t *v9cbd0cea2d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9cbd0cea2d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v8addb6523f + 0x4, 0x4, (uint8_t *)v9cbd0cea2d);
    free(v9cbd0cea2d);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v9e8140868a_0; break;
        case 1: goto v9e8140868a_1; break;
    }
v9e8140868a_0:;
    stateful_free(OHCI_TD_v4e0e675098);
    OHCI_TD_v4e0e675098 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v1cfc494da2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1cfc494da2[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v4e0e675098 + 0x0, 0x4, (uint8_t *)v1cfc494da2);
    free(v1cfc494da2);
    uint32_t *v99ea16a30a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v99ea16a30a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v4e0e675098 + 0x4, 0x4, (uint8_t *)v99ea16a30a);
    free(v99ea16a30a);
    uint32_t *v9c3138503a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9c3138503a[i] = (uint32_t)(OHCI_TD_v4e0e675098 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v4e0e675098 + 0x8, 0x4, (uint8_t *)v9c3138503a);
    free(v9c3138503a);
    uint32_t *v40afa6282e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v40afa6282e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v4e0e675098 + 0xc, 0x4, (uint8_t *)v40afa6282e);
    free(v40afa6282e);
    uint32_t *v1b4c149abf = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1b4c149abf[i] = (uint32_t)(OHCI_TD_v4e0e675098 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v8addb6523f + 0x8, 0x4, (uint8_t *)v1b4c149abf);
    free(v1b4c149abf);
    goto v9e8140868a_out;
v9e8140868a_1:;
    stateful_free(OHCI_ISO_TD_vad8df616a8);
    OHCI_ISO_TD_vad8df616a8 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v1bcad0cfe7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1bcad0cfe7[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x0, 0x4, (uint8_t *)v1bcad0cfe7);
    free(v1bcad0cfe7);
    uint32_t *v6cc9870bd9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6cc9870bd9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x4, 0x4, (uint8_t *)v6cc9870bd9);
    free(v6cc9870bd9);
    uint32_t *v17829fd292 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v17829fd292[i] = (uint32_t)(OHCI_ISO_TD_vad8df616a8 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x8, 0x4, (uint8_t *)v17829fd292);
    free(v17829fd292);
    uint32_t *v23c1bb5f98 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v23c1bb5f98[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0xc, 0x4, (uint8_t *)v23c1bb5f98);
    free(v23c1bb5f98);
    stateful_free(buffer_ve203f9c388);
    buffer_ve203f9c388 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve1524bef77 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve1524bef77[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve203f9c388 + 0x0, 0x100, (uint8_t *)ve1524bef77);
    free(ve1524bef77);
    uint32_t *v4f3d72799f = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v4f3d72799f[i] = (uint32_t)(buffer_ve203f9c388 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x10, 0x2, (uint8_t *)v4f3d72799f);
    free(v4f3d72799f);
    stateful_free(buffer_va5a5aefffe);
    buffer_va5a5aefffe = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd4223731d1 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd4223731d1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va5a5aefffe + 0x0, 0x100, (uint8_t *)vd4223731d1);
    free(vd4223731d1);
    uint32_t *v7a6f103fb6 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7a6f103fb6[i] = (uint32_t)(buffer_va5a5aefffe | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x12, 0x2, (uint8_t *)v7a6f103fb6);
    free(v7a6f103fb6);
    stateful_free(buffer_va6d52a7a80);
    buffer_va6d52a7a80 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4c46efda7d = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4c46efda7d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va6d52a7a80 + 0x0, 0x100, (uint8_t *)v4c46efda7d);
    free(v4c46efda7d);
    uint32_t *v434e6aee1e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v434e6aee1e[i] = (uint32_t)(buffer_va6d52a7a80 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x14, 0x2, (uint8_t *)v434e6aee1e);
    free(v434e6aee1e);
    stateful_free(buffer_vcac819637c);
    buffer_vcac819637c = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v45e5521f95 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v45e5521f95[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vcac819637c + 0x0, 0x100, (uint8_t *)v45e5521f95);
    free(v45e5521f95);
    uint32_t *v3a005ab8d3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v3a005ab8d3[i] = (uint32_t)(buffer_vcac819637c | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x16, 0x2, (uint8_t *)v3a005ab8d3);
    free(v3a005ab8d3);
    stateful_free(buffer_v7ec284a5a2);
    buffer_v7ec284a5a2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8e0703a9db = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8e0703a9db[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7ec284a5a2 + 0x0, 0x100, (uint8_t *)v8e0703a9db);
    free(v8e0703a9db);
    uint32_t *v2f01acebf6 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v2f01acebf6[i] = (uint32_t)(buffer_v7ec284a5a2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x18, 0x2, (uint8_t *)v2f01acebf6);
    free(v2f01acebf6);
    stateful_free(buffer_v4d6e96ecf5);
    buffer_v4d6e96ecf5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v584a3f03d7 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v584a3f03d7[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v4d6e96ecf5 + 0x0, 0x100, (uint8_t *)v584a3f03d7);
    free(v584a3f03d7);
    uint32_t *vbadfeb8ae2 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vbadfeb8ae2[i] = (uint32_t)(buffer_v4d6e96ecf5 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x1a, 0x2, (uint8_t *)vbadfeb8ae2);
    free(vbadfeb8ae2);
    stateful_free(buffer_vbc6fc8847d);
    buffer_vbc6fc8847d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb880d6c6af = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb880d6c6af[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vbc6fc8847d + 0x0, 0x100, (uint8_t *)vb880d6c6af);
    free(vb880d6c6af);
    uint32_t *v5a87817412 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5a87817412[i] = (uint32_t)(buffer_vbc6fc8847d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x1c, 0x2, (uint8_t *)v5a87817412);
    free(v5a87817412);
    stateful_free(buffer_v462c8f33b4);
    buffer_v462c8f33b4 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5500391edf = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5500391edf[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v462c8f33b4 + 0x0, 0x100, (uint8_t *)v5500391edf);
    free(v5500391edf);
    uint32_t *v9a23162078 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9a23162078[i] = (uint32_t)(buffer_v462c8f33b4 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vad8df616a8 + 0x1e, 0x2, (uint8_t *)v9a23162078);
    free(v9a23162078);
    uint32_t *v47a1b02a4b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v47a1b02a4b[i] = (uint32_t)(OHCI_ISO_TD_vad8df616a8 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v8addb6523f + 0x8, 0x4, (uint8_t *)v47a1b02a4b);
    free(v47a1b02a4b);
    goto v9e8140868a_out;
v9e8140868a_out:;
    uint32_t *v7ce97c0be6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7ce97c0be6[i] = (uint32_t)OHCI_ED_v8addb6523f;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v8addb6523f + 0xc, 0x4, (uint8_t *)v7ce97c0be6);
    free(v7ce97c0be6);
    uint32_t *v778b7b7fcc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v778b7b7fcc[i] = (uint32_t)OHCI_ED_v8addb6523f;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x68, 0x4, (uint8_t *)v778b7b7fcc);
    free(v778b7b7fcc);
    goto v7910dac4d5_out;
v7910dac4d5_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto va09c7cac52_0; break;
    }
va09c7cac52_0:;
    stateful_free(OHCI_ED_ve0ae86d823);
    OHCI_ED_ve0ae86d823 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *ve7c705a87f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve7c705a87f[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_ve0ae86d823 + 0x0, 0x4, (uint8_t *)ve7c705a87f);
    free(ve7c705a87f);
    uint32_t *v6160ae89c0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6160ae89c0[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_ve0ae86d823 + 0x4, 0x4, (uint8_t *)v6160ae89c0);
    free(v6160ae89c0);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vcf39fc1d93_0; break;
        case 1: goto vcf39fc1d93_1; break;
    }
vcf39fc1d93_0:;
    stateful_free(OHCI_TD_vf9ad5698b7);
    OHCI_TD_vf9ad5698b7 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vaec1f57257 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vaec1f57257[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf9ad5698b7 + 0x0, 0x4, (uint8_t *)vaec1f57257);
    free(vaec1f57257);
    uint32_t *v486388e6a2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v486388e6a2[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf9ad5698b7 + 0x4, 0x4, (uint8_t *)v486388e6a2);
    free(v486388e6a2);
    uint32_t *va64bd2f422 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va64bd2f422[i] = (uint32_t)(OHCI_TD_vf9ad5698b7 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf9ad5698b7 + 0x8, 0x4, (uint8_t *)va64bd2f422);
    free(va64bd2f422);
    uint32_t *v329ff816db = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v329ff816db[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_vf9ad5698b7 + 0xc, 0x4, (uint8_t *)v329ff816db);
    free(v329ff816db);
    uint32_t *v1a2b34c4be = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1a2b34c4be[i] = (uint32_t)(OHCI_TD_vf9ad5698b7 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_ve0ae86d823 + 0x8, 0x4, (uint8_t *)v1a2b34c4be);
    free(v1a2b34c4be);
    goto vcf39fc1d93_out;
vcf39fc1d93_1:;
    stateful_free(OHCI_ISO_TD_va9ca68a2cb);
    OHCI_ISO_TD_va9ca68a2cb = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v4f92cce24a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4f92cce24a[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x0, 0x4, (uint8_t *)v4f92cce24a);
    free(v4f92cce24a);
    uint32_t *vfa04d54326 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfa04d54326[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x4, 0x4, (uint8_t *)vfa04d54326);
    free(vfa04d54326);
    uint32_t *va9eb2dcf92 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va9eb2dcf92[i] = (uint32_t)(OHCI_ISO_TD_va9ca68a2cb & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x8, 0x4, (uint8_t *)va9eb2dcf92);
    free(va9eb2dcf92);
    uint32_t *v6102d04bf4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6102d04bf4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0xc, 0x4, (uint8_t *)v6102d04bf4);
    free(v6102d04bf4);
    stateful_free(buffer_vf805d37998);
    buffer_vf805d37998 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v98e3b7e32e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v98e3b7e32e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf805d37998 + 0x0, 0x100, (uint8_t *)v98e3b7e32e);
    free(v98e3b7e32e);
    uint32_t *v7900b6a223 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7900b6a223[i] = (uint32_t)(buffer_vf805d37998 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x10, 0x2, (uint8_t *)v7900b6a223);
    free(v7900b6a223);
    stateful_free(buffer_vc666e2bc46);
    buffer_vc666e2bc46 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3478d5f411 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3478d5f411[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc666e2bc46 + 0x0, 0x100, (uint8_t *)v3478d5f411);
    free(v3478d5f411);
    uint32_t *v6105d18bec = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6105d18bec[i] = (uint32_t)(buffer_vc666e2bc46 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x12, 0x2, (uint8_t *)v6105d18bec);
    free(v6105d18bec);
    stateful_free(buffer_v859f6ccbdd);
    buffer_v859f6ccbdd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v324cfdb450 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v324cfdb450[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v859f6ccbdd + 0x0, 0x100, (uint8_t *)v324cfdb450);
    free(v324cfdb450);
    uint32_t *v1a415161f8 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1a415161f8[i] = (uint32_t)(buffer_v859f6ccbdd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x14, 0x2, (uint8_t *)v1a415161f8);
    free(v1a415161f8);
    stateful_free(buffer_vcfae9f72fd);
    buffer_vcfae9f72fd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v792c49d2dc = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v792c49d2dc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vcfae9f72fd + 0x0, 0x100, (uint8_t *)v792c49d2dc);
    free(v792c49d2dc);
    uint32_t *v6a992f0496 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6a992f0496[i] = (uint32_t)(buffer_vcfae9f72fd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x16, 0x2, (uint8_t *)v6a992f0496);
    free(v6a992f0496);
    stateful_free(buffer_v1b233b6876);
    buffer_v1b233b6876 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v98e0a2eb50 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v98e0a2eb50[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v1b233b6876 + 0x0, 0x100, (uint8_t *)v98e0a2eb50);
    free(v98e0a2eb50);
    uint32_t *v8b0e35a74d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v8b0e35a74d[i] = (uint32_t)(buffer_v1b233b6876 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x18, 0x2, (uint8_t *)v8b0e35a74d);
    free(v8b0e35a74d);
    stateful_free(buffer_v451e33f974);
    buffer_v451e33f974 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9c7d3eb1b8 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9c7d3eb1b8[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v451e33f974 + 0x0, 0x100, (uint8_t *)v9c7d3eb1b8);
    free(v9c7d3eb1b8);
    uint32_t *vd6b7e03fc5 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vd6b7e03fc5[i] = (uint32_t)(buffer_v451e33f974 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x1a, 0x2, (uint8_t *)vd6b7e03fc5);
    free(vd6b7e03fc5);
    stateful_free(buffer_v947f99a4cf);
    buffer_v947f99a4cf = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v998272e2a4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v998272e2a4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v947f99a4cf + 0x0, 0x100, (uint8_t *)v998272e2a4);
    free(v998272e2a4);
    uint32_t *v7187fe38e3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7187fe38e3[i] = (uint32_t)(buffer_v947f99a4cf | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x1c, 0x2, (uint8_t *)v7187fe38e3);
    free(v7187fe38e3);
    stateful_free(buffer_vaf3e52b174);
    buffer_vaf3e52b174 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb3eab86836 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb3eab86836[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vaf3e52b174 + 0x0, 0x100, (uint8_t *)vb3eab86836);
    free(vb3eab86836);
    uint32_t *vce2dab1de8 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vce2dab1de8[i] = (uint32_t)(buffer_vaf3e52b174 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_va9ca68a2cb + 0x1e, 0x2, (uint8_t *)vce2dab1de8);
    free(vce2dab1de8);
    uint32_t *vc66bd8b306 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc66bd8b306[i] = (uint32_t)(OHCI_ISO_TD_va9ca68a2cb & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_ve0ae86d823 + 0x8, 0x4, (uint8_t *)vc66bd8b306);
    free(vc66bd8b306);
    goto vcf39fc1d93_out;
vcf39fc1d93_out:;
    uint32_t *v67db566ac9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v67db566ac9[i] = (uint32_t)OHCI_ED_ve0ae86d823;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_ve0ae86d823 + 0xc, 0x4, (uint8_t *)v67db566ac9);
    free(v67db566ac9);
    uint32_t *v980008c04f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v980008c04f[i] = (uint32_t)OHCI_ED_ve0ae86d823;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x6c, 0x4, (uint8_t *)v980008c04f);
    free(v980008c04f);
    goto va09c7cac52_out;
va09c7cac52_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v878b9155dd_0; break;
    }
v878b9155dd_0:;
    stateful_free(OHCI_ED_vfad395bd32);
    OHCI_ED_vfad395bd32 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v63dcd686f7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v63dcd686f7[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vfad395bd32 + 0x0, 0x4, (uint8_t *)v63dcd686f7);
    free(v63dcd686f7);
    uint32_t *v51d4424f7e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v51d4424f7e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vfad395bd32 + 0x4, 0x4, (uint8_t *)v51d4424f7e);
    free(v51d4424f7e);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v73428e2c5d_0; break;
        case 1: goto v73428e2c5d_1; break;
    }
v73428e2c5d_0:;
    stateful_free(OHCI_TD_v1f66dbaf30);
    OHCI_TD_v1f66dbaf30 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v99c1da5cd1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v99c1da5cd1[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1f66dbaf30 + 0x0, 0x4, (uint8_t *)v99c1da5cd1);
    free(v99c1da5cd1);
    uint32_t *v7c342d3c4f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7c342d3c4f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1f66dbaf30 + 0x4, 0x4, (uint8_t *)v7c342d3c4f);
    free(v7c342d3c4f);
    uint32_t *v3994e2f4d6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3994e2f4d6[i] = (uint32_t)(OHCI_TD_v1f66dbaf30 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1f66dbaf30 + 0x8, 0x4, (uint8_t *)v3994e2f4d6);
    free(v3994e2f4d6);
    uint32_t *vae11d034e3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vae11d034e3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v1f66dbaf30 + 0xc, 0x4, (uint8_t *)vae11d034e3);
    free(vae11d034e3);
    uint32_t *v2a371f3e7a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2a371f3e7a[i] = (uint32_t)(OHCI_TD_v1f66dbaf30 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vfad395bd32 + 0x8, 0x4, (uint8_t *)v2a371f3e7a);
    free(v2a371f3e7a);
    goto v73428e2c5d_out;
v73428e2c5d_1:;
    stateful_free(OHCI_ISO_TD_v5fb95bd505);
    OHCI_ISO_TD_v5fb95bd505 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vb9af983de5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb9af983de5[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x0, 0x4, (uint8_t *)vb9af983de5);
    free(vb9af983de5);
    uint32_t *vdf8c795055 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vdf8c795055[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x4, 0x4, (uint8_t *)vdf8c795055);
    free(vdf8c795055);
    uint32_t *v536cbdc14b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v536cbdc14b[i] = (uint32_t)(OHCI_ISO_TD_v5fb95bd505 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x8, 0x4, (uint8_t *)v536cbdc14b);
    free(v536cbdc14b);
    uint32_t *v9ecef5dffa = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9ecef5dffa[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0xc, 0x4, (uint8_t *)v9ecef5dffa);
    free(v9ecef5dffa);
    stateful_free(buffer_vcf914d86d9);
    buffer_vcf914d86d9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8d43b6e8c9 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8d43b6e8c9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vcf914d86d9 + 0x0, 0x100, (uint8_t *)v8d43b6e8c9);
    free(v8d43b6e8c9);
    uint32_t *v451f58e67d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v451f58e67d[i] = (uint32_t)(buffer_vcf914d86d9 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x10, 0x2, (uint8_t *)v451f58e67d);
    free(v451f58e67d);
    stateful_free(buffer_v97518f0275);
    buffer_v97518f0275 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8ff6700895 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8ff6700895[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v97518f0275 + 0x0, 0x100, (uint8_t *)v8ff6700895);
    free(v8ff6700895);
    uint32_t *vbe6dfec383 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vbe6dfec383[i] = (uint32_t)(buffer_v97518f0275 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x12, 0x2, (uint8_t *)vbe6dfec383);
    free(vbe6dfec383);
    stateful_free(buffer_v5f495d01fa);
    buffer_v5f495d01fa = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vea1cae51a4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vea1cae51a4[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5f495d01fa + 0x0, 0x100, (uint8_t *)vea1cae51a4);
    free(vea1cae51a4);
    uint32_t *v7a05e64f2e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v7a05e64f2e[i] = (uint32_t)(buffer_v5f495d01fa | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x14, 0x2, (uint8_t *)v7a05e64f2e);
    free(v7a05e64f2e);
    stateful_free(buffer_v51800e3269);
    buffer_v51800e3269 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va49e88cbea = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va49e88cbea[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v51800e3269 + 0x0, 0x100, (uint8_t *)va49e88cbea);
    free(va49e88cbea);
    uint32_t *v423f75c772 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v423f75c772[i] = (uint32_t)(buffer_v51800e3269 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x16, 0x2, (uint8_t *)v423f75c772);
    free(v423f75c772);
    stateful_free(buffer_v5f03757ad2);
    buffer_v5f03757ad2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4912deee9b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4912deee9b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5f03757ad2 + 0x0, 0x100, (uint8_t *)v4912deee9b);
    free(v4912deee9b);
    uint32_t *v571e49cf8a = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v571e49cf8a[i] = (uint32_t)(buffer_v5f03757ad2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x18, 0x2, (uint8_t *)v571e49cf8a);
    free(v571e49cf8a);
    stateful_free(buffer_v27940daa14);
    buffer_v27940daa14 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vfed9402261 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vfed9402261[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v27940daa14 + 0x0, 0x100, (uint8_t *)vfed9402261);
    free(vfed9402261);
    uint32_t *v1f8103c0cc = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1f8103c0cc[i] = (uint32_t)(buffer_v27940daa14 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x1a, 0x2, (uint8_t *)v1f8103c0cc);
    free(v1f8103c0cc);
    stateful_free(buffer_v8a9e76e0ae);
    buffer_v8a9e76e0ae = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v213c05ef04 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v213c05ef04[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8a9e76e0ae + 0x0, 0x100, (uint8_t *)v213c05ef04);
    free(v213c05ef04);
    uint32_t *v3136a3fd08 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v3136a3fd08[i] = (uint32_t)(buffer_v8a9e76e0ae | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x1c, 0x2, (uint8_t *)v3136a3fd08);
    free(v3136a3fd08);
    stateful_free(buffer_v9c0bc5300e);
    buffer_v9c0bc5300e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va6ce08a57a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va6ce08a57a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9c0bc5300e + 0x0, 0x100, (uint8_t *)va6ce08a57a);
    free(va6ce08a57a);
    uint32_t *va9888fce9e = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va9888fce9e[i] = (uint32_t)(buffer_v9c0bc5300e | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v5fb95bd505 + 0x1e, 0x2, (uint8_t *)va9888fce9e);
    free(va9888fce9e);
    uint32_t *v722dff5536 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v722dff5536[i] = (uint32_t)(OHCI_ISO_TD_v5fb95bd505 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vfad395bd32 + 0x8, 0x4, (uint8_t *)v722dff5536);
    free(v722dff5536);
    goto v73428e2c5d_out;
v73428e2c5d_out:;
    uint32_t *v204cc7be57 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v204cc7be57[i] = (uint32_t)OHCI_ED_vfad395bd32;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_vfad395bd32 + 0xc, 0x4, (uint8_t *)v204cc7be57);
    free(v204cc7be57);
    uint32_t *v9e78a7ada7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9e78a7ada7[i] = (uint32_t)OHCI_ED_vfad395bd32;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x70, 0x4, (uint8_t *)v9e78a7ada7);
    free(v9e78a7ada7);
    goto v878b9155dd_out;
v878b9155dd_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v2fd1c22402_0; break;
    }
v2fd1c22402_0:;
    stateful_free(OHCI_ED_v444a2c1cf1);
    OHCI_ED_v444a2c1cf1 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v7c501df21a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7c501df21a[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v444a2c1cf1 + 0x0, 0x4, (uint8_t *)v7c501df21a);
    free(v7c501df21a);
    uint32_t *v99e26e6f7d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v99e26e6f7d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v444a2c1cf1 + 0x4, 0x4, (uint8_t *)v99e26e6f7d);
    free(v99e26e6f7d);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto v6d1c1cf714_0; break;
        case 1: goto v6d1c1cf714_1; break;
    }
v6d1c1cf714_0:;
    stateful_free(OHCI_TD_v2b46648c8b);
    OHCI_TD_v2b46648c8b = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v54298d3c7e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v54298d3c7e[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2b46648c8b + 0x0, 0x4, (uint8_t *)v54298d3c7e);
    free(v54298d3c7e);
    uint32_t *v226294face = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v226294face[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2b46648c8b + 0x4, 0x4, (uint8_t *)v226294face);
    free(v226294face);
    uint32_t *vb604b5641a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb604b5641a[i] = (uint32_t)(OHCI_TD_v2b46648c8b & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2b46648c8b + 0x8, 0x4, (uint8_t *)vb604b5641a);
    free(vb604b5641a);
    uint32_t *v5ab9a05677 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5ab9a05677[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2b46648c8b + 0xc, 0x4, (uint8_t *)v5ab9a05677);
    free(v5ab9a05677);
    uint32_t *v7c802f2d80 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7c802f2d80[i] = (uint32_t)(OHCI_TD_v2b46648c8b & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v444a2c1cf1 + 0x8, 0x4, (uint8_t *)v7c802f2d80);
    free(v7c802f2d80);
    goto v6d1c1cf714_out;
v6d1c1cf714_1:;
    stateful_free(OHCI_ISO_TD_vcd0c821849);
    OHCI_ISO_TD_vcd0c821849 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *ve674a802e0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve674a802e0[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x0, 0x4, (uint8_t *)ve674a802e0);
    free(ve674a802e0);
    uint32_t *v15af9dd43e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v15af9dd43e[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x4, 0x4, (uint8_t *)v15af9dd43e);
    free(v15af9dd43e);
    uint32_t *v5e0b77facf = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5e0b77facf[i] = (uint32_t)(OHCI_ISO_TD_vcd0c821849 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x8, 0x4, (uint8_t *)v5e0b77facf);
    free(v5e0b77facf);
    uint32_t *v449cbd26f3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v449cbd26f3[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0xc, 0x4, (uint8_t *)v449cbd26f3);
    free(v449cbd26f3);
    stateful_free(buffer_v2968f68dba);
    buffer_v2968f68dba = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v56012de62a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v56012de62a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2968f68dba + 0x0, 0x100, (uint8_t *)v56012de62a);
    free(v56012de62a);
    uint32_t *vb883744db2 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb883744db2[i] = (uint32_t)(buffer_v2968f68dba | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x10, 0x2, (uint8_t *)vb883744db2);
    free(vb883744db2);
    stateful_free(buffer_v69bc21862b);
    buffer_v69bc21862b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd0cc748a9b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd0cc748a9b[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v69bc21862b + 0x0, 0x100, (uint8_t *)vd0cc748a9b);
    free(vd0cc748a9b);
    uint32_t *v2fdd19c367 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v2fdd19c367[i] = (uint32_t)(buffer_v69bc21862b | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x12, 0x2, (uint8_t *)v2fdd19c367);
    free(v2fdd19c367);
    stateful_free(buffer_v794c3fe6ae);
    buffer_v794c3fe6ae = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v566a4f435a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v566a4f435a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v794c3fe6ae + 0x0, 0x100, (uint8_t *)v566a4f435a);
    free(v566a4f435a);
    uint32_t *v20e335fafa = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v20e335fafa[i] = (uint32_t)(buffer_v794c3fe6ae | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x14, 0x2, (uint8_t *)v20e335fafa);
    free(v20e335fafa);
    stateful_free(buffer_ve7200484c8);
    buffer_ve7200484c8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd7ba26c366 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd7ba26c366[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve7200484c8 + 0x0, 0x100, (uint8_t *)vd7ba26c366);
    free(vd7ba26c366);
    uint32_t *v89530adc1a = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v89530adc1a[i] = (uint32_t)(buffer_ve7200484c8 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x16, 0x2, (uint8_t *)v89530adc1a);
    free(v89530adc1a);
    stateful_free(buffer_v3d8cb0e830);
    buffer_v3d8cb0e830 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va25f19ec05 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va25f19ec05[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3d8cb0e830 + 0x0, 0x100, (uint8_t *)va25f19ec05);
    free(va25f19ec05);
    uint32_t *v6f4f868039 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6f4f868039[i] = (uint32_t)(buffer_v3d8cb0e830 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x18, 0x2, (uint8_t *)v6f4f868039);
    free(v6f4f868039);
    stateful_free(buffer_v9c28316775);
    buffer_v9c28316775 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va9b2fa44e9 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va9b2fa44e9[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9c28316775 + 0x0, 0x100, (uint8_t *)va9b2fa44e9);
    free(va9b2fa44e9);
    uint32_t *vc45d0ad218 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc45d0ad218[i] = (uint32_t)(buffer_v9c28316775 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x1a, 0x2, (uint8_t *)vc45d0ad218);
    free(vc45d0ad218);
    stateful_free(buffer_vd0bb3cbf29);
    buffer_vd0bb3cbf29 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vaceb6afff6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vaceb6afff6[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd0bb3cbf29 + 0x0, 0x100, (uint8_t *)vaceb6afff6);
    free(vaceb6afff6);
    uint32_t *veba9dc59da = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        veba9dc59da[i] = (uint32_t)(buffer_vd0bb3cbf29 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x1c, 0x2, (uint8_t *)veba9dc59da);
    free(veba9dc59da);
    stateful_free(buffer_v7b8e075cfe);
    buffer_v7b8e075cfe = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4f591e2f5a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4f591e2f5a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7b8e075cfe + 0x0, 0x100, (uint8_t *)v4f591e2f5a);
    free(v4f591e2f5a);
    uint32_t *v5f52734cbd = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v5f52734cbd[i] = (uint32_t)(buffer_v7b8e075cfe | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_vcd0c821849 + 0x1e, 0x2, (uint8_t *)v5f52734cbd);
    free(v5f52734cbd);
    uint32_t *v8d4cf0c268 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8d4cf0c268[i] = (uint32_t)(OHCI_ISO_TD_vcd0c821849 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v444a2c1cf1 + 0x8, 0x4, (uint8_t *)v8d4cf0c268);
    free(v8d4cf0c268);
    goto v6d1c1cf714_out;
v6d1c1cf714_out:;
    uint32_t *v22c3011d11 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v22c3011d11[i] = (uint32_t)OHCI_ED_v444a2c1cf1;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v444a2c1cf1 + 0xc, 0x4, (uint8_t *)v22c3011d11);
    free(v22c3011d11);
    uint32_t *vc6147c1ac5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc6147c1ac5[i] = (uint32_t)OHCI_ED_v444a2c1cf1;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x74, 0x4, (uint8_t *)vc6147c1ac5);
    free(vc6147c1ac5);
    goto v2fd1c22402_out;
v2fd1c22402_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v15e1bf52e0_0; break;
    }
v15e1bf52e0_0:;
    stateful_free(OHCI_ED_v518a7f151e);
    OHCI_ED_v518a7f151e = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v2bf2a27676 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2bf2a27676[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v518a7f151e + 0x0, 0x4, (uint8_t *)v2bf2a27676);
    free(v2bf2a27676);
    uint32_t *vcaf2a96ec1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcaf2a96ec1[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v518a7f151e + 0x4, 0x4, (uint8_t *)vcaf2a96ec1);
    free(vcaf2a96ec1);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vcfed7d2cea_0; break;
        case 1: goto vcfed7d2cea_1; break;
    }
vcfed7d2cea_0:;
    stateful_free(OHCI_TD_v88fb6be7c0);
    OHCI_TD_v88fb6be7c0 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *vc1b2537326 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc1b2537326[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v88fb6be7c0 + 0x0, 0x4, (uint8_t *)vc1b2537326);
    free(vc1b2537326);
    uint32_t *v6544110f5a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6544110f5a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v88fb6be7c0 + 0x4, 0x4, (uint8_t *)v6544110f5a);
    free(v6544110f5a);
    uint32_t *vaf6b661e6f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vaf6b661e6f[i] = (uint32_t)(OHCI_TD_v88fb6be7c0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v88fb6be7c0 + 0x8, 0x4, (uint8_t *)vaf6b661e6f);
    free(vaf6b661e6f);
    uint32_t *vbf107b31e0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbf107b31e0[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v88fb6be7c0 + 0xc, 0x4, (uint8_t *)vbf107b31e0);
    free(vbf107b31e0);
    uint32_t *v1e6b1da560 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1e6b1da560[i] = (uint32_t)(OHCI_TD_v88fb6be7c0 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v518a7f151e + 0x8, 0x4, (uint8_t *)v1e6b1da560);
    free(v1e6b1da560);
    goto vcfed7d2cea_out;
vcfed7d2cea_1:;
    stateful_free(OHCI_ISO_TD_v775153a32a);
    OHCI_ISO_TD_v775153a32a = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *veb33a802ff = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        veb33a802ff[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x0, 0x4, (uint8_t *)veb33a802ff);
    free(veb33a802ff);
    uint32_t *ve43a4e3c87 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve43a4e3c87[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x4, 0x4, (uint8_t *)ve43a4e3c87);
    free(ve43a4e3c87);
    uint32_t *v3b657e42c1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3b657e42c1[i] = (uint32_t)(OHCI_ISO_TD_v775153a32a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x8, 0x4, (uint8_t *)v3b657e42c1);
    free(v3b657e42c1);
    uint32_t *v594cdf2186 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v594cdf2186[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0xc, 0x4, (uint8_t *)v594cdf2186);
    free(v594cdf2186);
    stateful_free(buffer_v8f2a7695df);
    buffer_v8f2a7695df = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4b4ea80595 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4b4ea80595[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8f2a7695df + 0x0, 0x100, (uint8_t *)v4b4ea80595);
    free(v4b4ea80595);
    uint32_t *ve59634e87f = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        ve59634e87f[i] = (uint32_t)(buffer_v8f2a7695df | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x10, 0x2, (uint8_t *)ve59634e87f);
    free(ve59634e87f);
    stateful_free(buffer_v3dbb8662a2);
    buffer_v3dbb8662a2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v21e8cd29c5 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v21e8cd29c5[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3dbb8662a2 + 0x0, 0x100, (uint8_t *)v21e8cd29c5);
    free(v21e8cd29c5);
    uint32_t *vdf88531294 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vdf88531294[i] = (uint32_t)(buffer_v3dbb8662a2 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x12, 0x2, (uint8_t *)vdf88531294);
    free(vdf88531294);
    stateful_free(buffer_v12e844ce65);
    buffer_v12e844ce65 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vaa64ed0edd = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vaa64ed0edd[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v12e844ce65 + 0x0, 0x100, (uint8_t *)vaa64ed0edd);
    free(vaa64ed0edd);
    uint32_t *va1e365436c = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        va1e365436c[i] = (uint32_t)(buffer_v12e844ce65 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x14, 0x2, (uint8_t *)va1e365436c);
    free(va1e365436c);
    stateful_free(buffer_vd611d9988a);
    buffer_vd611d9988a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9f0640a8df = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9f0640a8df[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd611d9988a + 0x0, 0x100, (uint8_t *)v9f0640a8df);
    free(v9f0640a8df);
    uint32_t *v81f40fc9d8 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v81f40fc9d8[i] = (uint32_t)(buffer_vd611d9988a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x16, 0x2, (uint8_t *)v81f40fc9d8);
    free(v81f40fc9d8);
    stateful_free(buffer_v52322488cd);
    buffer_v52322488cd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve2e7559ecb = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve2e7559ecb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v52322488cd + 0x0, 0x100, (uint8_t *)ve2e7559ecb);
    free(ve2e7559ecb);
    uint32_t *v487eb1ae5d = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v487eb1ae5d[i] = (uint32_t)(buffer_v52322488cd | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x18, 0x2, (uint8_t *)v487eb1ae5d);
    free(v487eb1ae5d);
    stateful_free(buffer_vb4066fca2d);
    buffer_vb4066fca2d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9ae8abfabf = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9ae8abfabf[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb4066fca2d + 0x0, 0x100, (uint8_t *)v9ae8abfabf);
    free(v9ae8abfabf);
    uint32_t *v2aa5f53d04 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v2aa5f53d04[i] = (uint32_t)(buffer_vb4066fca2d | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x1a, 0x2, (uint8_t *)v2aa5f53d04);
    free(v2aa5f53d04);
    stateful_free(buffer_vdb199d02a9);
    buffer_vdb199d02a9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vee758b6f37 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vee758b6f37[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vdb199d02a9 + 0x0, 0x100, (uint8_t *)vee758b6f37);
    free(vee758b6f37);
    uint32_t *v64d52b0f86 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v64d52b0f86[i] = (uint32_t)(buffer_vdb199d02a9 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x1c, 0x2, (uint8_t *)v64d52b0f86);
    free(v64d52b0f86);
    stateful_free(buffer_v99f7987c16);
    buffer_v99f7987c16 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1b7f4a1155 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1b7f4a1155[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v99f7987c16 + 0x0, 0x100, (uint8_t *)v1b7f4a1155);
    free(v1b7f4a1155);
    uint32_t *vb79c4880f7 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vb79c4880f7[i] = (uint32_t)(buffer_v99f7987c16 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v775153a32a + 0x1e, 0x2, (uint8_t *)vb79c4880f7);
    free(vb79c4880f7);
    uint32_t *v15c65dffde = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v15c65dffde[i] = (uint32_t)(OHCI_ISO_TD_v775153a32a & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v518a7f151e + 0x8, 0x4, (uint8_t *)v15c65dffde);
    free(v15c65dffde);
    goto vcfed7d2cea_out;
vcfed7d2cea_out:;
    uint32_t *v80c21dd037 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v80c21dd037[i] = (uint32_t)OHCI_ED_v518a7f151e;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v518a7f151e + 0xc, 0x4, (uint8_t *)v80c21dd037);
    free(v80c21dd037);
    uint32_t *v756a89151b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v756a89151b[i] = (uint32_t)OHCI_ED_v518a7f151e;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x78, 0x4, (uint8_t *)v756a89151b);
    free(v756a89151b);
    goto v15e1bf52e0_out;
v15e1bf52e0_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v5cba8d548a_0; break;
    }
v5cba8d548a_0:;
    stateful_free(OHCI_ED_v7d32b0ec10);
    OHCI_ED_v7d32b0ec10 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v984aacec9c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v984aacec9c[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x05 + 1)) - 1)) << 0x05));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7d32b0ec10 + 0x0, 0x4, (uint8_t *)v984aacec9c);
    free(v984aacec9c);
    uint32_t *v836484fb04 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v836484fb04[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7d32b0ec10 + 0x4, 0x4, (uint8_t *)v836484fb04);
    free(v836484fb04);
    switch (get_data_from_pool4() % 2){ 
        case 0: goto vda2f037210_0; break;
        case 1: goto vda2f037210_1; break;
    }
vda2f037210_0:;
    stateful_free(OHCI_TD_v2abd003c82);
    OHCI_TD_v2abd003c82 = stateful_malloc(0x10, /*chained=*/false);
    uint32_t *v8f4fd140a5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8f4fd140a5[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2abd003c82 + 0x0, 0x4, (uint8_t *)v8f4fd140a5);
    free(v8f4fd140a5);
    uint32_t *vac619f9d8a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vac619f9d8a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2abd003c82 + 0x4, 0x4, (uint8_t *)vac619f9d8a);
    free(vac619f9d8a);
    uint32_t *v787035e9e2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v787035e9e2[i] = (uint32_t)(OHCI_TD_v2abd003c82 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2abd003c82 + 0x8, 0x4, (uint8_t *)v787035e9e2);
    free(v787035e9e2);
    uint32_t *v74fadadddc = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v74fadadddc[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_TD_v2abd003c82 + 0xc, 0x4, (uint8_t *)v74fadadddc);
    free(v74fadadddc);
    uint32_t *vc953200b4f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc953200b4f[i] = (uint32_t)(OHCI_TD_v2abd003c82 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7d32b0ec10 + 0x8, 0x4, (uint8_t *)vc953200b4f);
    free(vc953200b4f);
    goto vda2f037210_out;
vda2f037210_1:;
    stateful_free(OHCI_ISO_TD_v9ce15cff68);
    OHCI_ISO_TD_v9ce15cff68 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v9dd2282291 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9dd2282291[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x0, 0x4, (uint8_t *)v9dd2282291);
    free(v9dd2282291);
    uint32_t *vcf55288941 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcf55288941[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x4, 0x4, (uint8_t *)vcf55288941);
    free(vcf55288941);
    uint32_t *vb14833bc11 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb14833bc11[i] = (uint32_t)(OHCI_ISO_TD_v9ce15cff68 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x8, 0x4, (uint8_t *)vb14833bc11);
    free(vb14833bc11);
    uint32_t *v2ce32ebc5d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2ce32ebc5d[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0xc, 0x4, (uint8_t *)v2ce32ebc5d);
    free(v2ce32ebc5d);
    stateful_free(buffer_v11538536aa);
    buffer_v11538536aa = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3ee61b6e66 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3ee61b6e66[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v11538536aa + 0x0, 0x100, (uint8_t *)v3ee61b6e66);
    free(v3ee61b6e66);
    uint32_t *v931da828a4 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v931da828a4[i] = (uint32_t)(buffer_v11538536aa | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x10, 0x2, (uint8_t *)v931da828a4);
    free(v931da828a4);
    stateful_free(buffer_v83627d99e7);
    buffer_v83627d99e7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5372ba0b47 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5372ba0b47[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v83627d99e7 + 0x0, 0x100, (uint8_t *)v5372ba0b47);
    free(v5372ba0b47);
    uint32_t *v6d614db5a3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v6d614db5a3[i] = (uint32_t)(buffer_v83627d99e7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x12, 0x2, (uint8_t *)v6d614db5a3);
    free(v6d614db5a3);
    stateful_free(buffer_v442df22c12);
    buffer_v442df22c12 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1c82b86aeb = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1c82b86aeb[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v442df22c12 + 0x0, 0x100, (uint8_t *)v1c82b86aeb);
    free(v1c82b86aeb);
    uint32_t *vc02987ee51 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc02987ee51[i] = (uint32_t)(buffer_v442df22c12 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x14, 0x2, (uint8_t *)vc02987ee51);
    free(vc02987ee51);
    stateful_free(buffer_v880eaff06a);
    buffer_v880eaff06a = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7a855d5488 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7a855d5488[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v880eaff06a + 0x0, 0x100, (uint8_t *)v7a855d5488);
    free(v7a855d5488);
    uint32_t *vca278f2a48 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vca278f2a48[i] = (uint32_t)(buffer_v880eaff06a | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x16, 0x2, (uint8_t *)vca278f2a48);
    free(vca278f2a48);
    stateful_free(buffer_ve6a30b2173);
    buffer_ve6a30b2173 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc8bf5ae555 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc8bf5ae555[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve6a30b2173 + 0x0, 0x100, (uint8_t *)vc8bf5ae555);
    free(vc8bf5ae555);
    uint32_t *v9b8bf21893 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v9b8bf21893[i] = (uint32_t)(buffer_ve6a30b2173 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x18, 0x2, (uint8_t *)v9b8bf21893);
    free(v9b8bf21893);
    stateful_free(buffer_ved1ad3b263);
    buffer_ved1ad3b263 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2576d045ee = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2576d045ee[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ved1ad3b263 + 0x0, 0x100, (uint8_t *)v2576d045ee);
    free(v2576d045ee);
    uint32_t *v1f6f8369f3 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1f6f8369f3[i] = (uint32_t)(buffer_ved1ad3b263 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x1a, 0x2, (uint8_t *)v1f6f8369f3);
    free(v1f6f8369f3);
    stateful_free(buffer_vc4d81a2ef7);
    buffer_vc4d81a2ef7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5a4398da21 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5a4398da21[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc4d81a2ef7 + 0x0, 0x100, (uint8_t *)v5a4398da21);
    free(v5a4398da21);
    uint32_t *vc6d66516df = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vc6d66516df[i] = (uint32_t)(buffer_vc4d81a2ef7 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x1c, 0x2, (uint8_t *)vc6d66516df);
    free(vc6d66516df);
    stateful_free(buffer_v4410267314);
    buffer_v4410267314 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vab08d64a6f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vab08d64a6f[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v4410267314 + 0x0, 0x100, (uint8_t *)vab08d64a6f);
    free(vab08d64a6f);
    uint32_t *vee6b816a78 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        vee6b816a78[i] = (uint32_t)(buffer_v4410267314 | 0x0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ISO_TD_v9ce15cff68 + 0x1e, 0x2, (uint8_t *)vee6b816a78);
    free(vee6b816a78);
    uint32_t *v638f6535d2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v638f6535d2[i] = (uint32_t)(OHCI_ISO_TD_v9ce15cff68 & 0xfffffff0);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7d32b0ec10 + 0x8, 0x4, (uint8_t *)v638f6535d2);
    free(v638f6535d2);
    goto vda2f037210_out;
vda2f037210_out:;
    uint32_t *vd98513f905 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd98513f905[i] = (uint32_t)OHCI_ED_v7d32b0ec10;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, OHCI_ED_v7d32b0ec10 + 0xc, 0x4, (uint8_t *)vd98513f905);
    free(vd98513f905);
    uint32_t *v4dc7463086 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4dc7463086[i] = (uint32_t)OHCI_ED_v7d32b0ec10;
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x7c, 0x4, (uint8_t *)v4dc7463086);
    free(v4dc7463086);
    goto v5cba8d548a_out;
v5cba8d548a_out:;
    uint32_t *v1bb5ec4249 = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        v1bb5ec4249[i] = (uint32_t)get_data_from_pool2();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x80, 0x2, (uint8_t *)v1bb5ec4249);
    free(v1bb5ec4249);
    uint32_t *ved15ee1d3b = (uint32_t *)malloc(0x2);
    for (int i = 0; i < (0x2) / 4; i++)
        ved15ee1d3b[i] = (uint32_t)get_data_from_pool2();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x82, 0x2, (uint8_t *)ved15ee1d3b);
    free(ved15ee1d3b);
    uint32_t *v5a9d4c527a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5a9d4c527a[i] = (uint32_t)get_data_from_pool4();
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ohci_hcca_0 + 0x84, 0x4, (uint8_t *)v5a9d4c527a);
    free(v5a9d4c527a);
    uint64_t vbe2f069b99 = (ohci_hcca_0 & 0xffffff00);
    size_1 += serialize(Data, size_1, CALLBACK_MAXSIZE, get_interface_id("ohci", EVENT_TYPE_MMIO_WRITE), 0x18, 0x4, (uint8_t *)&vbe2f069b99);
    goto veb1912cb14_out;
veb1912cb14_out:;
    return Data;
}

static size_t get_size_1() { return size_1;}

// ==== hw/usb/hcd-ehci.c:ehci_state_waitlisthead:uint32_t entry = ============================
size_t size_2 = 0;

static uint64_t ehci_qh_0 = 0;
static uint64_t EHCIqtd_v3898686d0b = 0;
static uint64_t buffer_v1e8e008bd7 = 0;
static uint64_t buffer_v7d25aa6f67 = 0;
static uint64_t buffer_vc936caf9cb = 0;
static uint64_t buffer_vd0018fa30e = 0;
static uint64_t buffer_v54f0ca491e = 0;
static uint64_t EHCIqtd_ve4b6f1754e = 0;
static uint64_t buffer_v64b154496b = 0;
static uint64_t buffer_ve882134760 = 0;
static uint64_t buffer_v421a234bc2 = 0;
static uint64_t buffer_v117055fa31 = 0;
static uint64_t buffer_v8105bebeda = 0;
static uint64_t EHCIqtd_v36dad6093b = 0;
static uint64_t buffer_v41a3a9345f = 0;
static uint64_t buffer_vb074714a5d = 0;
static uint64_t buffer_v831318d1ca = 0;
static uint64_t buffer_v778e1891cd = 0;
static uint64_t buffer_v204d229ccc = 0;
static uint64_t buffer_v373ffe54c8 = 0;
static uint64_t buffer_v6c986537e2 = 0;
static uint64_t buffer_v7230a05070 = 0;
static uint64_t buffer_vd6172c8831 = 0;
static uint64_t buffer_v654729e961 = 0;

static uint8_t *get_data_2() {
    size_2 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    switch (get_data_from_pool4() % 1){ 
        case 0: goto ve327bcd893_0; break;
    }
ve327bcd893_0:;
    stateful_free(ehci_qh_0);
    ehci_qh_0 = stateful_malloc(0x30, /*chained=*/false);
    uint32_t *v290450a367 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v290450a367[i] = (uint32_t)((ehci_qh_0 & 0xffffffe0) | 0x1);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x0, 0x4, (uint8_t *)v290450a367);
    free(v290450a367);
    uint32_t *va48af44e5f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va48af44e5f[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x4, 0x4, (uint8_t *)va48af44e5f);
    free(va48af44e5f);
    uint32_t *v5a475a976a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5a475a976a[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02));
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x8, 0x4, (uint8_t *)v5a475a976a);
    free(v5a475a976a);
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v98cb2d736d_0; break;
    }
v98cb2d736d_0:;
    stateful_free(EHCIqtd_v3898686d0b);
    EHCIqtd_v3898686d0b = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vfd097669e7 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfd097669e7[i] = (uint32_t)((EHCIqtd_v3898686d0b & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0x0, 0x4, (uint8_t *)vfd097669e7);
    free(vfd097669e7);
    uint32_t *v63680af216 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v63680af216[i] = (uint32_t)((EHCIqtd_v3898686d0b & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0x4, 0x4, (uint8_t *)v63680af216);
    free(v63680af216);
    uint32_t *vcd78009e7f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcd78009e7f[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0x8, 0x4, (uint8_t *)vcd78009e7f);
    free(vcd78009e7f);
    stateful_free(buffer_v1e8e008bd7);
    buffer_v1e8e008bd7 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v6fa28149d4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v6fa28149d4[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v1e8e008bd7 + 0x0, 0x100, (uint8_t *)v6fa28149d4);
    free(v6fa28149d4);
    uint32_t *v5ee78227d2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5ee78227d2[i] = (uint32_t)(buffer_v1e8e008bd7 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0xc, 0x4, (uint8_t *)v5ee78227d2);
    free(v5ee78227d2);
    stateful_free(buffer_v7d25aa6f67);
    buffer_v7d25aa6f67 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v8bc4f5b30b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v8bc4f5b30b[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7d25aa6f67 + 0x0, 0x100, (uint8_t *)v8bc4f5b30b);
    free(v8bc4f5b30b);
    uint32_t *vde4f51cc17 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vde4f51cc17[i] = (uint32_t)(buffer_v7d25aa6f67 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0x10, 0x4, (uint8_t *)vde4f51cc17);
    free(vde4f51cc17);
    stateful_free(buffer_vc936caf9cb);
    buffer_vc936caf9cb = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v2e23a916b1 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v2e23a916b1[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vc936caf9cb + 0x0, 0x100, (uint8_t *)v2e23a916b1);
    free(v2e23a916b1);
    uint32_t *vf38b7c500a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf38b7c500a[i] = (uint32_t)(buffer_vc936caf9cb | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0x14, 0x4, (uint8_t *)vf38b7c500a);
    free(vf38b7c500a);
    stateful_free(buffer_vd0018fa30e);
    buffer_vd0018fa30e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7fcd89c1d4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7fcd89c1d4[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd0018fa30e + 0x0, 0x100, (uint8_t *)v7fcd89c1d4);
    free(v7fcd89c1d4);
    uint32_t *vc32eb5f662 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc32eb5f662[i] = (uint32_t)(buffer_vd0018fa30e | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0x18, 0x4, (uint8_t *)vc32eb5f662);
    free(vc32eb5f662);
    stateful_free(buffer_v54f0ca491e);
    buffer_v54f0ca491e = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vfac64044ed = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vfac64044ed[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v54f0ca491e + 0x0, 0x100, (uint8_t *)vfac64044ed);
    free(vfac64044ed);
    uint32_t *vd5462271a9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd5462271a9[i] = (uint32_t)(buffer_v54f0ca491e | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v3898686d0b + 0x1c, 0x4, (uint8_t *)vd5462271a9);
    free(vd5462271a9);
    uint32_t *v195a1274c9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v195a1274c9[i] = (uint32_t)((EHCIqtd_v3898686d0b & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0xc, 0x4, (uint8_t *)v195a1274c9);
    free(v195a1274c9);
    goto v98cb2d736d_out;
v98cb2d736d_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vc4226d141a_0; break;
    }
vc4226d141a_0:;
    stateful_free(EHCIqtd_ve4b6f1754e);
    EHCIqtd_ve4b6f1754e = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v7307ea5f16 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7307ea5f16[i] = (uint32_t)((EHCIqtd_ve4b6f1754e & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0x0, 0x4, (uint8_t *)v7307ea5f16);
    free(v7307ea5f16);
    uint32_t *vf05717be8b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf05717be8b[i] = (uint32_t)((EHCIqtd_ve4b6f1754e & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0x4, 0x4, (uint8_t *)vf05717be8b);
    free(vf05717be8b);
    uint32_t *va5135b0f09 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va5135b0f09[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0x8, 0x4, (uint8_t *)va5135b0f09);
    free(va5135b0f09);
    stateful_free(buffer_v64b154496b);
    buffer_v64b154496b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va1574ba585 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va1574ba585[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v64b154496b + 0x0, 0x100, (uint8_t *)va1574ba585);
    free(va1574ba585);
    uint32_t *vfa7268f495 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfa7268f495[i] = (uint32_t)(buffer_v64b154496b | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0xc, 0x4, (uint8_t *)vfa7268f495);
    free(vfa7268f495);
    stateful_free(buffer_ve882134760);
    buffer_ve882134760 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v1a6440c578 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v1a6440c578[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve882134760 + 0x0, 0x100, (uint8_t *)v1a6440c578);
    free(v1a6440c578);
    uint32_t *v332cecd277 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v332cecd277[i] = (uint32_t)(buffer_ve882134760 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0x10, 0x4, (uint8_t *)v332cecd277);
    free(v332cecd277);
    stateful_free(buffer_v421a234bc2);
    buffer_v421a234bc2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v87638d57f1 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v87638d57f1[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v421a234bc2 + 0x0, 0x100, (uint8_t *)v87638d57f1);
    free(v87638d57f1);
    uint32_t *v4494ae2da9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4494ae2da9[i] = (uint32_t)(buffer_v421a234bc2 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0x14, 0x4, (uint8_t *)v4494ae2da9);
    free(v4494ae2da9);
    stateful_free(buffer_v117055fa31);
    buffer_v117055fa31 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va18cf210d6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va18cf210d6[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v117055fa31 + 0x0, 0x100, (uint8_t *)va18cf210d6);
    free(va18cf210d6);
    uint32_t *ve210382a9b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve210382a9b[i] = (uint32_t)(buffer_v117055fa31 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0x18, 0x4, (uint8_t *)ve210382a9b);
    free(ve210382a9b);
    stateful_free(buffer_v8105bebeda);
    buffer_v8105bebeda = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v29529a0ea3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v29529a0ea3[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8105bebeda + 0x0, 0x100, (uint8_t *)v29529a0ea3);
    free(v29529a0ea3);
    uint32_t *v7dd509edf0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7dd509edf0[i] = (uint32_t)(buffer_v8105bebeda | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_ve4b6f1754e + 0x1c, 0x4, (uint8_t *)v7dd509edf0);
    free(v7dd509edf0);
    uint32_t *v89d95492d1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v89d95492d1[i] = (uint32_t)((EHCIqtd_ve4b6f1754e & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x10, 0x4, (uint8_t *)v89d95492d1);
    free(v89d95492d1);
    goto vc4226d141a_out;
vc4226d141a_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vfeddb25eec_0; break;
    }
vfeddb25eec_0:;
    stateful_free(EHCIqtd_v36dad6093b);
    EHCIqtd_v36dad6093b = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *vba733e5f7f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vba733e5f7f[i] = (uint32_t)((EHCIqtd_v36dad6093b & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0x0, 0x4, (uint8_t *)vba733e5f7f);
    free(vba733e5f7f);
    uint32_t *v9066f56e93 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9066f56e93[i] = (uint32_t)((EHCIqtd_v36dad6093b & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0x4, 0x4, (uint8_t *)v9066f56e93);
    free(v9066f56e93);
    uint32_t *v595d4f421a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v595d4f421a[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0x8, 0x4, (uint8_t *)v595d4f421a);
    free(v595d4f421a);
    stateful_free(buffer_v41a3a9345f);
    buffer_v41a3a9345f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vced03b3fa6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vced03b3fa6[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v41a3a9345f + 0x0, 0x100, (uint8_t *)vced03b3fa6);
    free(vced03b3fa6);
    uint32_t *v30ab67906a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v30ab67906a[i] = (uint32_t)(buffer_v41a3a9345f | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0xc, 0x4, (uint8_t *)v30ab67906a);
    free(v30ab67906a);
    stateful_free(buffer_vb074714a5d);
    buffer_vb074714a5d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va6dee25fe4 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va6dee25fe4[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb074714a5d + 0x0, 0x100, (uint8_t *)va6dee25fe4);
    free(va6dee25fe4);
    uint32_t *v43cebeede4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v43cebeede4[i] = (uint32_t)(buffer_vb074714a5d | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0x10, 0x4, (uint8_t *)v43cebeede4);
    free(v43cebeede4);
    stateful_free(buffer_v831318d1ca);
    buffer_v831318d1ca = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vb5898bd9d3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vb5898bd9d3[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v831318d1ca + 0x0, 0x100, (uint8_t *)vb5898bd9d3);
    free(vb5898bd9d3);
    uint32_t *ve8adaa914c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve8adaa914c[i] = (uint32_t)(buffer_v831318d1ca | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0x14, 0x4, (uint8_t *)ve8adaa914c);
    free(ve8adaa914c);
    stateful_free(buffer_v778e1891cd);
    buffer_v778e1891cd = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v5a02420700 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v5a02420700[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v778e1891cd + 0x0, 0x100, (uint8_t *)v5a02420700);
    free(v5a02420700);
    uint32_t *vaf9620cfdb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vaf9620cfdb[i] = (uint32_t)(buffer_v778e1891cd | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0x18, 0x4, (uint8_t *)vaf9620cfdb);
    free(vaf9620cfdb);
    stateful_free(buffer_v204d229ccc);
    buffer_v204d229ccc = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v12000ef135 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v12000ef135[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v204d229ccc + 0x0, 0x100, (uint8_t *)v12000ef135);
    free(v12000ef135);
    uint32_t *vd3a6fe6afa = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd3a6fe6afa[i] = (uint32_t)(buffer_v204d229ccc | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v36dad6093b + 0x1c, 0x4, (uint8_t *)vd3a6fe6afa);
    free(vd3a6fe6afa);
    uint32_t *va0a2e1dab4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va0a2e1dab4[i] = (uint32_t)((EHCIqtd_v36dad6093b & 0xffffffe0) | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x14, 0x4, (uint8_t *)va0a2e1dab4);
    free(va0a2e1dab4);
    goto vfeddb25eec_out;
vfeddb25eec_out:;
    uint32_t *vfec2b3138b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfec2b3138b[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x18, 0x4, (uint8_t *)vfec2b3138b);
    free(vfec2b3138b);
    stateful_free(buffer_v373ffe54c8);
    buffer_v373ffe54c8 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vf9e5f7ff20 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vf9e5f7ff20[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v373ffe54c8 + 0x0, 0x100, (uint8_t *)vf9e5f7ff20);
    free(vf9e5f7ff20);
    uint32_t *v4a820ed2a0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4a820ed2a0[i] = (uint32_t)(buffer_v373ffe54c8 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x1c, 0x4, (uint8_t *)v4a820ed2a0);
    free(v4a820ed2a0);
    stateful_free(buffer_v6c986537e2);
    buffer_v6c986537e2 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v826ed114cc = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v826ed114cc[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v6c986537e2 + 0x0, 0x100, (uint8_t *)v826ed114cc);
    free(v826ed114cc);
    uint32_t *v6e0d7daaf9 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6e0d7daaf9[i] = (uint32_t)(buffer_v6c986537e2 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x20, 0x4, (uint8_t *)v6e0d7daaf9);
    free(v6e0d7daaf9);
    stateful_free(buffer_v7230a05070);
    buffer_v7230a05070 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v44092ad20e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v44092ad20e[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7230a05070 + 0x0, 0x100, (uint8_t *)v44092ad20e);
    free(v44092ad20e);
    uint32_t *v7c2ad712c3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7c2ad712c3[i] = (uint32_t)(buffer_v7230a05070 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x24, 0x4, (uint8_t *)v7c2ad712c3);
    free(v7c2ad712c3);
    stateful_free(buffer_vd6172c8831);
    buffer_vd6172c8831 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v16f378f4c6 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v16f378f4c6[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd6172c8831 + 0x0, 0x100, (uint8_t *)v16f378f4c6);
    free(v16f378f4c6);
    uint32_t *vf43ffd875e = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf43ffd875e[i] = (uint32_t)(buffer_vd6172c8831 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x28, 0x4, (uint8_t *)vf43ffd875e);
    free(vf43ffd875e);
    stateful_free(buffer_v654729e961);
    buffer_v654729e961 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v7dbf698e1c = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v7dbf698e1c[i] = (uint32_t)get_data_from_pool4();
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v654729e961 + 0x0, 0x100, (uint8_t *)v7dbf698e1c);
    free(v7dbf698e1c);
    uint32_t *vda0846c71d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vda0846c71d[i] = (uint32_t)(buffer_v654729e961 | 0x0);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_qh_0 + 0x2c, 0x4, (uint8_t *)vda0846c71d);
    free(vda0846c71d);
    uint64_t v7a9bbf8cb5 = ((ehci_qh_0 & 0xffffffe0) | 0x1);
    size_2 += serialize(Data, size_2, CALLBACK_MAXSIZE, get_interface_id("operational", EVENT_TYPE_MMIO_WRITE), 0x14, 0x4, (uint8_t *)&v7a9bbf8cb5);
    goto ve327bcd893_out;
ve327bcd893_out:;
    return Data;
}

static size_t get_size_2() { return size_2;}

// ==== hw/usb/hcd-ehci.c:ehci_advance_periodic_state:list = ehci->periodiclistbase ============================
size_t size_3 = 0;

static uint64_t ehci_mix_0 = 0;
static uint64_t EHCIqtd_v45bf927400 = 0;
static uint64_t buffer_v48c20e10f3 = 0;
static uint64_t buffer_vd25320183f = 0;
static uint64_t buffer_va59b1fd690 = 0;
static uint64_t buffer_veb1518ce30 = 0;
static uint64_t buffer_v5395d74b36 = 0;
static uint64_t EHCIqtd_v9c9abecfd0 = 0;
static uint64_t buffer_vf28d802337 = 0;
static uint64_t buffer_v35b69f7539 = 0;
static uint64_t buffer_v9cb17badec = 0;
static uint64_t buffer_ve700241bb0 = 0;
static uint64_t buffer_v9e88282d7d = 0;
static uint64_t EHCIqtd_v9690233359 = 0;
static uint64_t buffer_v180177385b = 0;
static uint64_t buffer_v22105374f1 = 0;
static uint64_t buffer_v28c5ab484b = 0;
static uint64_t buffer_v73fe499018 = 0;
static uint64_t buffer_ve61c323fb5 = 0;
static uint64_t buffer_vb020f85920 = 0;
static uint64_t buffer_v3a56b248d9 = 0;
static uint64_t buffer_v13ecc622dc = 0;
static uint64_t buffer_v8c78ea5e2d = 0;
static uint64_t buffer_v13ce24d9e3 = 0;
static uint64_t v6b62d791f3_base = 0;
static uint64_t ehci_mix_0_1 = 0;
static uint64_t buffer_vbf616b4090 = 0;
static uint64_t buffer_vf542a2d34d = 0;
static uint64_t buffer_v1f3166b886 = 0;
static uint64_t buffer_v8b0e217694 = 0;
static uint64_t buffer_v7bb239b149 = 0;
static uint64_t buffer_v974911ab9f = 0;
static uint64_t buffer_v2627164ea5 = 0;
static uint64_t v2d93efa7d4_base = 0;
static uint64_t ehci_mix_0_1_2 = 0;
static uint64_t buffer_v1fe5fa755d = 0;
static uint64_t buffer_v3a84310773 = 0;
static uint64_t vfb7b6be0c6_base = 0;

static uint8_t *get_data_3() {
    size_3 = 0;
    uint8_t *Data = (uint8_t *)malloc(CALLBACK_MAXSIZE);
    
    switch (get_data_from_pool4() % 3){ 
        case 0: goto v9f44654f4c_0; break;
        case 1: goto v9f44654f4c_1; break;
        case 2: goto v9f44654f4c_2; break;
    }
v9f44654f4c_0:;
    stateful_free(ehci_mix_0);
    ehci_mix_0 = stateful_malloc(0x30, /*chained=*/false);
    uint32_t *vd30f335e2c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd30f335e2c[i] = (uint32_t)((ehci_mix_0 & 0xffffffe0) | 0x1);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x0, 0x4, (uint8_t *)vd30f335e2c);
    free(vd30f335e2c);
    uint32_t *v3441c3540f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3441c3540f[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x4, 0x4, (uint8_t *)v3441c3540f);
    free(v3441c3540f);
    uint32_t *v4effb60840 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4effb60840[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x8, 0x4, (uint8_t *)v4effb60840);
    free(v4effb60840);
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v3dd2e9cc05_0; break;
    }
v3dd2e9cc05_0:;
    stateful_free(EHCIqtd_v45bf927400);
    EHCIqtd_v45bf927400 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v2493528d63 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2493528d63[i] = (uint32_t)((EHCIqtd_v45bf927400 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0x0, 0x4, (uint8_t *)v2493528d63);
    free(v2493528d63);
    uint32_t *v4179153fef = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4179153fef[i] = (uint32_t)((EHCIqtd_v45bf927400 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0x4, 0x4, (uint8_t *)v4179153fef);
    free(v4179153fef);
    uint32_t *v405a71d94b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v405a71d94b[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0x8, 0x4, (uint8_t *)v405a71d94b);
    free(v405a71d94b);
    stateful_free(buffer_v48c20e10f3);
    buffer_v48c20e10f3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va8c0c03219 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va8c0c03219[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v48c20e10f3 + 0x0, 0x100, (uint8_t *)va8c0c03219);
    free(va8c0c03219);
    uint32_t *veaeb304cbe = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        veaeb304cbe[i] = (uint32_t)(buffer_v48c20e10f3 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0xc, 0x4, (uint8_t *)veaeb304cbe);
    free(veaeb304cbe);
    stateful_free(buffer_vd25320183f);
    buffer_vd25320183f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v15bc148082 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v15bc148082[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vd25320183f + 0x0, 0x100, (uint8_t *)v15bc148082);
    free(v15bc148082);
    uint32_t *veb0ecfe265 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        veb0ecfe265[i] = (uint32_t)(buffer_vd25320183f | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0x10, 0x4, (uint8_t *)veb0ecfe265);
    free(veb0ecfe265);
    stateful_free(buffer_va59b1fd690);
    buffer_va59b1fd690 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vde5fc0ee0b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vde5fc0ee0b[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_va59b1fd690 + 0x0, 0x100, (uint8_t *)vde5fc0ee0b);
    free(vde5fc0ee0b);
    uint32_t *v6b4f813702 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6b4f813702[i] = (uint32_t)(buffer_va59b1fd690 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0x14, 0x4, (uint8_t *)v6b4f813702);
    free(v6b4f813702);
    stateful_free(buffer_veb1518ce30);
    buffer_veb1518ce30 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vba6f6e357e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vba6f6e357e[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_veb1518ce30 + 0x0, 0x100, (uint8_t *)vba6f6e357e);
    free(vba6f6e357e);
    uint32_t *v54d88977b5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v54d88977b5[i] = (uint32_t)(buffer_veb1518ce30 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0x18, 0x4, (uint8_t *)v54d88977b5);
    free(v54d88977b5);
    stateful_free(buffer_v5395d74b36);
    buffer_v5395d74b36 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vacfa91cced = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vacfa91cced[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v5395d74b36 + 0x0, 0x100, (uint8_t *)vacfa91cced);
    free(vacfa91cced);
    uint32_t *v7fd2afdc69 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v7fd2afdc69[i] = (uint32_t)(buffer_v5395d74b36 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v45bf927400 + 0x1c, 0x4, (uint8_t *)v7fd2afdc69);
    free(v7fd2afdc69);
    uint32_t *v800c231034 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v800c231034[i] = (uint32_t)((EHCIqtd_v45bf927400 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0xc, 0x4, (uint8_t *)v800c231034);
    free(v800c231034);
    goto v3dd2e9cc05_out;
v3dd2e9cc05_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto v1fb144b06c_0; break;
    }
v1fb144b06c_0:;
    stateful_free(EHCIqtd_v9c9abecfd0);
    EHCIqtd_v9c9abecfd0 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v4ca1a43265 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4ca1a43265[i] = (uint32_t)((EHCIqtd_v9c9abecfd0 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0x0, 0x4, (uint8_t *)v4ca1a43265);
    free(v4ca1a43265);
    uint32_t *vd3b7eb588a = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd3b7eb588a[i] = (uint32_t)((EHCIqtd_v9c9abecfd0 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0x4, 0x4, (uint8_t *)vd3b7eb588a);
    free(vd3b7eb588a);
    uint32_t *v3983b884da = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3983b884da[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0x8, 0x4, (uint8_t *)v3983b884da);
    free(v3983b884da);
    stateful_free(buffer_vf28d802337);
    buffer_vf28d802337 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd39783e8bd = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd39783e8bd[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf28d802337 + 0x0, 0x100, (uint8_t *)vd39783e8bd);
    free(vd39783e8bd);
    uint32_t *vb9ed729a1c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb9ed729a1c[i] = (uint32_t)(buffer_vf28d802337 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0xc, 0x4, (uint8_t *)vb9ed729a1c);
    free(vb9ed729a1c);
    stateful_free(buffer_v35b69f7539);
    buffer_v35b69f7539 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v50ddfe3779 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v50ddfe3779[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v35b69f7539 + 0x0, 0x100, (uint8_t *)v50ddfe3779);
    free(v50ddfe3779);
    uint32_t *v323e6ab217 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v323e6ab217[i] = (uint32_t)(buffer_v35b69f7539 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0x10, 0x4, (uint8_t *)v323e6ab217);
    free(v323e6ab217);
    stateful_free(buffer_v9cb17badec);
    buffer_v9cb17badec = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v652d7065c3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v652d7065c3[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9cb17badec + 0x0, 0x100, (uint8_t *)v652d7065c3);
    free(v652d7065c3);
    uint32_t *vf0ecea747f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf0ecea747f[i] = (uint32_t)(buffer_v9cb17badec | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0x14, 0x4, (uint8_t *)vf0ecea747f);
    free(vf0ecea747f);
    stateful_free(buffer_ve700241bb0);
    buffer_ve700241bb0 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v50a83bcb2a = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v50a83bcb2a[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve700241bb0 + 0x0, 0x100, (uint8_t *)v50a83bcb2a);
    free(v50a83bcb2a);
    uint32_t *vb3334a32c2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb3334a32c2[i] = (uint32_t)(buffer_ve700241bb0 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0x18, 0x4, (uint8_t *)vb3334a32c2);
    free(vb3334a32c2);
    stateful_free(buffer_v9e88282d7d);
    buffer_v9e88282d7d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v131fce6d88 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v131fce6d88[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v9e88282d7d + 0x0, 0x100, (uint8_t *)v131fce6d88);
    free(v131fce6d88);
    uint32_t *vbab93b1ccb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbab93b1ccb[i] = (uint32_t)(buffer_v9e88282d7d | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9c9abecfd0 + 0x1c, 0x4, (uint8_t *)vbab93b1ccb);
    free(vbab93b1ccb);
    uint32_t *vd2b5d3ecb6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd2b5d3ecb6[i] = (uint32_t)((EHCIqtd_v9c9abecfd0 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x10, 0x4, (uint8_t *)vd2b5d3ecb6);
    free(vd2b5d3ecb6);
    goto v1fb144b06c_out;
v1fb144b06c_out:;
    switch (get_data_from_pool4() % 1){ 
        case 0: goto vc181604df1_0; break;
    }
vc181604df1_0:;
    stateful_free(EHCIqtd_v9690233359);
    EHCIqtd_v9690233359 = stateful_malloc(0x20, /*chained=*/false);
    uint32_t *v8d6142c947 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v8d6142c947[i] = (uint32_t)((EHCIqtd_v9690233359 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0x0, 0x4, (uint8_t *)v8d6142c947);
    free(v8d6142c947);
    uint32_t *v53d4c6f188 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v53d4c6f188[i] = (uint32_t)((EHCIqtd_v9690233359 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0x4, 0x4, (uint8_t *)v53d4c6f188);
    free(v53d4c6f188);
    uint32_t *vb3f6940341 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vb3f6940341[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0x8, 0x4, (uint8_t *)vb3f6940341);
    free(vb3f6940341);
    stateful_free(buffer_v180177385b);
    buffer_v180177385b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vdf1f1551ff = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vdf1f1551ff[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v180177385b + 0x0, 0x100, (uint8_t *)vdf1f1551ff);
    free(vdf1f1551ff);
    uint32_t *v3dd398cfa3 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v3dd398cfa3[i] = (uint32_t)(buffer_v180177385b | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0xc, 0x4, (uint8_t *)v3dd398cfa3);
    free(v3dd398cfa3);
    stateful_free(buffer_v22105374f1);
    buffer_v22105374f1 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v50cc0024c3 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v50cc0024c3[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v22105374f1 + 0x0, 0x100, (uint8_t *)v50cc0024c3);
    free(v50cc0024c3);
    uint32_t *v5c95409784 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5c95409784[i] = (uint32_t)(buffer_v22105374f1 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0x10, 0x4, (uint8_t *)v5c95409784);
    free(v5c95409784);
    stateful_free(buffer_v28c5ab484b);
    buffer_v28c5ab484b = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v78a386f83f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v78a386f83f[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v28c5ab484b + 0x0, 0x100, (uint8_t *)v78a386f83f);
    free(v78a386f83f);
    uint32_t *vbec02474e6 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbec02474e6[i] = (uint32_t)(buffer_v28c5ab484b | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0x14, 0x4, (uint8_t *)vbec02474e6);
    free(vbec02474e6);
    stateful_free(buffer_v73fe499018);
    buffer_v73fe499018 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vd76a56a267 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vd76a56a267[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v73fe499018 + 0x0, 0x100, (uint8_t *)vd76a56a267);
    free(vd76a56a267);
    uint32_t *v5e9991d267 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5e9991d267[i] = (uint32_t)(buffer_v73fe499018 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0x18, 0x4, (uint8_t *)v5e9991d267);
    free(v5e9991d267);
    stateful_free(buffer_ve61c323fb5);
    buffer_ve61c323fb5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v4bab1106aa = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v4bab1106aa[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_ve61c323fb5 + 0x0, 0x100, (uint8_t *)v4bab1106aa);
    free(v4bab1106aa);
    uint32_t *vc3f21506fd = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc3f21506fd[i] = (uint32_t)(buffer_ve61c323fb5 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, EHCIqtd_v9690233359 + 0x1c, 0x4, (uint8_t *)vc3f21506fd);
    free(vc3f21506fd);
    uint32_t *v1affac8efb = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1affac8efb[i] = (uint32_t)((EHCIqtd_v9690233359 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x14, 0x4, (uint8_t *)v1affac8efb);
    free(v1affac8efb);
    goto vc181604df1_out;
vc181604df1_out:;
    uint32_t *vf3c320f11c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vf3c320f11c[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x02 + 1)) - 1)) << 0x02) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0f + 1)) - 1)) << 0x0f) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x18, 0x4, (uint8_t *)vf3c320f11c);
    free(vf3c320f11c);
    stateful_free(buffer_vb020f85920);
    buffer_vb020f85920 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v340d07e502 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v340d07e502[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vb020f85920 + 0x0, 0x100, (uint8_t *)v340d07e502);
    free(v340d07e502);
    uint32_t *vfb9e2f2b6b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vfb9e2f2b6b[i] = (uint32_t)(buffer_vb020f85920 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x1c, 0x4, (uint8_t *)vfb9e2f2b6b);
    free(vfb9e2f2b6b);
    stateful_free(buffer_v3a56b248d9);
    buffer_v3a56b248d9 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *va279756728 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        va279756728[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3a56b248d9 + 0x0, 0x100, (uint8_t *)va279756728);
    free(va279756728);
    uint32_t *v1e261263d0 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1e261263d0[i] = (uint32_t)(buffer_v3a56b248d9 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x20, 0x4, (uint8_t *)v1e261263d0);
    free(v1e261263d0);
    stateful_free(buffer_v13ecc622dc);
    buffer_v13ecc622dc = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v49eef7e9e7 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v49eef7e9e7[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v13ecc622dc + 0x0, 0x100, (uint8_t *)v49eef7e9e7);
    free(v49eef7e9e7);
    uint32_t *vbb43210bf8 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vbb43210bf8[i] = (uint32_t)(buffer_v13ecc622dc | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x24, 0x4, (uint8_t *)vbb43210bf8);
    free(vbb43210bf8);
    stateful_free(buffer_v8c78ea5e2d);
    buffer_v8c78ea5e2d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v709d84e875 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v709d84e875[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8c78ea5e2d + 0x0, 0x100, (uint8_t *)v709d84e875);
    free(v709d84e875);
    uint32_t *vd92bdc4fc1 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd92bdc4fc1[i] = (uint32_t)(buffer_v8c78ea5e2d | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x28, 0x4, (uint8_t *)vd92bdc4fc1);
    free(vd92bdc4fc1);
    stateful_free(buffer_v13ce24d9e3);
    buffer_v13ce24d9e3 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v804f77eb22 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v804f77eb22[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v13ce24d9e3 + 0x0, 0x100, (uint8_t *)v804f77eb22);
    free(v804f77eb22);
    uint32_t *v1ff7947b02 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1ff7947b02[i] = (uint32_t)(buffer_v13ce24d9e3 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0 + 0x2c, 0x4, (uint8_t *)v1ff7947b02);
    free(v1ff7947b02);
    stateful_free(v6b62d791f3_base);
    v6b62d791f3_base = stateful_malloc(0x1000, /*chained=*/false);
    uint32_t *v7f6f242c7a = (uint32_t *)malloc(0x1000);
    for (int i = 0; i < (0x1000) / 4; i++)
        v7f6f242c7a[i] = (uint32_t)((ehci_mix_0 & 0xffffffe0) | 0x1);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, v6b62d791f3_base, 0x1000, (uint8_t *)v7f6f242c7a);
    free(v7f6f242c7a);
    uint64_t v9b3d1228e1 = (v6b62d791f3_base | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, get_interface_id("operational", EVENT_TYPE_MMIO_WRITE), 0x14, 0x4, (uint8_t *)&v9b3d1228e1);
    goto v9f44654f4c_out;
v9f44654f4c_1:;
    stateful_free(ehci_mix_0_1);
    ehci_mix_0_1 = stateful_malloc(0x40, /*chained=*/false);
    uint32_t *v722a06d8f4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v722a06d8f4[i] = (uint32_t)((ehci_mix_0_1 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x0, 0x4, (uint8_t *)v722a06d8f4);
    free(v722a06d8f4);
    uint32_t *v577a104270 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v577a104270[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x4, 0x4, (uint8_t *)v577a104270);
    free(v577a104270);
    uint32_t *v6c4a0c48a4 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6c4a0c48a4[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x8, 0x4, (uint8_t *)v6c4a0c48a4);
    free(v6c4a0c48a4);
    uint32_t *v1cd1d95717 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v1cd1d95717[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0xc, 0x4, (uint8_t *)v1cd1d95717);
    free(v1cd1d95717);
    uint32_t *v2b30617dad = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v2b30617dad[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x10, 0x4, (uint8_t *)v2b30617dad);
    free(v2b30617dad);
    uint32_t *v6a2163c87d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6a2163c87d[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x14, 0x4, (uint8_t *)v6a2163c87d);
    free(v6a2163c87d);
    uint32_t *v5ca6304d52 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5ca6304d52[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x18, 0x4, (uint8_t *)v5ca6304d52);
    free(v5ca6304d52);
    uint32_t *vc770f1809b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc770f1809b[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x1c, 0x4, (uint8_t *)vc770f1809b);
    free(vc770f1809b);
    uint32_t *v9f91d3b239 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v9f91d3b239[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x0c + 1)) - 1)) << 0x0c) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x20, 0x4, (uint8_t *)v9f91d3b239);
    free(v9f91d3b239);
    stateful_free(buffer_vbf616b4090);
    buffer_vbf616b4090 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v3c4796c2da = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v3c4796c2da[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vbf616b4090 + 0x0, 0x100, (uint8_t *)v3c4796c2da);
    free(v3c4796c2da);
    uint32_t *vcf0d60dff2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vcf0d60dff2[i] = (uint32_t)(buffer_vbf616b4090 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x24, 0x4, (uint8_t *)vcf0d60dff2);
    free(vcf0d60dff2);
    stateful_free(buffer_vf542a2d34d);
    buffer_vf542a2d34d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vef45fa7056 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vef45fa7056[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_vf542a2d34d + 0x0, 0x100, (uint8_t *)vef45fa7056);
    free(vef45fa7056);
    uint32_t *v5c05f73db2 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v5c05f73db2[i] = (uint32_t)(buffer_vf542a2d34d | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x28, 0x4, (uint8_t *)v5c05f73db2);
    free(v5c05f73db2);
    stateful_free(buffer_v1f3166b886);
    buffer_v1f3166b886 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *ve0858e285f = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        ve0858e285f[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v1f3166b886 + 0x0, 0x100, (uint8_t *)ve0858e285f);
    free(ve0858e285f);
    uint32_t *v15f6f63f9d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v15f6f63f9d[i] = (uint32_t)(buffer_v1f3166b886 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x2c, 0x4, (uint8_t *)v15f6f63f9d);
    free(v15f6f63f9d);
    stateful_free(buffer_v8b0e217694);
    buffer_v8b0e217694 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v963eed6e2e = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v963eed6e2e[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v8b0e217694 + 0x0, 0x100, (uint8_t *)v963eed6e2e);
    free(v963eed6e2e);
    uint32_t *v6cd443c34f = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v6cd443c34f[i] = (uint32_t)(buffer_v8b0e217694 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x30, 0x4, (uint8_t *)v6cd443c34f);
    free(v6cd443c34f);
    stateful_free(buffer_v7bb239b149);
    buffer_v7bb239b149 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v13670c2014 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v13670c2014[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v7bb239b149 + 0x0, 0x100, (uint8_t *)v13670c2014);
    free(v13670c2014);
    uint32_t *ve395385042 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve395385042[i] = (uint32_t)(buffer_v7bb239b149 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x34, 0x4, (uint8_t *)ve395385042);
    free(ve395385042);
    stateful_free(buffer_v974911ab9f);
    buffer_v974911ab9f = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc520be670b = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc520be670b[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v974911ab9f + 0x0, 0x100, (uint8_t *)vc520be670b);
    free(vc520be670b);
    uint32_t *vc7ccbe330c = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vc7ccbe330c[i] = (uint32_t)(buffer_v974911ab9f | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x38, 0x4, (uint8_t *)vc7ccbe330c);
    free(vc7ccbe330c);
    stateful_free(buffer_v2627164ea5);
    buffer_v2627164ea5 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vca46c90384 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vca46c90384[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v2627164ea5 + 0x0, 0x100, (uint8_t *)vca46c90384);
    free(vca46c90384);
    uint32_t *v4634f8ac8b = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4634f8ac8b[i] = (uint32_t)(buffer_v2627164ea5 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1 + 0x3c, 0x4, (uint8_t *)v4634f8ac8b);
    free(v4634f8ac8b);
    stateful_free(v2d93efa7d4_base);
    v2d93efa7d4_base = stateful_malloc(0x1000, /*chained=*/false);
    uint32_t *va5ad2d20e6 = (uint32_t *)malloc(0x1000);
    for (int i = 0; i < (0x1000) / 4; i++)
        va5ad2d20e6[i] = (uint32_t)((ehci_mix_0_1 & 0xffffffe0) | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, v2d93efa7d4_base, 0x1000, (uint8_t *)va5ad2d20e6);
    free(va5ad2d20e6);
    uint64_t v3a239ab46a = (v2d93efa7d4_base | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, get_interface_id("operational", EVENT_TYPE_MMIO_WRITE), 0x14, 0x4, (uint8_t *)&v3a239ab46a);
    goto v9f44654f4c_out;
v9f44654f4c_2:;
    stateful_free(ehci_mix_0_1_2);
    ehci_mix_0_1_2 = stateful_malloc(0x1c, /*chained=*/false);
    uint32_t *vd3ab9f7989 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vd3ab9f7989[i] = (uint32_t)((ehci_mix_0_1_2 & 0xffffffe0) | 0x2);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1_2 + 0x0, 0x4, (uint8_t *)vd3ab9f7989);
    free(vd3ab9f7989);
    uint32_t *v4bd7791eae = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v4bd7791eae[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x04 + 1)) - 1)) << 0x04) | ((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x07 + 1)) - 1)) << 0x07) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1_2 + 0x4, 0x4, (uint8_t *)v4bd7791eae);
    free(v4bd7791eae);
    uint32_t *ve1031f2cc5 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        ve1031f2cc5[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x10 + 1)) - 1)) << 0x10));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1_2 + 0x8, 0x4, (uint8_t *)ve1031f2cc5);
    free(ve1031f2cc5);
    uint32_t *v940278ed0d = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v940278ed0d[i] = (uint32_t)(((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x08 + 1)) - 1)) << 0x08) | ((get_data_from_pool4() & ((1 << (0x0b + 1)) - 1)) << 0x0b) | ((get_data_from_pool4() & ((1 << (0x03 + 1)) - 1)) << 0x03) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01) | ((get_data_from_pool4() & ((1 << (0x01 + 1)) - 1)) << 0x01));
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1_2 + 0xc, 0x4, (uint8_t *)v940278ed0d);
    free(v940278ed0d);
    stateful_free(buffer_v1fe5fa755d);
    buffer_v1fe5fa755d = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *vc8e70dba91 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        vc8e70dba91[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v1fe5fa755d + 0x0, 0x100, (uint8_t *)vc8e70dba91);
    free(vc8e70dba91);
    uint32_t *vffbe838a60 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        vffbe838a60[i] = (uint32_t)(buffer_v1fe5fa755d | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1_2 + 0x10, 0x4, (uint8_t *)vffbe838a60);
    free(vffbe838a60);
    stateful_free(buffer_v3a84310773);
    buffer_v3a84310773 = stateful_malloc(0x100, /*chained=*/false);
    uint32_t *v9e5e1b3404 = (uint32_t *)malloc(0x100);
    for (int i = 0; i < (0x100) / 4; i++)
        v9e5e1b3404[i] = (uint32_t)get_data_from_pool4();
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, buffer_v3a84310773 + 0x0, 0x100, (uint8_t *)v9e5e1b3404);
    free(v9e5e1b3404);
    uint32_t *v992f4add68 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        v992f4add68[i] = (uint32_t)(buffer_v3a84310773 | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1_2 + 0x14, 0x4, (uint8_t *)v992f4add68);
    free(v992f4add68);
    uint32_t *va17b63f551 = (uint32_t *)malloc(0x4);
    for (int i = 0; i < (0x4) / 4; i++)
        va17b63f551[i] = (uint32_t)((ehci_mix_0_1_2 & 0xffffffe0) | 0x2);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, ehci_mix_0_1_2 + 0x18, 0x4, (uint8_t *)va17b63f551);
    free(va17b63f551);
    stateful_free(vfb7b6be0c6_base);
    vfb7b6be0c6_base = stateful_malloc(0x1000, /*chained=*/false);
    uint32_t *v213b1df3bb = (uint32_t *)malloc(0x1000);
    for (int i = 0; i < (0x1000) / 4; i++)
        v213b1df3bb[i] = (uint32_t)((ehci_mix_0_1_2 & 0xffffffe0) | 0x2);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, INTERFACE_MEM_WRITE, vfb7b6be0c6_base, 0x1000, (uint8_t *)v213b1df3bb);
    free(v213b1df3bb);
    uint64_t vd8cb08277a = (vfb7b6be0c6_base | 0x0);
    size_3 += serialize(Data, size_3, CALLBACK_MAXSIZE, get_interface_id("operational", EVENT_TYPE_MMIO_WRITE), 0x14, 0x4, (uint8_t *)&vd8cb08277a);
    goto v9f44654f4c_out;
v9f44654f4c_out:;
    return Data;
}

static size_t get_size_3() { return size_3;}

static Callback callbacks[] = { 
    [0] = {
        .id = 0,
        .name = "uhci",
        .get_data = get_data_0,
        .get_size = get_size_0,
    },
    [1] = {
        .id = 1,
        .name = "ohci",
        .get_data = get_data_1,
        .get_size = get_size_1,
    },
    [2] = {
        .id = 2,
        .name = "ehci0",
        .get_data = get_data_2,
        .get_size = get_size_2,
    },
    [3] = {
        .id = 3,
        .name = "ehci1",
        .get_data = get_data_3,
        .get_size = get_size_3,
    },
};

#endif /* STATEFUL_FUZZ_TSC_H */
