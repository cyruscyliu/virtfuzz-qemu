if not get_option('fuzzing')
  subdir_done()
endif

specific_fuzz_ss.add(files('fuzz.c', 'fork_fuzz.c', 'qos_fuzz.c',
                           'qtest_wrappers.c', 'less_crashes_wrappers.c'), qos)

# Targets
specific_fuzz_ss.add(when: 'CONFIG_I440FX', if_true: files('i440fx_fuzz.c'))
specific_fuzz_ss.add(when: 'CONFIG_VIRTIO_NET', if_true: files('virtio_net_fuzz.c'))
specific_fuzz_ss.add(when: 'CONFIG_VIRTIO_SCSI', if_true: files('virtio_scsi_fuzz.c'))
specific_fuzz_ss.add(when: 'CONFIG_VIRTIO_BLK', if_true: files('virtio_blk_fuzz.c'))
specific_fuzz_ss.add(files('generic_fuzz.c'))
specific_fuzz_ss.add(files('videzzo_qemu.c'))
vnc_client = declare_dependency(link_args: fuzz_exe_ldflags + ['-lvncclient'])
specific_fuzz_ss.add(vnc_client)

fork_fuzz = declare_dependency(
  link_args: fuzz_exe_ldflags +
             ['-Wl,-wrap,qtest_inb',
              '-Wl,-wrap,qtest_inw',
              '-Wl,-wrap,qtest_inl',
              '-Wl,-wrap,qtest_outb',
              '-Wl,-wrap,qtest_outw',
              '-Wl,-wrap,qtest_outl',
              '-Wl,-wrap,qtest_readb',
              '-Wl,-wrap,qtest_readw',
              '-Wl,-wrap,qtest_readl',
              '-Wl,-wrap,qtest_readq',
              '-Wl,-wrap,qtest_writeb',
              '-Wl,-wrap,qtest_writew',
              '-Wl,-wrap,qtest_writel',
              '-Wl,-wrap,qtest_writeq',
              '-Wl,-wrap,qtest_memread',
              '-Wl,-wrap,qtest_bufread',
              '-Wl,-wrap,qtest_memwrite',
              '-Wl,-wrap,qtest_bufwrite',
              '-Wl,-wrap,qtest_memset',
              '-Wl,-wrap,abort']
)

specific_fuzz_ss.add(fork_fuzz)
