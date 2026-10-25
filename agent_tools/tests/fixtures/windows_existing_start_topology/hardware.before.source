"""Pure argument-driven QEMU topology for one fresh Windows fixture."""


def qemu_argv(spec,binary,asset_sets):
    from pathlib import Path
    root=Path(spec['root'])
    args=[binary,'-name','vpn-control-'+spec['deploymentId'],'-uuid',spec['deploymentId'],
          '-machine','q35,smm=on','-accel','kvm','-cpu','host','-smp',str(spec['cpus']),'-m',str(spec['memoryMiB']),
          '-global','driver=cfi.pflash01,property=secure,value=on',
          '-drive','if=pflash,format=raw,readonly=on,file=/dev/fdset/'+str(asset_sets['firmwareCode']),
          '-drive','if=pflash,format=raw,file='+str(root/'uefi-vars.fd'),
          '-drive','file='+str(root/'disk.qcow2')+',if=none,id=system,format=qcow2',
          '-device','ide-hd,drive=system,bus=ide.0']
    for bus,name in enumerate(('installer','drivers'),1):
        args.extend(('-drive','file=/dev/fdset/'+str(asset_sets[name])+',media=cdrom,readonly=on,if=none,id='+name,
                     '-device','ide-cd,drive='+name+',bus=ide.'+str(bus)))
    args.extend(('-drive','file='+str(root/'seed.iso')+',media=cdrom,readonly=on,format=raw,if=none,id=seed',
                 '-device','ide-cd,drive=seed,bus=ide.3',
                 '-chardev','socket,id=tpmchar,path='+str(root/'swtpm.sock'),
                 '-tpmdev','emulator,id=tpm0,chardev=tpmchar','-device','tpm-tis,tpmdev=tpm0',
                 '-device','virtio-serial-pci','-chardev','socket,path='+str(root/'qga.sock')+',server=on,wait=off,id=qga',
                 '-device','virtserialport,chardev=qga,name=org.qemu.guest_agent.0',
                 '-netdev','user,id=net0','-device','e1000e,netdev=net0','-boot','order=c,once=d,menu=off',
                 '-display','none','-vnc','127.0.0.1:'+str(spec['vncPort']-5900),
                 '-monitor','none','-qmp','unix:'+str(root/'qmp.sock')+',server=on,wait=off'))
    return args
