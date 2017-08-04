<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Introduction](#introduction)
- [Ensure sVirt Framework Is Active](#ensure-svirt-framework-is-active)
- [Use Minimal Number Of Devices](#use-minimal-number-of-devices)
- [Ensure Binary Hardening Is Applied](#ensure-binary-hardening-is-applied)
- [Enable Kernel ASLR](#enable-kernel-aslr)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Introduction

We have compiled the most relevant hardening items for the KVM hypervisor. This guide focuses exclusively on the hardening of KVM itself (or aspects directly related to it). Further hardening consideration must be applied to the hypervisor system as a whole, which includes:
* Hardening of the base operating system (refer to our Linux guides)
* Restriction of management interfaces
* Segmentation, restriction, and isolation of the virtual network infrastructure

# Ensure sVirt Framework Is Active

The [sVirt framework](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/chap-Security-Enhanced_Linux-sVirt.html) must be active and used by KVM to isolate the processes belonging to the different virtual machines from each other and make the exploitation of virtual (QEMU) devices (significantly) harder. sVirt requires either SELinux or AppArmor, and its active use can be verified by inspecting the Linux process list:
```                                                                         
sudo ps auxZ  
```
and ensuring that processes belonging to different virtual machines have different labels assigned.

In addition, execute
```                                                                         
sudo sestatus 
```
to verify whether SELinux is active, or
```                                                                         
sudo aa-status
```
to verify whether AppArmor is active. 

If active, verify whether SELinux or AppArmor is properly configured; that is, whether the set isolation boundaries are correct. For example, verify that the SELinux file labels are correct. 

# Use Minimal Number Of Devices

QEMU, the device emulator used by KVM, may be compiled with support for a significant number of devices. The number of actually used devices by KVM-based virtual machines should be kept at a minimum to reduce the risk of breaches and vulnerability monitoring efforts for those devices. This is because QEMU devices contain vulnerabilities on a regular basis (refer to the corresponding [security advisories](https://access.redhat.com/errata/#)).

This control can be applied either by disabling device support at compile time or having another layer (e.g., OpenStack) that allows to start virtual machines only with certain devices enabled.

# Ensure Binary Hardening Is Applied

Ensure that [binary hardening mechanisms](https://wiki.debian.org/Hardening) are applied to all KVM/QEMU binaries which typically comprise at least, but are not limited to:
* qemu-kvm
* qemu-img
* qemu-nbd
* qemu-io
* kvm.ko
* kvm_intel.ko
* vhost-net.ko
* libvirtd
* virtlockd
* virtlogd
* virsh
* virtfs-proxy-helper
* virt-host-validate

Note that the vhost-net.ko and kvm_intel.ko loadable kernel modules may not be loaded and used by KVM, and that other modules may be used instead. This depends on the configuration of running KVM-based virtual machines and hardware platform, respectively. For example, if only AMD CPUs are present,
ensure that binary hardening mechanisms are applied to the kvm_amd.ko kernel module. 

You can use [checksec.sh](http://www.trapkit.de/tools/checksec.html) for verification.

# Enable Kernel ASLR

You should enable Kernel ASLR on the KVM host to hinder exploitation of vulnerabilities in the KVM kernel modules. While this is also makes sense for regular Linux systems, it is of particular relevance for KVM hosts as the successful virtual machine breakout potentially has a much higher impact than a local privilege escalation.