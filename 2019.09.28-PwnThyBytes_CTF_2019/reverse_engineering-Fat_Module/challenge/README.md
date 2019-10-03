**Fat Module**

**Author: adrians**

You need to create a kernel module that can be loaded on both x86 and arm kernels.

Send us a mod.ko file such that `insmod mod.ko` works in both virtual machines provided by the task.

The kernels are slightly modified in order to accept a "fat module" format. You need to figure out the format by reversing the kernel.

The `.config` files for building the kernels are provided. The kernel source tree that was used is https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.1.16.tar.xz

The module should create a character device with the major 400. Reading from this character device should return the string `Hello, World!\n`.

archive password: `Dea4choo5ahc5E`

`nc 137.117.216.128 13376`