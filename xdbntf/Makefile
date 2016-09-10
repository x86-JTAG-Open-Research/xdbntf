#
# xdbntf/Makefile
#
# Makefile for generating the Linux* kernel module to notify the 
# Intel(R) System Debugger
#
# Copyright (c) 2012-2016, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307 USA.
#
#* Other names and brands may be claimed as the property of others.


obj-m := xdbntf.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: default clean

default:
ifndef ANDROID_PRODUCT_OUT
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
else
	$(MAKE) -C  $(ANDROID_PRODUCT_OUT)/kernel_build M=$(PWD) modules
endif

clean:
	$(RM) xdbntf.ko xdbntf.mod.c xdbntf.mod.o xdbntf.o Module.symvers modules.order
