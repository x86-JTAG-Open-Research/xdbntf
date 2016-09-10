//
// xdbntf/xdbntf.c
//
// Linux* kernel module to notify the Intel(R) System Debugger
//
// Copyright (c) 2012-2016, Intel Corporation. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc., 59 Temple
// Place - Suite 330, Boston, MA 02111-1307 USA.
//
//

//////////////////////////////////////////////////////////////////////////////////
// This code is intended to be used as a target agent for the Intel(R) System
// debugger. It needs to be compiled and loaded as a Linux* kernel module to enable
// module debugging.
//
// The code collects and prepares meta information for the debugger to be able
// to parse the kernel module list. xdbntf registers a callback function that
// is invoked by the kernel for every module state change. The callback receives
// as a parameter the pointer to a module data structure and the corresponding
// new module state.
//
// To enable module debugging, this kernel module needs to be loaded to the
// kernel via the insmod mechanism before any other module the user actually
// wants to debug. If it gets unloaded (via rmmod) all the internally allocated
// data structures will be freed and module debugging with the Intel(R) System
// Debugger will be disabled.
//
// Aside: this module doesn't export any global symbols - all data and code is
// used internally only.
//
//* Other names and brands may be claimed as the property of others.


#include <linux/module.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/stddef.h>
#include <linux/version.h>



////////////////////////////////////////////////////////////////////////////////
// taken from kernel/module.c  ->  keep this in sync
// NOTE: Only from kernel version 2.6.26 onwards

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
struct module_sect_attr
{
    struct module_attribute mattr;
    char *name;
    unsigned long address;
};
struct module_sect_attrs
{
    struct attribute_group grp;
    unsigned int nsections;
    struct module_sect_attr attrs[0];
};
#endif

//
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// Function prototypes
//

static void fill_xdb_metainfo(void);
static int xdb_notify(struct notifier_block*, unsigned long, void*) __attribute((__noinline__));

//
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// Private data
//

static int is_started;              // 0 if initialization fails, 1 else

volatile static struct {
    uint64_t xdbntf_version;
    uint64_t xdbntf_kernel_version;
    uint64_t xdbntf_ptrsize;
    uint64_t xdbntf_metainfo_size;
    uint64_t xdbntf_metainfo_offsets;
    uint64_t xdbntf_metainfo_offsets_size;
    uint64_t xdbntf_metainfo_sizes;
    uint64_t xdbntf_metainfo_sizes_size;
    uint64_t xdbntf_metainfo_enumvals;
    uint64_t xdbntf_metainfo_enumvals_size;
} xdb_metainfo;

volatile static struct {
    uint64_t struct_module__offsetof__state;
    uint64_t struct_module__offsetof__list_next_ptr;
    uint64_t struct_module__offsetof__list_prev_ptr;
    uint64_t struct_module__offsetof__name;
    uint64_t struct_module__offsetof__init;
    uint64_t struct_module__offsetof__exit;
    uint64_t struct_module__offsetof__module_init;
    uint64_t struct_module__offsetof__module_core;
    uint64_t struct_module__offsetof__init_size;
    uint64_t struct_module__offsetof__core_size;
    uint64_t struct_module__offsetof__init_text_size;
    uint64_t struct_module__offsetof__core_text_size;
    uint64_t struct_module__offsetof__init_ro_size;
    uint64_t struct_module__offsetof__core_ro_size;
    uint64_t struct_module__offsetof__sect_attrs_ptr;
    uint64_t struct_module_sect_attrs__offsetof__nsections;
    uint64_t struct_module_sect_attrs__offsetof__attrs_array;
    uint64_t struct_module_sect_attr__offsetof__name_ptr;
    uint64_t struct_module_sect_attr__offsetof__addr;
} xdb_metainfo_offsets;

volatile static struct {
    uint64_t struct_module__sizeof;
    uint64_t struct_module__sizeof__state;
    uint64_t struct_module__sizeof__list_next_ptr;
    uint64_t struct_module__sizeof__list_prev_ptr;
    uint64_t struct_module__sizeof__name;
    uint64_t struct_module__sizeof__init;
    uint64_t struct_module__sizeof__exit;
    uint64_t struct_module__sizeof__module_init;
    uint64_t struct_module__sizeof__module_core;
    uint64_t struct_module__sizeof__init_size;
    uint64_t struct_module__sizeof__core_size;
    uint64_t struct_module__sizeof__init_text_size;
    uint64_t struct_module__sizeof__core_text_size;
    uint64_t struct_module__sizeof__init_ro_size;
    uint64_t struct_module__sizeof__core_ro_size;
    uint64_t struct_module__sizeof__sect_attrs_ptr;
    uint64_t struct_module_sect_attrs__sizeof;
    uint64_t struct_module_sect_attrs__sizeof__nsections;
    uint64_t struct_module_sect_attrs__sizeof__attrs_array;
    uint64_t struct_module_sect_attr__sizeof;
    uint64_t struct_module_sect_attr__sizeof__name_ptr;
    uint64_t struct_module_sect_attr__sizeof__addr;
} xdb_metainfo_sizes;

volatile static struct {
    uint64_t enum_module_state__MODULE_STATE_LIVE;
    uint64_t enum_module_state__MODULE_STATE_COMING;
    uint64_t enum_module_state__MODULE_STATE_GOING;
} xdb_metainfo_enumvals;

static struct notifier_block module_state_nb = {
    .notifier_call = xdb_notify
};

//
////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
// Magic breakpoint definition
//

#define XDBNTF_VERSION       1

#define XDBNTF_MODULE_COMING 1
#define XDBNTF_MODULE_LIVE   2
#define XDBNTF_MODULE_GOING  3
#define XDBNTF_XDBNTF_GOING  4

#define MAGIC_BREAK(code,data) __MAGIC_BREAK__(code,data)
#define __MAGIC_BREAK__(code, data) __asm__ __volatile__("\n\t" \
        ".byte 0xf1"                                     "\n\t" \
        "jmp 1f"                                         "\n\t" \
        ".byte 0xde"                                     "\n\t" \
        ".byte 0xad"                                     "\n\t" \
        ".byte " #code                                   "\n\t" \
        "1:"                                             "\n\t" \
        "nop"                                            "\n\t" \
        "nop"                                            "\n\t" \
        : : "a" (&xdb_metainfo), "b" (data))

//
////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
// The following function is registered in the kernel as a callback function,
// called for any module state event.
// The configuration is done via the kernel register_module_notifier
// mechanism. Check kernel/module.c for the caller.
//

static int
xdb_notify(
    struct notifier_block * self,
    unsigned long code,
    void * data
)
{
    if      (code==MODULE_STATE_COMING)  MAGIC_BREAK(XDBNTF_MODULE_COMING, data);
    else if (code==MODULE_STATE_LIVE)    MAGIC_BREAK(XDBNTF_MODULE_LIVE,   data);
    else if (code==MODULE_STATE_GOING)   MAGIC_BREAK(XDBNTF_MODULE_GOING,  data);

    return 0;
}

//
////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
// Meta-info preparation

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef msizeof
#define msizeof(TYPE, MEMBER) (sizeof(((TYPE *)0)->MEMBER))
#endif

#ifdef CONFIG_X86_64
#define PTR64BIT(ptr) ((uint64_t)(ptr))
#else
#define PTR64BIT(ptr) (((uint64_t)0) | ((uint32_t)(ptr)))
#endif

static void
fill_xdb_metainfo(void)
{
    // general info block
    xdb_metainfo.xdbntf_version                                           = (uint64_t) XDBNTF_VERSION;
    xdb_metainfo.xdbntf_kernel_version                                    = (uint64_t) LINUX_VERSION_CODE;
    xdb_metainfo.xdbntf_ptrsize                                           = (uint64_t) (sizeof(void*)*8);
    xdb_metainfo.xdbntf_metainfo_size                                     = (uint64_t) sizeof(xdb_metainfo);
    xdb_metainfo.xdbntf_metainfo_offsets                                  = (uint64_t) PTR64BIT(&xdb_metainfo_offsets);
    xdb_metainfo.xdbntf_metainfo_offsets_size                             = (uint64_t) sizeof(xdb_metainfo_offsets);
    xdb_metainfo.xdbntf_metainfo_sizes                                    = (uint64_t) PTR64BIT(&xdb_metainfo_sizes);
    xdb_metainfo.xdbntf_metainfo_sizes_size                               = (uint64_t) sizeof(xdb_metainfo_sizes);
    xdb_metainfo.xdbntf_metainfo_enumvals                                 = (uint64_t) PTR64BIT(&xdb_metainfo_enumvals);
    xdb_metainfo.xdbntf_metainfo_enumvals_size                            = (uint64_t) sizeof(xdb_metainfo_enumvals);
    // offsets
    xdb_metainfo_offsets.struct_module__offsetof__state                   = (uint64_t) offsetof(struct module, state);
    xdb_metainfo_offsets.struct_module__offsetof__list_next_ptr           = (uint64_t) offsetof(struct module, list.next);
    xdb_metainfo_offsets.struct_module__offsetof__list_prev_ptr           = (uint64_t) offsetof(struct module, list.prev);
    xdb_metainfo_offsets.struct_module__offsetof__name                    = (uint64_t) offsetof(struct module, name);
    xdb_metainfo_offsets.struct_module__offsetof__init                    = (uint64_t) offsetof(struct module, init);
    xdb_metainfo_offsets.struct_module__offsetof__exit                    = (uint64_t) offsetof(struct module, exit);
    xdb_metainfo_offsets.struct_module__offsetof__module_init             = (uint64_t) offsetof(struct module, module_init);
    xdb_metainfo_offsets.struct_module__offsetof__module_core             = (uint64_t) offsetof(struct module, module_core);
    xdb_metainfo_offsets.struct_module__offsetof__init_size               = (uint64_t) offsetof(struct module, init_size);
    xdb_metainfo_offsets.struct_module__offsetof__core_size               = (uint64_t) offsetof(struct module, core_size);
    xdb_metainfo_offsets.struct_module__offsetof__init_text_size          = (uint64_t) offsetof(struct module, init_text_size);
    xdb_metainfo_offsets.struct_module__offsetof__core_text_size          = (uint64_t) offsetof(struct module, core_text_size);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
    xdb_metainfo_offsets.struct_module__offsetof__init_ro_size            = (uint64_t) offsetof(struct module, init_ro_size);
    xdb_metainfo_offsets.struct_module__offsetof__core_ro_size            = (uint64_t) offsetof(struct module, core_ro_size);
#else
    xdb_metainfo_offsets.struct_module__offsetof__init_ro_size            = (uint64_t) 0;
    xdb_metainfo_offsets.struct_module__offsetof__core_ro_size            = (uint64_t) 0;
#endif
    xdb_metainfo_offsets.struct_module__offsetof__sect_attrs_ptr          = (uint64_t) offsetof(struct module, sect_attrs);
    xdb_metainfo_offsets.struct_module_sect_attrs__offsetof__nsections    = (uint64_t) offsetof(struct module_sect_attrs, nsections);
    xdb_metainfo_offsets.struct_module_sect_attrs__offsetof__attrs_array  = (uint64_t) offsetof(struct module_sect_attrs, attrs);
    xdb_metainfo_offsets.struct_module_sect_attr__offsetof__name_ptr      = (uint64_t) offsetof(struct module_sect_attr, name);
    xdb_metainfo_offsets.struct_module_sect_attr__offsetof__addr          = (uint64_t) offsetof(struct module_sect_attr, address);
    // sizes
    xdb_metainfo_sizes.struct_module__sizeof                              = (uint64_t) sizeof(struct module);
    xdb_metainfo_sizes.struct_module__sizeof__state                       = (uint64_t) msizeof(struct module, state);
    xdb_metainfo_sizes.struct_module__sizeof__list_next_ptr               = (uint64_t) msizeof(struct module, list.next);
    xdb_metainfo_sizes.struct_module__sizeof__list_prev_ptr               = (uint64_t) msizeof(struct module, list.prev);
    xdb_metainfo_sizes.struct_module__sizeof__name                        = (uint64_t) msizeof(struct module, name);
    xdb_metainfo_sizes.struct_module__sizeof__init                        = (uint64_t) msizeof(struct module, init);
    xdb_metainfo_sizes.struct_module__sizeof__exit                        = (uint64_t) msizeof(struct module, exit);
    xdb_metainfo_sizes.struct_module__sizeof__module_init                 = (uint64_t) msizeof(struct module, module_init);
    xdb_metainfo_sizes.struct_module__sizeof__module_core                 = (uint64_t) msizeof(struct module, module_core);
    xdb_metainfo_sizes.struct_module__sizeof__init_size                   = (uint64_t) msizeof(struct module, init_size);
    xdb_metainfo_sizes.struct_module__sizeof__core_size                   = (uint64_t) msizeof(struct module, core_size);
    xdb_metainfo_sizes.struct_module__sizeof__init_text_size              = (uint64_t) msizeof(struct module, init_text_size);
    xdb_metainfo_sizes.struct_module__sizeof__core_text_size              = (uint64_t) msizeof(struct module, core_text_size);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
    xdb_metainfo_sizes.struct_module__sizeof__init_ro_size                = (uint64_t) msizeof(struct module, init_ro_size);
    xdb_metainfo_sizes.struct_module__sizeof__core_ro_size                = (uint64_t) msizeof(struct module, core_ro_size);
#else
    xdb_metainfo_sizes.struct_module__sizeof__init_ro_size                = (uint64_t) 0;
    xdb_metainfo_sizes.struct_module__sizeof__core_ro_size                = (uint64_t) 0;
#endif
    xdb_metainfo_sizes.struct_module__sizeof__sect_attrs_ptr              = (uint64_t) msizeof(struct module, sect_attrs);
    xdb_metainfo_sizes.struct_module_sect_attrs__sizeof                   = (uint64_t) sizeof(struct module_sect_attrs);
    xdb_metainfo_sizes.struct_module_sect_attrs__sizeof__nsections        = (uint64_t) msizeof(struct module_sect_attrs, nsections);
    xdb_metainfo_sizes.struct_module_sect_attrs__sizeof__attrs_array      = (uint64_t) msizeof(struct module_sect_attrs, attrs);
    xdb_metainfo_sizes.struct_module_sect_attr__sizeof                    = (uint64_t) sizeof(struct module_sect_attr);
    xdb_metainfo_sizes.struct_module_sect_attr__sizeof__name_ptr          = (uint64_t) msizeof(struct module_sect_attr, name);
    xdb_metainfo_sizes.struct_module_sect_attr__sizeof__addr              = (uint64_t) msizeof(struct module_sect_attr, address);
    // enums
    xdb_metainfo_enumvals.enum_module_state__MODULE_STATE_LIVE            = (uint64_t) MODULE_STATE_LIVE;
    xdb_metainfo_enumvals.enum_module_state__MODULE_STATE_COMING          = (uint64_t) MODULE_STATE_COMING;
    xdb_metainfo_enumvals.enum_module_state__MODULE_STATE_GOING           = (uint64_t) MODULE_STATE_GOING;
}

//
////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
// The initialization function of this kernel module. Called by the kernel
// when the module gets loaded via insmod.
//
static int
__init
xdbntf_init(void)
{
    if (register_module_notifier(&module_state_nb) != 0) {
        is_started = 0;
        return -1;
    }

    fill_xdb_metainfo();
    is_started = 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
    printk(KERN_NOTICE "xdbntf: issuing initial notification\n");
    MAGIC_BREAK(XDBNTF_MODULE_COMING, THIS_MODULE);
#endif

    return 0;
}


////////////////////////////////////////////////////////////////////////////////
// The cleanup function of this kernel module. Called by the kernel
// when the module gets unloaded via rmmod.
//
static void
__exit
xdbntf_exit(void)
{
    if (is_started) {
        unregister_module_notifier(&module_state_nb);
        MAGIC_BREAK(XDBNTF_XDBNTF_GOING, 0);
    }
}


module_init(xdbntf_init);
module_exit(xdbntf_exit);
MODULE_LICENSE("GPL");
