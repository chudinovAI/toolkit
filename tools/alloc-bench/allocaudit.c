#define _GNU_SOURCE
#include <link.h>
#include <stdint.h>
#include "../_bench_evidence.h"

#ifndef __GLIBC__
#error "alloc-bench auditing requires the glibc dynamic linker"
#endif

/* Audit callbacks never allocate or write to application-owned descriptors. */
unsigned int la_version(unsigned int version) {
    bench_init();
    bench_record('A', 0, 0, 0, 0, NULL);
    return version < LAV_CURRENT ? version : LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t ns, uintptr_t *cookie) {
    (void)ns;
    *cookie = (uintptr_t)map;
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

#if UINTPTR_MAX == UINT64_MAX
#define AUDIT_SYM Elf64_Sym
#define AUDIT_BIND la_symbind64
#else
#define AUDIT_SYM Elf32_Sym
#define AUDIT_BIND la_symbind32
#endif

uintptr_t AUDIT_BIND(AUDIT_SYM *sym, unsigned int ndx, uintptr_t *ref,
                     uintptr_t *def, unsigned int *flags, const char *name) {
    (void)ndx; (void)ref; (void)flags;
    if (name[0] == 'm' && name[1] == 'a' && name[2] == 'l' &&
        name[3] == 'l' && name[4] == 'o' && name[5] == 'c' && !name[6]) {
        /* An executable's canonical PLT entry can have a nonzero value but
         * remain undefined. It is a trampoline, not an allocator definition. */
        if (sym->st_shndx == SHN_UNDEF) return sym->st_value;
        struct link_map *map = (struct link_map *)*def;
        const char *path = map && map->l_name && *map->l_name ? map->l_name : "<main-executable>";
        bench_record('M', 0, 0, 0, 0, path);
    }
    return sym->st_value;
}
