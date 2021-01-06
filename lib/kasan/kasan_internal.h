#ifndef _SYS_KASAN_INTERNAL_H_
#define _SYS_KASAN_INTERNAL_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <uk/essentials.h>
/* Part of internal compiler interface */
#define KASAN_SHADOW_SCALE_SHIFT 3

#define __uk_image_symbol(addr)    ((unsigned long)(addr))
extern char _end[];
#define __END	__uk_image_symbol(_end)

/* Shadow memory */
// TODOO
#define SUPERPAGESIZE (1 << 22) /* 4 MB */
#define KASAN_MD_SHADOW_START __END
#define KASAN_MD_SHADOW_SIZE (1 << 24) /* 16 MB */

#define KASAN_MD_SHADOW_END (KASAN_MD_SHADOW_START + KASAN_MD_SHADOW_SIZE)
 
/* Sanitized memory (accesses within this range are checked) */
#define KASAN_MD_SANITIZED_START ALIGN_UP(KASAN_MD_SHADOW_START + KASAN_MD_SHADOW_SIZE, __PAGE_SIZE)
//0x15e0000//KERNEL_SPACE_BEGIN /* beginning of KSEG2 
#define KASAN_MD_SANITIZED_SIZE                                                \
  (KASAN_MD_SHADOW_SIZE << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_MD_SANITIZED_END                                                 \
  (KASAN_MD_SANITIZED_START + KASAN_MD_SANITIZED_SIZE)
 
/* Note: this offset has also to be explicitly set in CFLAGS_KASAN */
#define KASAN_MD_OFFSET                                                        \
  (KASAN_MD_SHADOW_START -                                                     \
   (KASAN_MD_SANITIZED_START >> KASAN_SHADOW_SCALE_SHIFT))
 
static inline int8_t *kasan_md_addr_to_shad(uintptr_t addr) {                                                                                                                                      
  return (int8_t *)(KASAN_MD_OFFSET + (addr >> KASAN_SHADOW_SCALE_SHIFT));
}
 
bool kasan_md_addr_supported(uintptr_t addr) {
  return addr >= KASAN_MD_SANITIZED_START && addr < KASAN_MD_SANITIZED_END;
}


#endif /* !_SYS_KASAN_INTERNAL_H_ */
