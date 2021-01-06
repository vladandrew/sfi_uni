#include "kasan_internal.h"
#include <stdbool.h>
#include <uk/print.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <uk/kasan.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Part of internal compiler interface */
#define KASAN_SHADOW_SCALE_SHIFT 3
#define KASAN_ALLOCA_REDZONE_SIZE 32

#define KASAN_SHADOW_SCALE_SIZE (1 << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK (KASAN_SHADOW_SCALE_SIZE - 1)

#define roundup(x, y) ((((x) + ((y)-1)) / (y)) * (y))

#define is_aligned(addr, size)                                                 \
  ({                                                                           \
    intptr_t _addr = (intptr_t)(addr);                                         \
    intptr_t _size = (intptr_t)(size);                                         \
    !(_addr & (_size - 1));                                                    \
  })

typedef unsigned long uptr;

struct __asan_global_source_location {
  const char *filename;
  int line_no;
  int column_no;
};


struct __asan_global {
  uptr beg;                /* The address of the global */
  uptr size;                    /* The original size of the global */
  uptr size_with_redzone;       /* The size with the redzone */
  const char *name;               /* Name as a C string */
  const char *module_name;        /* Module name as a C string */
  uptr has_dynamic_init; /* Does the global have dynamic initializer */
  struct __asan_global_source_location *location; /* Location of a global */
  uptr odr_indicator; /* The address of the ODR indicator symbol */
};

static int kasan_ready = 1;

static const char *code_name(uint8_t code) {
  switch (code) {
    case KASAN_CODE_STACK_LEFT:
    case KASAN_CODE_STACK_MID:
    case KASAN_CODE_STACK_RIGHT:
      return "stack buffer-overflow";
    case KASAN_CODE_GLOBAL_OVERFLOW:
      return "global buffer-overflow";
    case KASAN_CODE_KMEM_FREED:
      return "kmem use-after-free";
    case KASAN_CODE_POOL_OVERFLOW:
      return "pool buffer-overflow";
    case KASAN_CODE_POOL_FREED:
      return "pool use-after-free";
    case KASAN_CODE_KMALLOC_OVERFLOW:
      return "buffer-overflow";
    case KASAN_CODE_KMALLOC_FREED:
      return "use-after-free";
    case 1 ... 7:
      return "partial redzone";
    default:
      return "unknown redzone";
  }
}

/* Check whether all bytes from range [addr, addr + size) are mapped to
 * a single shadow byte */
static inline bool access_within_shadow_byte(uintptr_t addr,
                                                             size_t size) {
  return (addr >> KASAN_SHADOW_SCALE_SHIFT) ==
         ((addr + size - 1) >> KASAN_SHADOW_SCALE_SHIFT);
}

static inline bool shadow_1byte_isvalid(uintptr_t addr,
                                                        uint8_t *code) {
  int8_t shadow_val = (int8_t)*kasan_md_addr_to_shad(addr);
  int8_t last = addr & KASAN_SHADOW_MASK;
  if (likely(shadow_val == 0 || last < shadow_val))
    return true;
  *code = shadow_val;
  return false;
}

static inline bool shadow_2byte_isvalid(uintptr_t addr,
                                                        uint8_t *code) {
  if (!access_within_shadow_byte(addr, 2))
    return shadow_1byte_isvalid(addr, code) &&
           shadow_1byte_isvalid(addr + 1, code);

  int8_t shadow_val = *kasan_md_addr_to_shad(addr);
  int8_t last = (addr + 1) & KASAN_SHADOW_MASK;
  if (likely(shadow_val == 0 || last < shadow_val))
    return true;
  *code = shadow_val;
  return false;
}

static inline bool shadow_4byte_isvalid(uintptr_t addr,
                                                        uint8_t *code) {
  if (!access_within_shadow_byte(addr, 4))
    return shadow_2byte_isvalid(addr, code) &&
           shadow_2byte_isvalid(addr + 2, code);

  int8_t shadow_val = *kasan_md_addr_to_shad(addr);
  int8_t last = (addr + 3) & KASAN_SHADOW_MASK;
  if (likely(shadow_val == 0 || last < shadow_val))
    return true;
  *code = shadow_val;
  return false;
}

static inline bool shadow_8byte_isvalid(uintptr_t addr,
                                                        uint8_t *code) {
  if (!access_within_shadow_byte(addr, 8))
    return shadow_4byte_isvalid(addr, code) &&
           shadow_4byte_isvalid(addr + 4, code);

  int8_t shadow_val = *kasan_md_addr_to_shad(addr);
  int8_t last = (addr + 7) & KASAN_SHADOW_MASK;
  if (likely(shadow_val == 0 || last < shadow_val))
    return true;
  *code = shadow_val;
  return false;
}

static inline bool
shadow_Nbyte_isvalid(uintptr_t addr, size_t size, uint8_t *code) {
  for (size_t i = 0; i < size; i++)
    if (unlikely(!shadow_1byte_isvalid(addr + i, code)))
      return false;
  return true;
}

static inline void shadow_check(uintptr_t addr, size_t size,
                                                bool read) {
  if (unlikely(!kasan_ready))
    return;
  if (unlikely(!kasan_md_addr_supported(addr)))
    return;

  uint8_t code = 0;
  bool valid = true;
  if (__builtin_constant_p(size)) {
    switch (size) {
      case 1:
        valid = shadow_1byte_isvalid(addr, &code);
        break;
      case 2:
        valid = shadow_2byte_isvalid(addr, &code);
        break;
      case 4:
        valid = shadow_4byte_isvalid(addr, &code);
        break;
      case 8:
        valid = shadow_8byte_isvalid(addr, &code);
        break;
    }
  } else {
    valid = shadow_Nbyte_isvalid(addr, size, &code);
  }

  if (unlikely(!valid)) {
    UK_CRASH("===========KernelAddressSanitizer===========\n"
            "ERROR:\n"
            "* invalid access to address %p\n"
            "* %s of size %lu\n"
            "* redzone code 0x%x (%s)\n"
            "============================================\n",
            (void *)addr, (read ? "read" : "write"), size, code,
            code_name(code));
  }
}

/* Marking memory has limitations captured by assertions in the code below.
 *
 * Memory is divided into 8-byte blocks aligned to 8-byte boundary. Each block
 * has corresponding descriptor byte in the shadow memory. You can mark each
 * block as valid (0x00) or invalid (0xF1 - 0xFF). Blocks can be partially valid
 * (0x01 - 0x07) - i.e. prefix is valid, suffix is invalid.  Other variants are
 * NOT POSSIBLE! Thus `addr` and `total` must be block aligned.
 *
 * Note: use of __builtin_memset in this function is not optimal if its
 * implementation is instrumented (i.e. not written in asm). */
void kasan_mark(const void *addr, size_t valid, size_t total, uint8_t code) {
  UK_ASSERT(is_aligned(addr, KASAN_SHADOW_SCALE_SIZE));
  UK_ASSERT(is_aligned(total, KASAN_SHADOW_SCALE_SIZE));
  UK_ASSERT(valid <= total);

  int8_t *shadow = kasan_md_addr_to_shad((uintptr_t)addr);
  int8_t *end = shadow + total / KASAN_SHADOW_SCALE_SIZE;

  /* Valid bytes. */
  size_t len = valid / KASAN_SHADOW_SCALE_SIZE;
  __builtin_memset(shadow, 0, len);
  shadow += len;

  /* At most one partially valid byte. */
  if (valid & KASAN_SHADOW_MASK)
    *shadow++ = valid & KASAN_SHADOW_MASK;

  /* Invalid bytes. */
  if (shadow < end)
    __builtin_memset(shadow, code, end - shadow);
}

void kasan_mark_valid(const void *addr, size_t size) {
  kasan_mark(addr, size, size, 0);
}

void kasan_mark_invalid(const void *addr, size_t size, uint8_t code) {
  kasan_mark(addr, 0, size, code);
}

void init_kasan(void) {
  /* Set entire shadow memory to zero */
  //kasan_mark_valid((const void *)KASAN_MD_SANITIZED_START,
  //                 KASAN_MD_SANITIZED_SIZE);

  /* KASAN is ready to check for errors! */
  kasan_ready = 1;
}

#define DEFINE_ASAN_LOAD_STORE(size)                                           \
  void __asan_load##size##_noabort(uintptr_t addr) {                           \
    shadow_check(addr, size, true);                                            \
  }                                                                            \
  void __asan_store##size##_noabort(uintptr_t addr) {                          \
    shadow_check(addr, size, false);                                           \
  }


#define DEFINE_ASAN_LOAD_STORE_CLANG(size)                                           \
  void __asan_report_load##size##_noabort(uintptr_t addr) {                           \
    shadow_check(addr, size, true);                                            \
  }                                                                            \
  void __asan_report_store##size##_noabort(uintptr_t addr) {                          \
    shadow_check(addr, size, false);                                           \
  }

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);
DEFINE_ASAN_LOAD_STORE(16);

DEFINE_ASAN_LOAD_STORE_CLANG(1);
DEFINE_ASAN_LOAD_STORE_CLANG(2);
DEFINE_ASAN_LOAD_STORE_CLANG(4);
DEFINE_ASAN_LOAD_STORE_CLANG(8);
DEFINE_ASAN_LOAD_STORE_CLANG(16);

void __asan_loadN_noabort(uintptr_t addr, size_t size) {
  shadow_check(addr, size, true);
}

void __asan_storeN_noabort(uintptr_t addr, size_t size) {
  shadow_check(addr, size, false);
}

// for clang
void __asan_report_load_n_noabort(uintptr_t addr, size_t size) {
  shadow_check(addr, size, true);
}
void __asan_report_store_n_noabort(uintptr_t addr, size_t size) {
  shadow_check(addr, size, false);
}

/* Called at the end of every function marked as "noreturn".
 * Performs cleanup of the current stack's shadow memory to prevent false
 * positives. */
void __asan_handle_no_return(void) {
    // TODO
  //kstack_t *stack = &thread_self()->td_kstack;
  //kasan_mark_valid(stack->stk_base, stack->stk_size);
}
void __asan_register_globals(uptr globals, uptr n) {
  /*
  for (size_t i = 0; i < n; i++)
    kasan_mark(globals[i].beg, globals[i].size, globals[i].size_with_redzone,
               KASAN_CODE_GLOBAL_OVERFLOW); */
}


void __asan_unregister_globals(uptr globals __unused, uptr n __unused) {
}

/* Note: alloca is currently used in strntoul and test_sleepq_sync functions */

void __asan_alloca_poison(uptr addr, uptr size) {
  void *left_redzone = (int8_t *)addr - KASAN_ALLOCA_REDZONE_SIZE;
  size_t size_with_mid_redzone = roundup(size, KASAN_ALLOCA_REDZONE_SIZE);
  void *right_redzone = (int8_t *)addr + size_with_mid_redzone;

  kasan_mark_invalid(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
                     KASAN_CODE_STACK_LEFT);
  kasan_mark(addr, size, size_with_mid_redzone, KASAN_CODE_STACK_MID);
  kasan_mark_invalid(right_redzone, KASAN_ALLOCA_REDZONE_SIZE,
                     KASAN_CODE_STACK_RIGHT);
}

void __asan_allocas_unpoison(uptr begin, uptr size) {
  kasan_mark_valid(begin, size);
}

#ifdef __cplusplus
}
#endif
