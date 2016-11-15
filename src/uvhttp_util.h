#ifndef UVHTTP_UTIL_H__
#define UVHTTP_UTIL_H__

#include <stdlib.h>
#if defined(_MSC_VER) || defined(__MINGW64_VERSION_MAJOR)
#include <crtdbg.h>
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define UVHTTP_CONTAINER_PTR(  s, m, p) (s*)((unsigned char*)p - (int)(&((s*)0)->m))
#define UVHTTP_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define UVHTTP_SAFE_FREE(p) if(p){free(p); p = 0;}


#ifndef UVBUF_SIZE_MULTIPLIER
#define UVBUF_SIZE_MULTIPLIER 2
#endif

struct uvhttp_chunk {
    unsigned int len;
    char* base;
};

struct uvhttp_buffer {
  char *base; 
  unsigned int len;
  unsigned int size;
};

void uvhttp_buffer_init(
    struct uvhttp_buffer *, 
    unsigned int initial_capacity
    );

void uvhttp_buffer_free(
    struct uvhttp_buffer *
    );

unsigned int uvhttp_buf_append(
    struct uvhttp_buffer *, 
    const void *data, 
    unsigned int data_size
    );

unsigned int uvhttp_buf_insert(
    struct uvhttp_buffer *,
    unsigned int, 
    const void *, 
    unsigned int
    );

void uvhttp_buf_remove(
    struct uvhttp_buffer *,
    unsigned int data_size
    );

void uvhttp_buf_resize(
    struct uvhttp_buffer *, 
    unsigned int new_size
    );

void uvhttp_buf_trim(
    struct uvhttp_buffer *
    );

char* new_string_buffer( 
    const char* old_buffer,
    const char* append_buffer,
    int append_len
    );

char* new_cstring_buffer( 
    const char* old_buffer,
    const char* append_buffer,
    int append_len
    );

void free_string_buffer(
    char* string_buffer
    );

int uvhttp_vcmp(
    const struct uvhttp_chunk* str1,
    const char* str2
    );

#if defined(__cplusplus)
}
#endif /* __cplusplus */

#endif // UVHTTP_UTIL_H__