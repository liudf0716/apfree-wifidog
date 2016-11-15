#include "uvhttp_util.h"
#include <assert.h>
#include <string.h>

void uvhttp_buffer_init(
    struct uvhttp_buffer *buf,
    unsigned int initial_size
    )
{
    buf->len = buf->size = 0;
    buf->base = NULL;
    uvhttp_buf_resize(buf, initial_size);
}

void uvhttp_buffer_free(
    struct uvhttp_buffer *buf
    )
{
    if (buf->base != NULL) {
        free(buf->base);
        uvhttp_buffer_init(buf, 0);
    }
}

void uvhttp_buf_resize(
    struct uvhttp_buffer *a,
    unsigned int new_size
    )
{
    if (new_size > a->size || (new_size < a->size && new_size >= a->len)) {
        char *buf = (char *) realloc(a->base, new_size);
        /*
        * In case realloc fails, there's not much we can do, except keep things as
        * they are. Note that NULL is a valid return value from realloc when
        * size == 0, but that is covered too.
        */
        if (buf == NULL && new_size != 0) return;
        a->base = buf;
        a->size = new_size;
    }
}

void uvhttp_buf_trim(
    struct uvhttp_buffer *buf
    )
{
    uvhttp_buf_resize(buf, buf->len);
}

unsigned int uvhttp_buf_insert(
    struct uvhttp_buffer *a, 
    unsigned int off, 
    const void *buf, 
    unsigned int len
    )
{
    char *p = NULL;

    assert(a != NULL);
    assert(a->len <= a->size);
    assert(off <= a->len);

    /* check overflow */
    if (~(unsigned int) 0 - (unsigned int) a->base < len) return 0;

    if (a->len + len <= a->size) {
        memmove(a->base + off + len, a->base + off, a->len - off);
        if (buf != NULL) {
            memcpy(a->base + off, buf, len);
        }
        a->len += len;
    } else if ((p = (char *) realloc(
        a->base, (a->len + len) * UVBUF_SIZE_MULTIPLIER)) != NULL) {
            a->base = p;
            memmove(a->base + off + len, a->base + off, a->len - off);
            if (buf != NULL) {
                memcpy(a->base + off, buf, len);
            }
            a->len += len;
            a->size = a->len * UVBUF_SIZE_MULTIPLIER;
    } else {
        len = 0;
    }

    return len;
}

unsigned int uvhttp_buf_append(
    struct uvhttp_buffer *a, 
    const void *buf, 
    unsigned int len
    ) 
{
    return uvhttp_buf_insert(a, a->len, buf, len);
}

void uvhttp_buf_remove(
    struct uvhttp_buffer *mb, 
    unsigned int n
    ) 
{
    if (n > 0 && n <= mb->len) {
        memmove(mb->base, mb->base + n, mb->len - n);
        mb->len -= n;
    }
}

char* new_string_buffer( 
    const char* old_buffer,
    const char* append_buffer,
    int append_len
    )
{
    char* ret_buffer = 0;
    int ret_len = 0;
    int old_len = 0;
    if ( !append_len) {
        return (char*)old_buffer;
    }
    if ( old_buffer) {
        old_len = strlen( old_buffer);
    }
    ret_len = old_len + append_len + 1;
    ret_buffer = (char*)malloc( ret_len);
    if ( old_len > 0) {
        memcpy( ret_buffer, old_buffer, old_len );
        free( (char*)old_buffer);
    }
    memcpy( ret_buffer + old_len, append_buffer, append_len );
    ret_buffer[ ret_len - 1] = '\0' ;

    return ret_buffer;
}

char* new_cstring_buffer( 
    const char* old_buffer,
    const char* append_buffer,
    int append_len
    )
{
    char* ret_buffer = 0;
    int ret_len = 0;
    int old_len = 0;
    if ( old_buffer) {
        old_len = strlen( old_buffer);
    }
    ret_len = old_len + append_len + 1;
    ret_buffer = (char*)malloc( ret_len);
    if ( old_len > 0) {
        memcpy( ret_buffer, old_buffer, old_len );
    }
    if ( append_len > 0)
    {
        memcpy( ret_buffer + old_len, append_buffer, append_len );
    }
    ret_buffer[ ret_len - 1] = '\0' ;
    return ret_buffer;
}

void free_string_buffer(
    char* string_buffer
    )
{
    free( string_buffer);
}

int uvhttp_vcmp(
    const struct uvhttp_chunk* str1, 
    const char* str2
    )
{
    size_t n2 = strlen(str2), n1 = str1->len;
    int r = memcmp(str1->base, str2, (n1 < n2) ? n1 : n2);
    if (r == 0) {
        return n1 - n2;
    }
    return r;
}
