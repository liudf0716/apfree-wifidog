#include "uvhttp_base.h"
#include <uv.h>

struct uvhttp_header* uvhttp_headers_append( 
    struct uvhttp_header* headers,
    char* field,
    char* value
    )
{
    int len = 0;
    struct uvhttp_header* first = 0;
    if ( headers == 0) {
        headers = (struct uvhttp_header*)malloc( sizeof(struct uvhttp_header));
        headers->field = field;
        headers->value = value;
        headers->next = (struct uvhttp_header*)malloc( sizeof(struct uvhttp_header));
        headers->next->field = (void*)1;
        headers->next->next = headers;
        return headers->next;
    }
    first = headers->next;
    headers->next =  (struct uvhttp_header*)malloc( sizeof(struct uvhttp_header));
    len = (int)headers->field;
    headers->next->field = (char*)(++len);
    headers->next->next = first;
    headers->field = field;
    headers->value = value;

    return headers->next;
}

struct uvhttp_header* uvhttp_headers_begin( 
    struct uvhttp_header* headers
    )
{
    return headers->next;
}

struct uvhttp_header* uvhttp_headers_end( 
    struct uvhttp_header* headers
    )
{
    return headers;
}

void uvhttp_headers_free(
    struct uvhttp_header* headers
    )
{
    struct uvhttp_header* begin = headers;
    struct uvhttp_header* cur = begin;
    struct uvhttp_header* next = begin;
    do 
    {
        next = next->next;
        free( cur);
        cur = next;
    } while ( begin != cur);
}

int uvhttp_headers_size(
    struct uvhttp_header* headers
    )
{
    return (int)headers->field;
}
uvhttp_loop uvhttp_loop_new( )
{
    return (uvhttp_loop)uv_loop_new();
}

void uvhttp_loop_delete( 
    uvhttp_loop loop
    )
{
    uv_loop_delete( (uv_loop_t*)loop);
}

int uvhttp_run( 
    uvhttp_loop loop
    )
{
    return uv_run( (uv_loop_t*)loop, UV_RUN_DEFAULT);
}

void uvhttp_stop(
    uvhttp_loop loop
    )
{
    uv_stop( (uv_loop_t*)loop);
}
