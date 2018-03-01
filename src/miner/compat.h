#ifndef __COMPAT_H__
#define __COMPAT_H__

#include <json-c/json.h>

#include "../debug.h"
#include "../util.h"

#ifdef WIN32

#include <windows.h>

#define sleep(secs) Sleep((secs) * 1000)

enum {
	PRIO_PROCESS		= 0,
};

static inline int setpriority(int which, int who, int prio)
{
	return -!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

#endif /* WIN32 */

// liudf 20180227;
// from jansson to jsonc
#define json_t				json_object
#define	json_object_get		json_object_object_get
#define	json_string_value	json_object_get_string
#define	json_array_size		json_object_array_length
#define	json_array_get		json_object_array_get_idx
#define	json_integer_value	json_object_get_int
// liudf,attention!
#define	json_object_set		json_object_object_add
#define json_object_set_new	json_object_object_add
#define	json_string			json_object_new_string
#define	json_decref			json_object_put
#define	json_dumps			json_object_to_json_string
#define json_number_value	json_object_get_double

#define	applog				debug

#define	sleep(x)			s_sleep(x, 0)

static inline int json_is_object(const json_object *json_obj)
{
	return json_object_is_type(json_obj, json_type_object);
}

static inline int json_is_array(const json_object *json_obj)
{
	return json_object_is_type(json_obj, json_type_array);
}

static inline int json_is_integer(const json_object *json_obj)
{
	return json_object_is_type(json_obj, json_type_int);
}

static inline int json_is_string(const json_object *json_obj)
{
	return json_object_is_type(json_obj, json_type_string);
}

static inline int json_is_null(const json_object *json_obj)
{
	return json_object_is_type(json_obj, json_type_null);
}

static inline int json_is_false(const json_object *json_obj)
{
	return json_object_is_type(json_obj, json_type_boolean) && 
		json_object_get_boolean(json_obj) == 0;
}

static inline int json_is_true(const json_object *json_obj)
{
	return json_object_is_type(json_obj, json_type_boolean) && 
		json_object_get_boolean(json_obj) > 0;
}
#endif /* __COMPAT_H__ */
