// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "debug.h"
#include "uci_helper.h"

#define UCI_PATH_MAX 256

static int build_uci_path3(char *buf, size_t len, const char *package_name, const char *section_name, const char *option_name)
{
    if (!buf || len == 0 || !package_name || !section_name || !option_name) {
        return -1;
    }

    int n = snprintf(buf, len, "%s.%s.%s", package_name, section_name, option_name);
    if (n <= 0 || n >= (int)len) {
        return -1;
    }

    return 0;
}

static int build_uci_path2(char *buf, size_t len, const char *package_name, const char *section_name)
{
    if (!buf || len == 0 || !package_name || !section_name) {
        return -1;
    }

    int n = snprintf(buf, len, "%s.%s", package_name, section_name);
    if (n <= 0 || n >= (int)len) {
        return -1;
    }

    return 0;
}

static int lookup_uci_ptr(struct uci_context *ctx, struct uci_ptr *ptr, const char *path)
{
    if (!ctx || !ptr || !path) {
        return -1;
    }

    memset(ptr, 0, sizeof(*ptr));
    if (uci_lookup_ptr(ctx, ptr, (char *)path, true) != UCI_OK) {
        return -1;
    }

    return 0;
}

static int parse_uci_option_path(const char *config_path, char *package_name, size_t package_name_len, char *section_name, size_t section_name_len, const char **option_name)
{
    if (!config_path || !package_name || package_name_len == 0 || !section_name || section_name_len == 0 || !option_name) {
        return -1;
    }

    for (const char *p = config_path; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '_') {
            return -1;
        }
    }

    const char *dot1 = strchr(config_path, '.');
    if (!dot1) {
        return -1;
    }

    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        return -1;
    }

    size_t pkg_len = (size_t)(dot1 - config_path);
    size_t sec_len = (size_t)(dot2 - dot1 - 1);
    const char *opt = dot2 + 1;

    if (pkg_len == 0 || sec_len == 0 || *opt == '\0') {
        return -1;
    }

    if (pkg_len >= package_name_len || sec_len >= section_name_len) {
        return -1;
    }

    memcpy(package_name, config_path, pkg_len);
    package_name[pkg_len] = '\0';
    memcpy(section_name, dot1 + 1, sec_len);
    section_name[sec_len] = '\0';
    *option_name = opt;

    return 0;
}

int uci_open_package(const char *package_name, struct uci_context **ctx_out, struct uci_package **pkg_out)
{
    if (!package_name || !ctx_out || !pkg_out) return -1;

    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return -1;

    struct uci_package *pkg = NULL;
    if (uci_load(ctx, package_name, &pkg) != UCI_OK || !pkg) {
        uci_free_context(ctx);
        return -1;
    }

    *ctx_out = ctx;
    *pkg_out = pkg;
    return 0;
}

void uci_close_package(struct uci_context *ctx, struct uci_package *pkg)
{
    if (ctx && pkg) {
        uci_unload(ctx, pkg);
    }
    if (ctx) {
        uci_free_context(ctx);
    }
}

int uci_save_package_with_ctx(struct uci_context *ctx, struct uci_package *pkg)
{
    if (!ctx || !pkg) {
        return -1;
    }

    if (uci_save(ctx, pkg) != UCI_OK) {
        return -1;
    }

    return 0;
}

int uci_save_commit_package_with_ctx(struct uci_context *ctx, struct uci_package **pkg_io)
{
    if (!ctx || !pkg_io || !*pkg_io) {
        return -1;
    }

    if (uci_save(ctx, *pkg_io) != UCI_OK) {
        return -1;
    }

    if (uci_commit(ctx, pkg_io, false) != UCI_OK) {
        return -1;
    }

    return 0;
}

int uci_set_config_path_staged(const char *config_path, const char *value)
{
    if (!config_path || !value) {
        return -1;
    }

    char package_name[64];
    char section_name[128];
    const char *option_name = NULL;
    if (parse_uci_option_path(config_path, package_name, sizeof(package_name), section_name, sizeof(section_name), &option_name) != 0) {
        return -1;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package(package_name, &ctx, &pkg) != 0) {
        return -1;
    }

    int ret = 0;
    if (uci_set_option_with_ctx(ctx, package_name, section_name, option_name, value) != 0) {
        ret = -1;
    } else if (uci_save_package_with_ctx(ctx, pkg) != 0) {
        ret = -1;
    }

    uci_close_package(ctx, pkg);
    return ret;
}

int uci_set_option_with_ctx(struct uci_context *ctx, const char *package_name, const char *section_name, const char *option_name, const char *value)
{
    if (!ctx || !package_name || !section_name || !option_name || !value) return -1;

    char path[UCI_PATH_MAX];
    if (build_uci_path3(path, sizeof(path), package_name, section_name, option_name) != 0) {
        return -1;
    }

    struct uci_ptr ptr;
    if (lookup_uci_ptr(ctx, &ptr, path) != 0) {
        return -1;
    }

    ptr.value = (char *)value;
    if (uci_set(ctx, &ptr) != UCI_OK) {
        return -1;
    }

    return 0;
}

int uci_delete_section_with_ctx(struct uci_context *ctx, const char *package_name, const char *section_name)
{
    if (!ctx || !package_name || !section_name) return -1;

    char path[UCI_PATH_MAX];
    if (build_uci_path2(path, sizeof(path), package_name, section_name) != 0) {
        return -1;
    }

    struct uci_ptr ptr;
    if (lookup_uci_ptr(ctx, &ptr, path) != 0 || !ptr.s) {
        return -1;
    }

    if (uci_delete(ctx, &ptr) != UCI_OK) {
        return -1;
    }

    return 0;
}

int uci_commit_package_by_name(const char *package_name)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package(package_name, &ctx, &pkg) != 0) {
        return -1;
    }

    int rc = (uci_commit(ctx, &pkg, false) == UCI_OK) ? 0 : -1;

    uci_close_package(ctx, pkg);
    return rc;
}

int uci_del_value(const char *package, const char *section, const char *option)
{
    if (!package || !section || !option) {
        return -1;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package(package, &ctx, &pkg) != 0) {
        return -1;
    }

    char path[UCI_PATH_MAX];
    if (build_uci_path3(path, sizeof(path), package, section, option) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    struct uci_ptr ptr;
    if (lookup_uci_ptr(ctx, &ptr, path) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    int ret = 0;
    if (uci_delete(ctx, &ptr) != UCI_OK) {
        ret = -1;
    } else if (uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        ret = -1;
    }

    uci_close_package(ctx, pkg);
    return ret;
}

int uci_del_list_option(const char *package, const char *section, const char *option)
{
    if (!package || !section || !option) {
        return -1;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package(package, &ctx, &pkg) != 0) {
        debug(LOG_ERR, "Failed to open UCI package: %s", package);
        return -1;
    }

    char path[UCI_PATH_MAX];
    if (build_uci_path3(path, sizeof(path), package, section, option) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    struct uci_ptr ptr;
    if (lookup_uci_ptr(ctx, &ptr, path) != 0) {
        debug(LOG_DEBUG, "UCI option %s doesn't exist, consider it deleted", path);
        uci_close_package(ctx, pkg);
        return 0;
    }

    int changed = 0;
    int ret = 0;
    if (ptr.o) {
        if (ptr.o->type == UCI_TYPE_LIST) {
            struct uci_element *e, *tmp;
            struct uci_list *list = &ptr.o->v.list;

            uci_foreach_element_safe(list, tmp, e) {
                struct uci_ptr del_ptr;
                memset(&del_ptr, 0, sizeof(del_ptr));
                del_ptr.package = ptr.package;
                del_ptr.section = ptr.section;
                del_ptr.option = ptr.option;
                del_ptr.value = e->name;

                if (uci_del_list(ctx, &del_ptr) != UCI_OK) {
                    debug(LOG_ERR, "Failed to delete list item: %s", e->name);
                    ret = -1;
                } else {
                    changed = 1;
                }
            }
        } else {
            if (uci_delete(ctx, &ptr) != UCI_OK) {
                ret = -1;
            } else {
                changed = 1;
            }
        }

        if (ret == 0 && changed && uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
            ret = -1;
        }
    }

    uci_close_package(ctx, pkg);
    return ret;
}

int uci_add_list_value(const char *package, const char *section, const char *option, const char *value)
{
    if (!package || !section || !option || !value) {
        return -1;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package(package, &ctx, &pkg) != 0) {
        return -1;
    }

    char path[UCI_PATH_MAX];
    if (build_uci_path3(path, sizeof(path), package, section, option) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    struct uci_ptr ptr;
    if (lookup_uci_ptr(ctx, &ptr, path) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    ptr.value = (char *)value;

    int ret = 0;
    if (uci_add_list(ctx, &ptr) != UCI_OK) {
        ret = -1;
    } else if (uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        ret = -1;
    }

    uci_close_package(ctx, pkg);
    return ret;
}

int uci_set_value(const char *package, const char *section, const char *option, const char *value)
{
    if (!package || !section || !option || !value) {
        return -1;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package(package, &ctx, &pkg) != 0) {
        return -1;
    }

    int ret = 0;
    if (uci_set_option_with_ctx(ctx, package, section, option, value) != 0) {
        ret = -1;
    } else if (uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        ret = -1;
    }

    uci_close_package(ctx, pkg);
    return ret;
}

int uci_get_value(const char *package, const char *section, const char *option, char *value, int v_len)
{
    if (!package || !section || !option || !value || v_len <= 0) {
        return -1;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package(package, &ctx, &pkg) != 0) {
        return -1;
    }

    char path[UCI_PATH_MAX];
    if (build_uci_path3(path, sizeof(path), package, section, option) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    struct uci_ptr ptr;
    if (lookup_uci_ptr(ctx, &ptr, path) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    int ret = 0;
    if (ptr.o && ptr.o->type == UCI_TYPE_STRING) {
        strncpy(value, ptr.o->v.string, v_len - 1);
        value[v_len - 1] = '\0';
    } else {
        ret = -1;
    }

    uci_close_package(ctx, pkg);
    return ret;
}
