// SPDX-License-Identifier: GPL-3.0-only

#ifndef _UCI_HELPER_H_
#define _UCI_HELPER_H_

#include <uci.h>

int uci_open_package(const char *package_name, struct uci_context **ctx_out, struct uci_package **pkg_out);
void uci_close_package(struct uci_context *ctx, struct uci_package *pkg);

int uci_save_package_with_ctx(struct uci_context *ctx, struct uci_package *pkg);
int uci_save_commit_package_with_ctx(struct uci_context *ctx, struct uci_package **pkg_io);
int uci_set_config_path_staged(const char *config_path, const char *value);
int uci_set_option_with_ctx(struct uci_context *ctx, const char *package_name, const char *section_name, const char *option_name, const char *value);
int uci_delete_section_with_ctx(struct uci_context *ctx, const char *package_name, const char *section_name);
int uci_commit_package_by_name(const char *package_name);

int uci_get_value(const char *package, const char *section, const char *option, char *value, int v_len);
int uci_set_value(const char *package, const char *section, const char *option, const char *value);
int uci_del_value(const char *package, const char *section, const char *option);
int uci_add_list_value(const char *package, const char *section, const char *option, const char *value);
int uci_del_list_option(const char *package, const char *section, const char *option);

#endif /* _UCI_HELPER_H_ */
