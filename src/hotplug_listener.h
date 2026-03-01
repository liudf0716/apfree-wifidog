// SPDX-License-Identifier: GPL-3.0-only

#ifndef _HOTPLUG_LISTENER_H_
#define _HOTPLUG_LISTENER_H_

struct bufferevent;

/* Handle one hotplug event JSON payload. If fd is non-NULL, writes Yes/No response. */
void hotplug_handle_event(struct bufferevent *fd, const char *event_json_data);

/* OpenWrt-only background listener for `ubus listen network.interface`. */
void thread_hotplug_listener(void *arg);

#endif
