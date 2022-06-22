/*
 * Netlink helper functions for driver wrappers
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NETLINK_H
#define NETLINK_H

struct netlink_data;
struct ifinfomsg;

struct netlink_config {
	void *ctx;
	void (*newlink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,
			   size_t len);
	void (*dellink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,
			   size_t len);
	void (*newneigh_cb)(void *ctx, struct nlmsghdr *h);
	void (*delneigh_cb)(void *ctx, struct nlmsghdr *h);
};

static inline u32 nl_mgrp(u32 group)
{
	if (group > 31 ) {
		fprintf(stderr, "Use setsockopt for this group %d\n", group);
		return(0);
	}
	return group ? (1 << (group - 1)) : 0;
}

struct netlink_data * netlink_init(struct netlink_config *cfg);
void netlink_deinit(struct netlink_data *netlink);
int netlink_send_oper_ifla(struct netlink_data *netlink, int ifindex,
			   int linkmode, int operstate);

#endif /* NETLINK_H */
