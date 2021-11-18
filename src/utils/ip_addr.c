/*
 * IP address processing
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <netdb.h>
#include <resolv.h>

#include "includes.h"

#include "common.h"
#include "ip_addr.h"

/**
 * Do a DNS lookup on fqdn_addr and, if successful, set addr accordingly. If
 * resolve fails, return 0, otherwise 1.
 */
int resolve_fqdn(const char *fqdn_addr, struct hostapd_ip_addr *addr)
{
	struct addrinfo *servinfo = NULL;
	struct addrinfo hints;
	struct addrinfo *next = NULL;
	int sfd = 0;
	int rc = 0;

	/* Ensure we do not get old DNS entries from getaddrinfo() */
	res_init();

	os_memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;     /* IPv4 or IPv6*/
	hints.ai_socktype = SOCK_DGRAM;  /* DGRAM sockets only */
	hints.ai_protocol = IPPROTO_UDP; /* UDP only */
	hints.ai_flags = AI_NUMERICSERV; /* No service name lookup */

	rc = getaddrinfo(fqdn_addr, NULL, &hints, &servinfo);
	if (rc != 0 || !servinfo) {
		freeaddrinfo(servinfo);
		return 0;
	}

	/* For each addrinfo entry (if any), validate it by trying to connect to
	 * it. Break out of the loop with first entry we can connect with. */
	for (next = servinfo; next != NULL; next = next->ai_next) {
		/* We're only interested in IPv4 or IPv6 entries */
		if (next->ai_family == AF_INET || next->ai_family == AF_INET6) {
			sfd = socket(next->ai_family, next->ai_socktype, next->ai_protocol);
			if (sfd == -1)
				continue;

			if (connect(sfd, next->ai_addr, next->ai_addrlen) == -1) {
				close(sfd);
				continue;
			}

			/* Connection established. Use this entry. */
			close(sfd);
			break;
                }
        }

	/* Could not connect using any entry returned by getaddrinfo() */
	if (next == NULL) {
		freeaddrinfo(servinfo);
		return 0;
	}

	/* Update addr with the entry we could connect with */
	addr->af = next->ai_family;
	switch (next->ai_family) {
	case AF_INET:
		addr->u.v4.s_addr = (*(struct sockaddr_in *)next->ai_addr).sin_addr.s_addr;
		break;

#ifdef CONFIG_IPV6
	case AF_INET6:
		os_memcpy(addr->u.v6.s6_addr, &(*(struct sockaddr_in6 *)next->ai_addr).sin6_addr,
			  sizeof(struct in6_addr));
		break;
#endif /* CONFIG_IPV6 */
	default:
		return 0;
	}

	freeaddrinfo(servinfo);
	return 1;
}

const char * hostapd_ip_txt(const struct hostapd_ip_addr *addr, char *buf,
			    size_t buflen)
{
	if (buflen == 0 || addr == NULL)
		return NULL;

	if (addr->af == AF_INET) {
		os_strlcpy(buf, inet_ntoa(addr->u.v4), buflen);
	} else {
		buf[0] = '\0';
	}
#ifdef CONFIG_IPV6
	if (addr->af == AF_INET6) {
		if (inet_ntop(AF_INET6, &addr->u.v6, buf, buflen) == NULL)
			buf[0] = '\0';
	}
#endif /* CONFIG_IPV6 */

	return buf;
}


int hostapd_parse_ip_addr(const char *txt, struct hostapd_ip_addr *addr)
{
#ifndef CONFIG_NATIVE_WINDOWS
	if (inet_aton(txt, &addr->u.v4)) {
		addr->af = AF_INET;
		return 0;
	}

#ifdef CONFIG_IPV6
	if (inet_pton(AF_INET6, txt, &addr->u.v6) > 0) {
		addr->af = AF_INET6;
		return 0;
	}
#endif /* CONFIG_IPV6 */
#endif /* CONFIG_NATIVE_WINDOWS */

	return -1;
}
