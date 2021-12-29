/*
 * Wired Ethernet driver interface via Linux bridge
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004, Gunter Burchardt <tira@isx.de>
 * Copyright (c) 2022, Magnus Malm <magnusmalm@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <syslog.h>

#include "common.h"
#include "eloop.h"
#include <linux/rtnetlink.h>
#include "netlink.h"
#include "driver.h"
#include "driver_wired_common.h"

#include "common/eapol_common.h"
#include "eap_common/eap_defs.h"

#include <assert.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/rtnl.h>

#undef IFNAMSIZ
#include <net/if.h>
#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <linux/if_link.h>
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
#include <net/if_dl.h>
#include <net/if_media.h>
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__) */
#ifdef __sun__
#include <sys/sockio.h>
#endif /* __sun__ */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP   0x10000         /* driver signals L1 up         */
#endif
#ifndef IFF_DORMANT
#define IFF_DORMANT    0x20000         /* driver signals dormant       */
#endif


#ifndef NDA_RTA
#define NDA_RTA(r)							\
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

/* TODO: Make this configurable */
#define DRIVER_BRIDGE_SCRIPT_PATH "/bin/hostapd_auth_deauth.sh"

/* TODO: Make this configurable */
#define DRIVER_BRIDGE_MAC_HANDLED_CMD "/sbin/macdctl ignore"

#define DIR_ROOT    "/var/run/dot1x"
#define DIR_MAC     DIR_ROOT "/mac"
#define DIR_BY_IFNAME DIR_ROOT "/by_ifname"

#define STR_AUTHED "authorized"
#define STR_UNAUTHED "unauthorized"
#define STR_AUTH_IN_PROGRESS "authorizing"

#ifndef erase
static inline int erase(const char *path)
{
	if (remove(path) && errno != ENOENT)
		return -1;
	return 0;
}
#endif

static const u8 PAE_GROUP_ADDR[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

struct bridge_driver_data {
	struct driver_wired_common_data common;
	struct hostapd_data *hapd;
	struct netlink_data *netlink;

	int eap_active_authentication;
	u_int8_t own_addr[ETH_ALEN];
	int use_pae_group_addr;
	u_int8_t req_id;
	u_int flags;
	u_int8_t ifindex;
	u_int link_oper;
	void *ctx;
	int has_authed;
};

typedef struct {
	char mac_str[ETH_ALEN * 3];
	char ifname[IFNAMSIZ];
	char auth[16]; /* Auth state of MAC entry ("unauthorized", "authorizing", "authorized" */
} entry_t;

int recursive_delete(char *path)
{
	struct dirent *d;
	DIR *dir;
	char buf[PATH_MAX];

	dir = opendir(path);
	if (!dir)
		return 1;

	while ((d = readdir (dir))) {
		struct stat sb;

		if (!os_strcmp(".", d->d_name) || !os_strcmp("..", d->d_name))
			continue;

		os_snprintf(buf, sizeof(buf), "%s/%s", path, d->d_name);

		if (!stat (buf, &sb) && (sb.st_mode & S_IFMT) == S_IFDIR)
			recursive_delete(buf);

		erase(buf);

		/* Remove symlinked file too */
		os_snprintf(buf, sizeof(buf), "%s/%s", DIR_MAC, d->d_name);
		erase(buf);
	}

	closedir(dir);

	return 0;
}

static const char *ether_sprintf(const u8 *addr)
{
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		os_snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		os_snprintf(buf, sizeof(buf), MACSTR, 0, 0, 0, 0, 0, 0);
	return buf;
}


static int entry_set(const char *mac_str, const char *ifname, const char *auth)
{
	char path[64];
	FILE* fp;

	os_snprintf(path, sizeof(path), "%s/%s", DIR_MAC, mac_str);

	fp = fopen(path, "w");
	if (!fp) {
		wpa_printf(MSG_ERROR, "BRIDGE: Failed to open file %s.\n", path);
		return 1;
	}
	fprintf(fp, "mac:%s ifname:%s auth:%s\n", mac_str, ifname, auth);
	fclose(fp);

	return 0;
}

static int entry_get(const char *mac_str, entry_t *entry)
{
	char path[64];
	FILE* fp;

	os_snprintf(path, sizeof(path), "%s/%s", DIR_MAC, mac_str);

	fp = fopen(path, "r");
	if (!fp)
		return 1;

	if (fscanf(fp, "mac:%s ifname:%s auth:%s\n",
		   entry->mac_str, entry->ifname, entry->auth) != 3) {
		fclose(fp);
		return 1;
	}
	fclose(fp);

	return 0;
}

char *entry_get_ifname(const char *mac_str, char *ifname)
{
	entry_t entry;
	if (entry_get(mac_str, &entry))
		return NULL;

	os_strlcpy(ifname, entry.ifname, sizeof(entry.ifname));
	return ifname;
}

char *entry_get_auth(const char *mac_str, char *auth)
{
	entry_t entry;
	if (entry_get(mac_str, &entry))
		return NULL;

	os_strlcpy(auth, entry.auth, sizeof(entry.auth));
	return auth;
}

int entry_set_auth(const char* mac, const char *auth)
{
	entry_t entry;

	if (entry_get(mac, &entry))
		return 1;

	/* No need to set flag if it has the same value */
	if (os_strncmp(entry.auth, auth, sizeof(entry.auth)) == 0)
		return 0;

	os_strlcpy(entry.auth, auth, sizeof(entry.auth));

	entry_set(mac, entry.ifname, entry.auth);

	return 0;
}

int entry_has_mac_entry(const char *mac_str)
{
	char path[64];

	os_snprintf(path, sizeof(path), "%s/%s", DIR_MAC, mac_str);

	if (access(path, F_OK))
		return 0;

	return 1;
}

int entry_add(u8 *addr, const char *ifname, const char *auth)
{
	char path[64], lpath[64];

	const char *mac_str = ether_sprintf(addr);

	/* Check if entry already exists */
	if (entry_has_mac_entry(mac_str)) {
		wpa_printf(MSG_ERROR, "BRIDGE: 802.1x entry %s already exists.\n", mac_str);
		return 1;
	}

	/* Create directory */
	if (mkdir(DIR_ROOT, 0755) && errno != EEXIST) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Failed to create directory %s (%s)",
			   __func__, DIR_ROOT, strerror(errno));
		return 1;
	}

	os_snprintf(path, sizeof(path), "%s", DIR_MAC);
	if (mkdir(path, 0755) && errno != EEXIST) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Failed to create directory %s (%s)",
			   __func__, path, strerror(errno));
		return 1;
	}

	/* Add mac entry file */
	if (entry_set(mac_str, ifname, auth))
		return 1;

	/* Create by_ifname link */
	os_snprintf(lpath, sizeof(lpath), "%s", DIR_BY_IFNAME);
	if (mkdir(lpath, 0755) && errno != EEXIST) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Failed to create directory %s (%s)",
			   __func__, lpath, strerror(errno));
		return 1;
	}

	os_snprintf(lpath, sizeof(lpath), "%s/%s", DIR_BY_IFNAME, ifname);
	if (mkdir(lpath, 0755) && errno != EEXIST) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Failed to create directory %s (%s)",
			   __func__, lpath, strerror(errno));
		return 1;
	}

	os_snprintf(path, sizeof(path), "%s/%s", DIR_MAC, mac_str);
	os_snprintf(lpath, sizeof(lpath), "%s/%s/%s", DIR_BY_IFNAME, ifname, mac_str);
	if (symlink(path, lpath) && errno != EEXIST) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Failed to create symlink %s (%s)",
			   __func__, lpath, strerror(errno));
		return 1;
	}

	return 0;
}

int entry_is_authed(const char *mac_str) {
	char auth[16] = { 0 };

	entry_get_auth(mac_str, auth);
	return (strcmp(auth, STR_AUTHED) == 0);
}

int entry_is_unauthed(const char *mac_str) {
	char auth[16] = { 0 };

	entry_get_auth(mac_str, auth);
	return (strcmp(auth, STR_UNAUTHED) == 0);
}

int entry_remove(const char *mac_str, const char *ifname)
{
	char path[64];

	/* Remove by_ifname link */
	snprintf(path, sizeof(path), "%s/%s/%s", DIR_BY_IFNAME, ifname, mac_str);
	erase(path);

	/* Remove MAC entry */
	os_snprintf(path, sizeof(path), "%s/%s", DIR_MAC, mac_str);
	erase(path);

	return 0;
}

int entry_remove_all(const char *ifname)
{
	char path[64] = { 0 };
	os_snprintf(path, sizeof(path), "%s/%s", DIR_BY_IFNAME, ifname);

	/* Remove all files in the by_ifname directory */
	recursive_delete(path);

	/* Finally, remove the by_ifname/<ifname> directory itself */
	erase(path);

	return 0;
}

static int bridge_allow_mac_addr(struct bridge_driver_data *drv,
				 const char *auth, const char *mac_str) {
	int ret = 1;
	char cmd[256] = {0};
	entry_t entry;
	int authed = !os_strncmp(auth, STR_AUTHED, sizeof(STR_AUTHED));

	if (entry_get(mac_str, &entry)) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Entry for %s did not exist!",
			   __func__, mac_str);
		return ret;
	}

	os_snprintf(cmd, sizeof(cmd), "%s %s %s %s", DRIVER_BRIDGE_SCRIPT_PATH,
		    ((authed > 0) ? "replace" : "del"),
		    entry.mac_str, drv->common.ifname);

	ret = system(cmd);

	if (ret)
		wpa_printf(MSG_DEBUG, "BRIDGE: %s: Cmd \"%s\" returned %d, no entry update for %s",
			   __func__, cmd, ret, mac_str);
	else {
		wpa_printf(MSG_DEBUG, "BRIDGE: %s: Cmd \"%s\" %d",
			   __func__, cmd, ret);
		if (authed) {
			drv->has_authed++;
			syslog(LOG_AUTH | LOG_NOTICE, "Auth successful for %s on %s",
			       mac_str, drv->common.ifname);
			entry_set_auth(mac_str, auth);
		}
		else {
			drv->has_authed--;
			syslog(LOG_AUTH | LOG_WARNING, "Auth failed for %s on %s",
			       mac_str, drv->common.ifname);
			/* entry_remove(mac_str, drv->common.ifname); */
			entry_set_auth(mac_str, auth);
		}

		if (drv->has_authed < 0)
			drv->has_authed = 0;
	}

	return ret;
}

#ifdef __linux__
static void handle_data(void *ctx, unsigned char *buf, size_t len, void *sock_ctx)
{
	struct ieee8023_hdr *hdr;
	struct ieee802_1x_hdr *hdr_1x;
	u8 *pos, *sa;
	size_t left;
	union wpa_event_data event;

	struct bridge_driver_data *drv = (struct bridge_driver_data *)sock_ctx;

	/* must contain at least ieee8023_hdr 6 byte source, 6 byte dest,
	 * 2 byte ethertype */
	if (len < 14) {
		wpa_printf(MSG_MSGDUMP, "BRIDGE: handle_data: too short (%lu)",
			   (unsigned long) len);
		return;
	}

	hdr = (struct ieee8023_hdr *) buf;
	hdr_1x = (struct ieee802_1x_hdr *) (hdr + 1);
	if (hdr_1x) {
		wpa_printf(MSG_MSGDUMP, "BRIDGE: EAPOL packet version %d, type %d, len %d",
			   hdr_1x->version, hdr_1x->type, hdr_1x->length);
		if (hdr_1x->type > IEEE802_1X_TYPE_EAPOL_MKA) {
			wpa_printf(MSG_MSGDUMP, "BRIDGE: Unknown 802.1X type: %d. Ignore.",
				   hdr_1x->type);
			return;
		}
	}

	switch (ntohs(hdr->ethertype)) {
	case ETH_P_PAE:
		wpa_printf(MSG_MSGDUMP, "BRIDGE: Received EAPOL packet on %s", drv->common.ifname);
		sa = hdr->src;
		os_memset(&event, 0, sizeof(event));
		event.new_sta.addr = sa;

		char mac_str[18];
		os_strlcpy(mac_str, ether_sprintf(sa), sizeof(mac_str));

		/* Add connection to entry list if not already exists */
		if (!entry_has_mac_entry(mac_str)) {
			wpa_printf(MSG_MSGDUMP, "BRIDGE: %s: New STA %s connected on %s",
				   __func__, mac_str, drv->common.ifname);

			if (entry_add(sa, drv->common.ifname, "unauthorized")) {
				wpa_printf(MSG_ERROR, "BRIDGE: %s: Unable to add entry for STA %s",
					   __func__, mac_str);
				return;
			}

			/* Signal that we're handling this stations MAC address */
			char cmd[256] = {0};
			os_snprintf(cmd, sizeof(cmd), "%s %s", DRIVER_BRIDGE_MAC_HANDLED_CMD,
				    mac_str);
			int ret = system(cmd);
			wpa_printf(MSG_ERROR, "BRIDGE: %s: Cmd \"%s\" returned %d.",
				   __func__, cmd, ret);

			drv_event_disassoc(ctx, sa);
		}

		/* Re-authenticate on traffic from an already authenticated STA */
		if (entry_is_authed(mac_str)) {
			wpa_printf(MSG_MSGDUMP, "BRIDGE: %s: STA is already authenticated, "
				   "re-authenticating", __func__);
			drv_event_disassoc(ctx, sa);
		}

		wpa_supplicant_event(ctx, EVENT_NEW_STA, &event);

		pos = (u8 *) (hdr + 1);
		left = len - sizeof(*hdr);
		drv_event_eapol_rx(ctx, sa, pos, left);
		break;

	default:
		wpa_printf(MSG_DEBUG, "BRIDGE: Unknown ethertype 0x%04x in data frame",
			   ntohs(hdr->ethertype));
		break;
	}
}

static void handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s recv: %s", __func__, strerror(errno));
		return;
	}

	handle_data(eloop_ctx, buf, len, sock_ctx);
}
#endif /* __linux__ */


static int bridge_init_sockets(struct bridge_driver_data *drv, u8 *own_addr)
{
#ifdef __linux__
	struct ifreq ifr;
	struct sockaddr_ll addr;
	struct sockaddr_in addr2;

	drv->common.sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if (drv->common.sock < 0) {
		wpa_printf(MSG_ERROR, "BRIDGE: socket[PF_PACKET,SOCK_RAW]: %s",
			   strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->common.ifname, sizeof(ifr.ifr_name));
	if (ioctl(drv->common.sock, SIOCGIFINDEX, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "BRIDGE: ioctl(SIOCGIFINDEX): %s",
			   strerror(errno));
		return -1;
	}
	wpa_printf(MSG_DEBUG, "BRIDGE: %s: Setting ifname to %s", __func__,
		   drv->common.ifname);

	os_memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	wpa_printf(MSG_DEBUG, "BRIDGE: Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (eloop_register_read_sock(drv->common.sock, handle_read,
				     drv->common.ctx, drv)) {
		wpa_printf(MSG_INFO, "BRIDGE: Could not register read socket");
		return -1;
	}

	if (bind(drv->common.sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		{
			wpa_printf(MSG_ERROR, "BRIDGE: bind: %s", strerror(errno));
			return -1;
		}

	/* filter multicast address */
	if (wired_multicast_membership(drv->common.sock, ifr.ifr_ifindex,
				       pae_group_addr, 1) < 0) {
		wpa_printf(MSG_ERROR, "BRIDGE: Failed to add multicast group "
			   "membership");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->common.ifname, sizeof(ifr.ifr_name));
	if (ioctl(drv->common.sock, SIOCGIFHWADDR, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "BRIDGE: ioctl(SIOCGIFHWADDR): %s",
			   strerror(errno));
		return -1;
	}

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		wpa_printf(MSG_INFO, "BRIDGE: Invalid HW-addr family 0x%04x",
			   ifr.ifr_hwaddr.sa_family);
		return -1;
	}
	os_memcpy(own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	os_memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_port = htons(67);
	addr2.sin_addr.s_addr = INADDR_ANY;

	return 0;
#else /* __linux__ */
	return -1;
#endif /* __linux__ */
}



static int bridge_send_eapol(void *priv, const u8 *addr,
			     const u8 *data, size_t data_len, int encrypt,
			     const u8 *own_addr, u32 flags)
{
	struct bridge_driver_data *drv = priv;
	struct ieee8023_hdr *hdr;
	size_t len;
	u8 *pos;
	int res;

	len = sizeof(*hdr) + data_len;
	hdr = os_zalloc(len);
	if (hdr == NULL) {
		wpa_printf(MSG_INFO, "BRIDGE: malloc() failed for bridge_send_eapol(len=%lu)",
			   (unsigned long) len);
		return -1;
	}

	os_memcpy(hdr->dest, drv->use_pae_group_addr ? pae_group_addr : addr,
		  ETH_ALEN);
	os_memcpy(hdr->src, own_addr, ETH_ALEN);
	hdr->ethertype = htons(ETH_P_PAE);

	pos = (u8 *) (hdr + 1);
	os_memcpy(pos, data, data_len);

	res = send(drv->common.sock, (u8 *) hdr, len, 0);
	os_free(hdr);

	if (res < 0)
		wpa_printf(MSG_ERROR, "BRIDGE: %s - packet len: %lu - failed: send: %s", __func__,
			   (unsigned long) len, strerror(errno));

	return res;
}

static void send_eapreq_ident(struct bridge_driver_data *drv)
{
	u16 x_hdr_len = ntohs(14);
	u16 hdr_len = ntohs(10);
	struct ieee802_1x_hdr x_hdr = {EAPOL_VERSION, IEEE802_1X_TYPE_EAP_PACKET, x_hdr_len} ;
	struct eap_hdr hdr = {EAP_CODE_REQUEST, drv->req_id++, hdr_len} ;
	u8 addr[6] = { 0 };
	u8 data[15] = { 0 };

	os_memcpy(&addr, PAE_GROUP_ADDR, ETH_ALEN);
	os_memcpy(&data, &x_hdr, sizeof(x_hdr));
	os_memcpy(&data[sizeof(x_hdr)], &hdr, sizeof(hdr));
	data[8] = EAP_TYPE_IDENTITY;
	os_memcpy(&data[9], "hello", sizeof("hello"));

	if (drv->link_oper && !drv->has_authed) {
		bridge_send_eapol(drv, addr, data, sizeof(data), 0, drv->own_addr, 0);
	} else {
		wpa_printf(MSG_ERROR, "BRIDGE: %s (%s, %s) No EAP Req Ident sent: "
			   "link_oper = %d, has_authed = %d\n", __func__,
			   drv->common.ifname, ether_sprintf(addr),
			   drv->link_oper, drv->has_authed);
	}
}

static void bridge_event_rtm_newlink(void *ctx, struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	struct bridge_driver_data *drv = ctx;
	char namebuf[IFNAMSIZ];

	if (drv->ifindex != ifi->ifi_index) {
		wpa_printf(MSG_DEBUG, "%s: RTM_NEWLINK: ifindex %d (%s) is not of "
			   "interest for ifindex %d iface %s",
			   __func__, ifi->ifi_index,
			   if_indextoname(ifi->ifi_index, namebuf),
			   drv->ifindex,
			   drv->common.ifname);
		return;
	}
	/* Ignore spurious newlink events with no actual state changes */
	if (ifi->ifi_flags == drv->flags)
		return;

	wpa_printf(MSG_DEBUG, "BRIDGE: RTM_NEWLINK: Flag changes on %s: Prev 0x%x, New 0x%x",
		   drv->common.ifname, drv->flags, ifi->ifi_flags);

	drv->flags = ifi->ifi_flags;

	drv->link_oper = ((drv->flags & IFF_UP) && (drv->flags & IFF_RUNNING));

	wpa_printf(MSG_DEBUG, "BRIDGE: RTM_NEWLINK: ifname=%s "
		   "ifi_index=%d ifi_flags=0x%x (%s%s%s%s)",
		   drv->common.ifname, ifi->ifi_index, drv->flags,
		   (drv->flags & IFF_UP) ? "[UP]" : "",
		   (drv->flags & IFF_RUNNING) ? "[RUNNING]" : "",
		   (drv->flags & IFF_LOWER_UP) ? "[LOWER_UP]" : "",
		   (drv->flags & IFF_DORMANT) ? "[DORMANT]" : "");

	if (drv->link_oper) {
		wpa_printf(MSG_DEBUG, "BRIDGE: RTM NEWLINK: Link operational on %s",
			   drv->common.ifname);
		send_eapreq_ident(drv);
	} else {
		wpa_printf(MSG_DEBUG, "BRIDGE: RTM NEWLINK: Link NOT operational on %s",
			   drv->common.ifname);
		entry_remove_all(drv->common.ifname);
		drv->has_authed = 0;
	}
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
			len, rta->rta_len);
	return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}



const char *ll_addr_n2a(const unsigned char *addr, int alen,
			char *buf, int blen)
{
	int i;
	int l;

	snprintf(buf, blen, "%02x", addr[0]);
	for (i = 1, l = 2; i < alen && l < blen; i++, l += 3)
		snprintf(buf + l, blen - l, ":%02x", addr[i]);
	return buf;
}

int nl_neigh_mac_str(struct nlmsghdr *n, char *mac_str)
{
	struct ndmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[NDA_MAX+1];
	__u32 ext_flags = 0;
	__u16 vid = 0;

	if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
		wpa_printf(MSG_DEBUG, "BRIDGE: %s: Not RTM_NEWNEIGH: %08x %08x %08x\n",
			   __func__, n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 1;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		wpa_printf(MSG_DEBUG, "BRIDGE: %s: wrong nlmsg len %d\n", __func__, len);
		return 1;
	}

	if (r->ndm_family != AF_BRIDGE)
		return 1;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[NDA_LLADDR]) {
		const unsigned char *lladdr;
		char b1[64] = { 0 };

		lladdr = ll_addr_n2a(RTA_DATA(tb[NDA_LLADDR]),
				     RTA_PAYLOAD(tb[NDA_LLADDR]),
				     b1, sizeof(b1));

		if (lladdr) {
			os_strlcpy(mac_str, b1, sizeof(b1));

			return 0;
		} else
			wpa_printf(MSG_DEBUG, "BRIDGE: %s: wrong nlmsg len %d\n", __func__, len);
	}

	return 1;
}

int nl_neigh_ifindex(struct nlmsghdr *n)
{
	struct ndmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;

	if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Not RTM_NEWNEIGH: %08x %08x %08x",
			   __func__, n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return -1;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: wrong nlmsg len %d\n", __func__, len);
		return -1;
	}

	if (r->ndm_family != AF_BRIDGE)
		return -1;

	if (r->ndm_ifindex < 1) {
		wpa_printf(MSG_ERROR, "BRIDGE: %s: Invalid ifindex %d for new neighbour. "
			   "(%08x %08x %08x)", __func__,
			   r->ndm_ifindex, n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return -1;
	}

	return r->ndm_ifindex;
}

static void bridge_event_rtm_newneigh(void *ctx, struct nlmsghdr *h)
{
	struct bridge_driver_data *drv = ctx;
	char mac_str[18] = { 0 };
	char ifname[IFNAMSIZ];
	entry_t entry;
	int ifindex;
	int ret;

	ifindex = nl_neigh_ifindex(h);

	/* Ignore loopback completely */
	if (ifindex <= 1)
		return;

	wpa_printf(MSG_DEBUG, "BRIDGE RTM_NEWNEIGH: ifindex %d. Our ifindex %d",
		   ifindex, drv->ifindex);

	if (!if_indextoname(ifindex, ifname)) {
		wpa_printf(MSG_DEBUG, "BRIDGE RTM_NEWNEIGH: Invalid ifname for ifindex %d.",
			   ifindex);
		return;
	}

	wpa_printf(MSG_DEBUG, "BRIDGE RTM_NEWNEIGH: ifname %s. Our ifname %s",
		   ifname, drv->common.ifname);

	ret = nl_neigh_mac_str(h, mac_str);

	/* If we've authed this MAC, but this newneigh event's ifindex does not match the authed
	   entry's ifindex, deauth that station because this most likely indicates that the station
	   has moved to an unmanaged port */
	if (!ret) {
		if (entry_get(mac_str, &entry)) {
			wpa_printf(MSG_DEBUG, "BRIDGE RTM_NEWNEIGH: No entry for %s", mac_str);
			return;
		}

		wpa_printf(MSG_DEBUG, "BRIDGE RTM_NEWNEIGH: MAC addr %s is %s",
			   mac_str, entry_is_authed(mac_str) ? "authed" : "unauthed.");

		if (entry_is_authed(mac_str) && ifindex != if_nametoindex(entry.ifname)) {
			wpa_printf(MSG_DEBUG, "BRIDGE RTM_NEWNEIGH: Authed MAC %s from "
				   "%s (%d) which is not under our control. Deauth it",
				   mac_str, ifname, ifindex);
			/* entry_remove(mac_str, drv->common.ifname); */
			entry_set_auth(mac_str, STR_UNAUTHED);
			drv->has_authed--;

			if (drv->has_authed < 0)
				drv->has_authed = 0;

			return;
		}
	}
}

static void bridge_event_rtm_delneigh(void *ctx, struct nlmsghdr *h)
{
	struct bridge_driver_data *drv = ctx;
	char mac_str[18] = { 0 };

	nl_neigh_mac_str(h, mac_str);

	if (mac_str[0]) {
		wpa_printf(MSG_DEBUG, "BRIDGE RTM_DELNEIGH: Entry to delete %s", mac_str);
		/* entry_remove(mac_str, drv->common.ifname); */
		entry_set_auth(mac_str, STR_UNAUTHED);
	}
}

static int bridge_event_init(struct bridge_driver_data *drv)
{
	struct netlink_config *cfg;
	char cmd[256] = {0};
	int ret;

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		return -1;
	cfg->ctx = drv;
	cfg->newlink_cb = bridge_event_rtm_newlink;
	cfg->delneigh_cb = bridge_event_rtm_delneigh;
	cfg->newneigh_cb = bridge_event_rtm_newneigh;
	drv->netlink = netlink_init(cfg);
	if (drv->netlink == NULL) {
		os_free(cfg);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "BRIDGE: %s: Flush all FDBs on '%s'",
		   __func__, drv->common.ifname);
	os_snprintf(cmd, sizeof(cmd), "ip link set dev %s type bridge_slave fdb_flush",
		    drv->common.ifname);

	ret = system(cmd);
	wpa_printf(MSG_DEBUG, "BRIDGE: %s: Cmd \"%s\" returned %d\n", __func__, cmd, ret);
	return 0;
}


static void bridge_driver_active_auth_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bridge_driver_data *drv = eloop_ctx;

	send_eapreq_ident(drv);

	eloop_register_timeout(drv->eap_active_authentication, 0,
			       bridge_driver_active_auth_timeout,
			       drv, NULL);
}

static void * bridge_driver_hapd_init(struct hostapd_data *hapd,
				      struct wpa_init_params *params)
{
	struct bridge_driver_data *drv;

	drv = os_zalloc(sizeof(struct bridge_driver_data));
	if (drv == NULL) {
		wpa_printf(MSG_INFO, "BRIDGE: Could not allocate memory for wired driver data");
		wpa_printf(MSG_ERROR, "BRIDGE: Initialize bridge driver for iface %s FAILED",
			   params->ifname);
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "BRIDGE: Initialize bridge driver for iface %s",
		   params->ifname);

	drv->common.ctx = hapd;
	drv->ctx = hapd;
	drv->flags = 0;
	os_strlcpy(drv->common.ifname, params->ifname,
		   sizeof(drv->common.ifname));
	drv->ifindex = if_nametoindex(drv->common.ifname);
	wpa_printf(MSG_DEBUG, "BRIDGE: drv->ifindex for iface %s is %d",
		   drv->common.ifname, drv->ifindex);
	drv->req_id = 0;
	drv->use_pae_group_addr = params->use_pae_group_addr;
	drv->eap_active_authentication = params->eap_active_authentication;

	entry_remove_all(drv->common.ifname);
	drv->has_authed = 0;

	if (bridge_init_sockets(drv, params->own_addr) ||
	    bridge_event_init(drv)) {
		os_free(drv);
		wpa_printf(MSG_ERROR, "BRIDGE: Initialize bridge driver for iface %s FAILED",
			   params->ifname);
		return NULL;
	}

	os_memcpy(drv->own_addr, params->own_addr, ETH_ALEN);

	if (drv->eap_active_authentication > 0) {
		wpa_printf(MSG_DEBUG, "BRIDGE: Register active auth timeout callback for %s.",
			   drv->common.ifname);

		eloop_register_timeout(drv->eap_active_authentication,
				       0, bridge_driver_active_auth_timeout,
				       drv, drv->common.ctx);
	}

	wpa_printf(MSG_DEBUG, "BRIDGE: Initialize bridge driver for iface %s done",
		   params->ifname);

	return drv;
}


static void bridge_driver_hapd_deinit(void *priv)
{
	struct bridge_driver_data *drv = priv;

	if (drv->common.sock >= 0) {
		eloop_unregister_read_sock(drv->common.sock);
		close(drv->common.sock);
	}

	os_free(drv);
}



static int sta_set_flags(void *priv, const u8 *addr, unsigned int total_flags,
			 unsigned int flags_or, unsigned int flags_and)
{
	assert (priv);
	assert (addr);
	struct bridge_driver_data *drv = priv;

	/* Authorized */
	if (flags_or & WPA_STA_AUTHORIZED) {
		if (entry_is_authed(ether_sprintf(addr))) {
			/* TODO: Do we need to do anything special here? */
			wpa_printf(MSG_DEBUG, "BRIDGE: %s reauthorized on %s",
				   ether_sprintf(addr), drv->common.ifname);
		} else {
			wpa_printf(MSG_DEBUG, "BRIDGE: %s authorized on %s",
				   ether_sprintf(addr), drv->common.ifname);
		}
		bridge_allow_mac_addr(drv, STR_AUTHED, ether_sprintf(addr));
	}

	/* Not authorized */
	if (!(flags_and & WPA_STA_AUTHORIZED)) {
		wpa_printf(MSG_DEBUG, "BRIDGE: %s unauthorized on %s",
			   ether_sprintf(addr), drv->common.ifname);

		bridge_allow_mac_addr(drv, STR_UNAUTHED, ether_sprintf(addr));
		/* TODO: When (if at all) do we remove the entry? */
		/* entry_remove(ether_sprintf(addr), drv->common.ifname); */
	}
	return 0;
}

/**
 * sta_remove - Remove STA
 */
int sta_remove (void *priv, const u8 *addr)
{
	assert (priv);
	assert (addr);

	struct bridge_driver_data *drv = priv;

	if (entry_is_unauthed(ether_sprintf(addr))) {
		wpa_printf(MSG_DEBUG, "BRIDGE: %s: %s not authenticated on %s. Nothing to do.",
			   __func__, ether_sprintf(addr), drv->common.ifname);
		return 0;
	}

	wpa_printf(MSG_DEBUG, "BRIDGE: %s: Remove STA %s on %s", __func__,
		   ether_sprintf(addr), drv->common.ifname);
	if (bridge_allow_mac_addr(drv, STR_UNAUTHED, ether_sprintf(addr)) != 0)
		return -1;

	return 0;
}

const struct wpa_driver_ops wpa_driver_bridge_ops = {
	.name = "bridge",
	.desc = "Wired Ethernet driver via bridge",
	.hapd_init = bridge_driver_hapd_init,
	.hapd_deinit = bridge_driver_hapd_deinit,
	.hapd_send_eapol = bridge_send_eapol,
	.get_ssid = driver_wired_get_ssid,
	.get_bssid = driver_wired_get_bssid,
	.get_capa = driver_wired_get_capa,
	.sta_set_flags = sta_set_flags,
	.sta_remove = sta_remove,
};
