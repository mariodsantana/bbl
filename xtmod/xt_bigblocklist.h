#ifndef _LINUX_NETFILTER_XT_BIGBLOCKLIST_H
#define _LINUX_NETFILTER_XT_BIGBLOCKLIST_H

/* Flags used in our mtinfo struct */
#define XT_BBL_INVERT     (0x01) /* Run in negated mode */
#define XT_BBL_SRC        (0x02) /* Match on SRC addresses */
#define XT_BBL_DST        (0x04) /* Match on DST addresses */
#define XT_BBL_BOTH       (0x08) /* Match on both SRC and DST addresses */
#define XT_BBL_VERBOSE    (0x10) /* Show your work */

/* Prefix of name of block device exposing the bitfield. Make it < 29 chars */
#define XT_BBL_DEVNAM "bbl_bitfield"

struct bbl_mtinfo {
	uint8_t *bitfield;
	unsigned int flags;
	unsigned int refcount;
	void *dev; /* struct bbl_dev * in kernel space */
};

#endif /* _LINUX_NETFILTER_XT_BIGBLOCKLIST_H */
