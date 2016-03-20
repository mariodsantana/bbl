#ifndef _LINUX_NETFILTER_XT_BIGBLOCKLIST_H
#define _LINUX_NETFILTER_XT_BIGBLOCKLIST_H

/* Flags used in our mtinfo struct */
#define XT_BBL_INVERT     (0x01) /* Run in negated mode */
#define XT_BBL_SRC        (0x02) /* Match on SRC addresses */
#define XT_BBL_DST        (0x04) /* Match on DST addresses */
#define XT_BBL_BOTH       (0x08) /* Match on both SRC and DST */
#define XT_BBL_VERBOSE    (0x10) /* Show your work */

/* Prefix of name of block device exposing the bitfield. Make it < 29 chars */
#define XT_BBL_DEVNAM "bbl6_lohi"

/* XXX: are the kernel's ipv6 structs tightly packed? */
union bbl_v6ip {
	uint8_t  ui8x16[16];
	uint16_t ui16x8[8];
	uint32_t ui32x4[4];
	uint64_t ui64x2[2];
};

/* Each range has a lo and a hi address */
struct bbl_lohi {
	union bbl_v6ip lo;
	union bbl_v6ip hi;
};

/* Each match instance has an mtinfo struct */
struct bbl_mtinfo6 {
	struct bbl_lohi *lohi; /* array of entries, sorted by lo */
	long long nlohi; /* number of actual entries */
	long long lohisiz; /* array's allocated memory */
	unsigned int flags;
	unsigned int refcount;
	void *dev; /* struct bbl_dev6 * in kernel space */
};

#endif /* _LINUX_NETFILTER_XT_BIGBLOCKLIST_H */
