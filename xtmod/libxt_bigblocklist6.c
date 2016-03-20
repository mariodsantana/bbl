#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <xtables.h>
#include "xt_bigblocklist6.h"

#define D(flags,...) if (flags & XT_BBL_VERBOSE) \
			fprintf(stderr, "bigblocklist6: " __VA_ARGS__)

static const struct option bbl_mt_opts[] = {
	{.name = "src",      .has_arg = false,  .val = 's'},
	{.name = "dst",      .has_arg = false,  .val = 'd'},
	{.name = "both",     .has_arg = false,  .val = 'b'},
	{.name = "0verbose", .has_arg = false,  .val = 'v'},
	{NULL},
};

static void bbl_mt_help(void) {
	printf("Big IP Block List for IPv6 options:\n"
		"    --src --dst --both\n"
		"           match against src and/or dst addresses\n"
		"    --0verbose\n"
		"           show my work.\n");
} /* bbl_mt_help */

static void bbl_mt_init(struct xt_entry_match *match) {
	struct bbl_mtinfo6 *info = (void *)match->data;
	info->lohi = NULL;
	info->nlohi = 0;
	info->lohisiz = 0;
	info->flags = 0;
	info->refcount = 0;
	info->dev = NULL;
} /* bbl_mt_init */


static int bbl_mt_parse(int c, char **argv, int invert, unsigned int *flags,
			const void *entry, struct xt_entry_match **match) {
	struct bbl_mtinfo6 *info = (void *)(*match)->data;

	if (invert)
		info->flags |= XT_BBL_INVERT;
	switch (c) {
	case 's':
		*flags = info->flags |= XT_BBL_SRC;
		D(info->flags,"Will check src addresses (--src)\n");
		break;
	case 'd':
		*flags = info->flags |= XT_BBL_DST;
		D(info->flags,"Will check dst addresses (--dst)\n");
		break;
	case 'b':
		*flags = info->flags |= XT_BBL_BOTH;
		D(info->flags,"Will check src and dst addresses (--both)\n");
		break;
	case 'v':
		*flags = info->flags |= XT_BBL_VERBOSE;
		D(info->flags,"Will show my work (--0verbose)\n");
		break;
	default:
		D(info->flags,"Unknown argument %c\n",c);
		while (*argv) {
			D(info->flags,"argv item: %s\n",*argv);
			argv++;
		}
	}
	return true;
} /* bbl_mt_parse */

static void bbl_mt_check(unsigned int flags) {
	bool ok = true;
	char *msg = NULL;

	D(flags,"bigblocklist6: checking flags: %u\n",flags);
	if (! (flags & (XT_BBL_SRC | XT_BBL_DST | XT_BBL_BOTH)) )
		xtables_error(PARAMETER_PROBLEM,
			"xt_bigblocklist6: must specify src, dst, or both\n");
	if (flags & XT_BBL_VERBOSE) {
		fprintf(stderr,"bigblocklist6: good flags: %x\n----[ ",flags);
		if (flags & XT_BBL_DST)
			fprintf(stderr," --dst (0x%x) ",XT_BBL_DST);
		if (flags & XT_BBL_SRC)
			fprintf(stderr," --src (0x%x) ",XT_BBL_SRC);
		if (flags & XT_BBL_BOTH)
			fprintf(stderr," --both (0x%x) ",XT_BBL_BOTH);
		if (flags & XT_BBL_VERBOSE)
			fprintf(stderr," --0verbose (0x%x) ",XT_BBL_VERBOSE);
		if (flags & XT_BBL_INVERT)
			fprintf(stderr," ! (inversion) (0x%x) ",XT_BBL_INVERT);
		fprintf(stderr,"\n");
	}
} /* bbl_mt_check */

static void bbl_mt_save(const void *ip, const struct xt_entry_match *match) {
	const struct bbl_mtinfo6 *info = (const void *)match->data;

	D(info->flags,"Entering save routine.\n");
	if (info->flags & XT_BBL_INVERT)
		printf(" !");
	if (info->flags & XT_BBL_DST)
		printf(" --dst");
	if (info->flags & XT_BBL_SRC)
		printf(" --src");
	if (info->flags & XT_BBL_BOTH)
		printf(" --both");
	if (info->flags & XT_BBL_VERBOSE)
		printf(" --0verbose");
} /* bbl_mt_save */

static void bbl_mt_print(const void *ip, const struct xt_entry_match *match,
			 int numeric) {
	printf(" -m bigblocklist6");
	bbl_mt_save(ip, match);
} /* bbl_mt_print */

static struct xtables_match bbl_mt_reg = {
	.version        = XTABLES_VERSION,
	.name           = "bigblocklist6",
	.revision       = 1,
	.family         = NFPROTO_UNSPEC,
	.size           = XT_ALIGN(sizeof(struct bbl_mtinfo6)),
	.userspacesize  = XT_ALIGN(sizeof(struct bbl_mtinfo6)),
	.init           = bbl_mt_init,
	.help           = bbl_mt_help,
	.parse          = bbl_mt_parse,
	.final_check    = bbl_mt_check,
	.print          = bbl_mt_print,
	.save           = bbl_mt_save,
	.extra_opts     = bbl_mt_opts,
};

static void _init(void) {
	xtables_register_match(&bbl_mt_reg);
} /* _init */
