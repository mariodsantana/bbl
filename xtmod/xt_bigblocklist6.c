/* xt_bigblocklist6 - Xtables module to match against a large IPv6 list
 * Copyright © Mario D. Santana, 2016   All rights reserved.
 */

/* This module maintains a sorted array of hi/lo pairs of IP addresses.
 * Lookups are performed with a binary search of the array.
 * Adds and deletes are performed from userspace, by writing to the block
 *   device exported by this module.  The module will interpret the written
 *   data as hi/lo pairs (32 Bytes == 1 pair) and will merge it into the
 *   array.  That merge might create a new entry, extending the array; or it
 *   might bridge two or more existing entries, collapsing them into a single
 *   entry and shrinking the array; or it might extend a single entry, not
 *   changing the array's length at all.  This happens no matter what offset
 *   the write is performed.
 * Reading the block device yields the raw binary form of the array, just
 *   as it is stored in memory.  So data written to the array may not be
 *   available as written.
 * Note that we use the ip values in network byte order, so that the sorted
 *   array might not seem sorted at first blush.  This means the raw array
 *   isn't portable between different-endian systems.
 */

#include <linux/fs.h>                 /* file and blk_dev ops */
#include <linux/ipv6.h>               /* ip address manipulation */
#include <linux/module.h>             /* I'm a kernel module */
#include <linux/netfilter/x_tables.h> /* I'm a xt module */
#include <linux/blkdev.h>             /* I'm a block device driver */
#include "xt_bigblocklist6.h"

MODULE_AUTHOR("Mario D. Santana");
MODULE_DESCRIPTION("Xtables: Big Blocklist for IPv6");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_bigblocklist6");

#define D(flags,...) if (flags & XT_BBL_VERBOSE) \
			pr_debug("bigblocklist6: " __VA_ARGS__)
#define P(flags,...) if (flags & XT_BBL_VERBOSE) \
			pr_info("bigblocklist6: " __VA_ARGS__)
#define E(...) printk(KERN_ERR "bigblocklist6: " __VA_ARGS__)

/* Managing refcount for each match instance happens inside a critical section
 *
 * Would love to use per-rule mutex in the mtinfo6 struct, but don't know how
 * to initialize it from userspace when the mtinfo6 struct is initialized.
 */
static DEFINE_MUTEX(bbl_refcount_mutex);

/* Ditto for merge operations. */
static DEFINE_MUTEX(bbl_lohi_mutex);

/* Major device number for block device.  Set to 0 to let kernel choose */
static int bbl_dev_major = 0;

/* Bitfield showing which device numbers are already in use. */
static uint32_t bbl_dev_minors = 0;

/* There's one block device per match instance, so width of this variable is
 * the maximum number of match instances to be brought up.  This module really
 * only makes sense for large blocklists, which use lots of RAM, so 32 should
 * be a reasonable maximum.
 */
#define BBL_MAXDEVS (sizeof(bbl_dev_minors)*8)

/* Each match instance has its own block device, this is the device info. */
struct bbl_dev {
	struct request_queue *q;
	struct gendisk *gd;
	spinlock_t lock;
	int devnum;
};

/* Managing the bbl_dev_minors count happens inside a critical section. */
static DEFINE_MUTEX(bbl_dev_minors_mutex);

/* Define the block device */
static struct block_device_operations bbl_dev_ops = {
	.owner           = THIS_MODULE,
};

/* Compare IPv6 addresses
 *
 * @param a IPv6 address to compare
 * @param a IPv6 address to compare
 * @return -2/-1/0/1/2 if a is less/less-by-1/equal/greater-by-1/greater than b
 */
static int bbl_cmp_v6ip(union bbl_v6ip *a, union bbl_v6ip *b)
{
	int i;

	for (i=0; i<16; i++) {
		if (a->ui8x16[i] > b->ui8x16[i])
			if (a->ui8x16[i]-1 == b->ui8x16[i])
				return 1;
			return 2;
		if (a->ui8x16[i] < b->ui8x16[i])
			if (a->ui8x16[i]+1 == b->ui8x16[i])
				return -1;
			return -2;
	}
	return 0;
} /* bbl_cmp_v6ip*/

/* Insert new lohi range into array.
 *
 * @param info mtinfo data blob
 * @param newlohi range to merge
 * @param r index after which to insert newlohi
 * @return 0 on success, <0 otherwise
 */
static int bbl_insert_lohi(struct bbl_mtinfo6 *info, struct bbl_lohi *newlohi,
		long long r)
{
	struct bbl_lohi *p, *o;
	const size_t s = sizeof(struct bbl_lohi);

	if (mutex_lock_interruptible(&bbl_lohi_mutex) < 0) {
		D("bbl_insert_lohi: failed to lock lohi mutex\n");
		return -EAGAIN;
	}
	if (info->lohisiz < s*(info->nlohi+1)) { /* copy to bigger area */
		p = vmalloc(info->lohisiz + s*4096);
		if (p == NULL) {
			E("vmalloc() failed for expanding array");
			mutex_unlock(&bbl_lohi_mutex);
			return -ENOMEM;
		}
		memcpy(p,info->lohi,s*r);
		p[r+1] = *newlohi;
		memcpy(p+r+2,info->lohi+r+1,s*(info->nlohi-r));
		o = info->lohi;
		info->lohi = p;
		info->nlohi++;
		info->lohisiz += s*4096;
		/* FIXME: matches might still be searching old array */
		vfree(o);
	} else { /* have enough room, just copy */
		memmove(info->lohi+r+2,info->lohi+r+1,info->nlohi-r);
		info->lohi[r+1] = *newlohi;
		info->nlohi++;
	}
	mutex_unlock(&bbl_lohi_mutex);
	return 0;
} /* bbl_insert_lohi */

/* Perform the write ops for the block device.  The array remains always
 *   sorted so matches won't fail unexpected ways; however, if the array must
 *   be collapsed, there's a race condition where matches may miss hits for
 *   addresses towards the end of the array.
 *
 * @param newlohi range to merge
 * @param info mtinfo data blob
 * @return 0 on success, <0 otherwise
 */
static int bbl_merge_lohi(struct bbl_lohi *newlohi, struct bbl_mtinfo6 *info)
{
	long long l, r, m;

	/* binary search, find where newlohi sorts in */
	l = 0;
	r = info->nlohi;
	while (l <= r) {
		m = (l+r)/2;
		if (bbl_cmp_v6ip(&newlohi->lo,&info->lohi[m].hi) >= 2)
			l = m + 1;
		else if (bbl_cmp_v6ip(&newlohi->hi,&info->lohi[m].lo) <= -2)
			r = m - 1;
		else
			break;
	}
	if (l > r) /* no overlaps, newlohi is independent entry */
		return bbl_insert_lohi(info,newlohi,r);
	if (mutex_lock_interruptible(&bbl_lohi_mutex) < 0) {
		D("bbl_merge_lohi: failed to lock lohi mutex\n");
		return -EAGAIN;
	}
	/* find lowest overlapping or contiguous entry */
	while (l > 0)
		if (bbl_cmp_v6ip(&newlohi->lo,&info->lohi[l-1].hi) < 2)
			l--;
	/* find highest overlapping or contiguous entry */
	while (r < info->nlohi)
		if (bbl_cmp_v6ip(&newlohi->hi,&info->lohi[r+1].lo) > -2)
			r++;
	/* set info->lohi[l] to expanded range */
	if (bbl_cmp_v6ip(&newlohi->lo,&info->lohi[l].lo) < 0)
		info->lohi[l].lo = newlohi->lo;
	if (bbl_cmp_v6ip(&newlohi->hi,&info->lohi[r].hi) > 0)
		info->lohi[l].hi = newlohi->hi;
	else if (bbl_cmp_v6ip(&info->lohi[r].hi,&info->lohi[l].hi) > 0)
		info->lohi[l].hi = info->lohi[r].hi;
	/* collapse multiple entries bridged by expanded range */
	m = r - l;
	if (m > 0) {
		info->nlohi -= m;
		/* right-to-left copy maintains sort */
		for (r=info->nlohi; r>l; r--)
			info->lohi[r] = info->lohi[r+m];
	}
	mutex_unlock(&bbl_lohi_mutex);
	return 0;
} /* bbl_merge_lohi */

/* Perform the read ops for the block device.
 *
 * @param q empty IO request queue
 * @param b BIO to process
 */
static void bbl_do_read(struct bio *bio)
{
	struct block_device *bdev;
	struct bio_vec bvec;
	struct bvec_iter i;
	uint8_t *ptr;
	const size_t s = sizeof(struct bbl_lohi);
	void *buf;
	struct bbl_mtinfo6 *info;

	bdev  = bio->bi_bdev;
	info  = bdev->bd_disk->private_data;
	if (mutex_lock_interruptible(&bbl_lohi_mutex) < 0) {
		D("bbl_merge_lohi: failed to lock lohi mutex\n");
		bio_endio(bio,-EAGAIN);
		return;
	}
	ptr = ((uint8_t *)info->lohi) + (bio->bi_iter.bi_sector*512);
	bio_for_each_segment(bvec, bio, i) {
		if (bvec.bv_offset+bvec.bv_len >= s*info->nlohi) {
			E("block IO attempted to read past array bounds\n");
			D("off(%u)+len(%u) >= size(%zu)*nlohi(%llu)\n",
				bvec.bv_offset, bvec.bv_len, s, info->nlohi);
			bio_endio(bio,-EIO);
			goto out_read_mutex;
		}
		buf = kmap(bvec.bv_page) + bvec.bv_offset;
		D("reading %u bytes starting at %p\n", bvec.bv_len, ptr);
		memcpy(buf,ptr,bvec.bv_len);
		kunmap(bvec.bv_page);
		ptr += bvec.bv_len;
	}
	bio_endio(bio,0);
out_read_mutex:
	mutex_unlock(&bbl_lohi_mutex);
} /* bbl_do_read */

/* Perform the write ops for the block device.
 *
 * @param b BIO to process
 */
static void bbl_do_write(struct bio *bio)
{
	struct block_device *bdev;
	struct bio_vec bvec;
	struct bvec_iter i;
	const size_t s = sizeof(struct bbl_lohi);
	uint8_t buf[s];
	uint8_t *ptr;
	int j, carry, ret;
	struct bbl_mtinfo6 *info;

	bdev  = bio->bi_bdev;
	info  = bdev->bd_disk->private_data;
	carry = 0;
	bio_for_each_segment(bvec, bio, i) {
		ptr = kmap(bvec.bv_page) + bvec.bv_offset;
		/* XXX: we deal with chunks of size s, what if a legit write
		 *      splits a bbl_lohi across multiple bvecs?
		 */
		for (j=0; j < bvec.bv_len/s; j++) {
			if (!carry) {
				memcpy(buf,ptr,s);
				ptr += s;
			} else {
				memcpy(buf+carry,ptr,s-carry);
				ptr += s-carry;
			}
			ret = bbl_merge_lohi((struct bbl_lohi *)buf, info);
			if (ret < 0) {
				kunmap(bvec.bv_page);
				bio_endio(bio,ret);
				return;
			}
		}
		carry = s - (bvec.bv_len % s);
		if (carry)
			memcpy(buf,ptr,carry);
		kunmap(bvec.bv_page);
	}
	bio_endio(bio,0);
} /* bbl_do_write */

/* Perform the read/write ops for the block device.
 *
 * @param q empty IO request queue
 * @param b BIO to process
 */
static void bbl_make_request(struct request_queue *q, struct bio *bio)
{
	if (bio_data_dir(bio) != READ)
		bbl_do_write(bio);
	else
		bbl_do_read(bio);
}

/* Initialize block device functionality
 *
 * @param info module-specific data blob
 * @return 0 on success, <0 otherwise
 */
static int bbl_dev_setup(struct bbl_mtinfo6 *info)
{
	int err = -EIO;
	struct bbl_dev *dev;

	/* create device struct, init lock & devnum */
	dev = info->dev = kmalloc(sizeof(struct bbl_dev),GFP_KERNEL);
	if (dev == NULL) {
		E("failed to kmalloc block device management\n");
		return -ENOMEM;
	}
	spin_lock_init(&dev->lock);
	if (mutex_lock_interruptible(&bbl_dev_minors_mutex) < 0) {
		D("bbl_dev_setup: failed to lock dev_minors mutex\n");
		return -EAGAIN;
	}
	for (dev->devnum=0; dev->devnum < BBL_MAXDEVS; dev->devnum++)
		if (!(bbl_dev_minors & (1 << dev->devnum)))
			break;
	if (dev->devnum >= BBL_MAXDEVS) {
		mutex_unlock(&bbl_dev_minors_mutex);
		E("maximum number of devices reached: %u\n", BBL_MAXDEVS);
		err = -EMFILE;
		goto out_free_dev;
	}
	bbl_dev_minors |= (1 << dev->devnum);
	mutex_unlock(&bbl_dev_minors_mutex);

	/* create & init IO queue */
	dev->q = blk_alloc_queue(GFP_KERNEL);
	if (!dev->q) {
		E("failed to allocate IO queue\n");
		goto out_free_dev_num;
	}
	dev->q->queuedata = info;
	blk_queue_make_request(dev->q, bbl_make_request);
	blk_queue_max_hw_sectors(dev->q, 1024);
	blk_queue_bounce_limit(dev->q, BLK_BOUNCE_ANY);

	/* create & init gendisk */
	dev->gd = alloc_disk(1);
	if (!dev->gd) {
		E("failed to allocate block device\n");
		goto out_free_queue;
	}
	dev->gd->major = bbl_dev_major;
	dev->gd->first_minor = dev->devnum;
	dev->gd->fops = &bbl_dev_ops;
	dev->gd->queue = dev->q;
	dev->gd->private_data = info;
	dev->gd->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	snprintf(dev->gd->disk_name, 32, XT_BBL_DEVNAM "-%c",
			dev->devnum + 'a');
	set_capacity(dev->gd,0); /* XXX: can we change this dynamically? */
	add_disk(dev->gd);
	return 0;

out_free_queue:
	blk_cleanup_queue(dev->q);
out_free_dev_num:
	bbl_dev_minors &= ~(1 << dev->devnum);
out_free_dev:
	kfree(dev);
out:
	return err;
} /* bbl_dev_setup */

/* Manage reference counts, initialize array & blockdev if first reference.
 *
 * @param par xtables-specific information for this match
 * @return 0 on success, <0 otherwise
 */
static int bbl_check(const struct xt_mtchk_param *par)
{
	struct bbl_mtinfo6 *info = (struct bbl_mtinfo6 *)par->matchinfo;
	int ret;

	if (mutex_lock_interruptible(&bbl_refcount_mutex) < 0) {
		D("Failed to lock refcount mutex!  Bail with EAGAIN\n");
		return -EAGAIN;
	}
	info->refcount++;
	mutex_unlock(&bbl_refcount_mutex);
	if (info->refcount > 1) {
		D("have %d references, check function won't set up again\n",
				info->refcount-1);
		return 0;
	}

	info->nlohi = 0;
	info->lohisiz = 0;
	info->lohi = NULL;

	P("initializing block IO\n");
	ret = bbl_dev_setup(info);
	if (ret < 0)
		E("failed to initialize block IO\n");
	return ret;
} /* bbl_check */

/* Decrease reference counts on module resources, release if appropriate
 *
 * @param par xtables-specific information for this match
 */
static void bbl_destroy(const struct xt_mtdtor_param *par)
{
	struct bbl_mtinfo6 *info = (struct bbl_mtinfo6 *)par->matchinfo;
	struct bbl_dev *dev = info->dev;
	int ret;

	ret = mutex_lock_interruptible(&bbl_refcount_mutex);
	if (ret < 0)
		D("bbl_destroy: failed to lock refcount mutex, proceeding\n");
	info->refcount--;
	if (info->refcount > 0) {
		mutex_unlock(&bbl_refcount_mutex);
		D("still have %d references, destroy function won't vfree()\n",
				info->refcount);
		return;
	}
	if (ret == 0)
		mutex_unlock(&bbl_refcount_mutex);

	/* FIXME: what happens if the block device is still held open? */
	P("dismantling block IO\n");
	if (dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}
	if (dev->q)
		blk_cleanup_queue(dev->q);
	ret = mutex_lock_interruptible(&bbl_dev_minors_mutex);
	if (ret < 0)
		D("bbl_destroy: failed to lock dev_minors mutex, proceeding\n");
	bbl_dev_minors ^= (1 << dev->devnum);
	if (ret == 0)
		mutex_unlock(&bbl_dev_minors_mutex);
	kfree(info->dev);

	P("vfree()ing array data at %p\n", info->lohi);
	if (info->lohi && info->lohisiz) {
		info->lohisiz = 0;
		vfree(info->lohi);
	}
} /* bbl_destroy */

/* @brief Perform a match against a packet
 *
 * @param info modules-specific data blob
 * @param ip address to search for in the array
 * @return True if match successful, false if no match found
 */
static bool bbl_do_match(struct bbl_mtinfo6 *info, struct in6_addr ip6)
{
	long long l, r, m;
	union bbl_v6ip *ip = (union bbl_v6ip *)&ip6;

	l = 0;
	r = info->nlohi;
	while (l <= r) {
		m = (l+r)/2;
		if (bbl_cmp_v6ip(ip,&info->lohi[m].hi) > 0)
			l = m + 1;
		else if (bbl_cmp_v6ip(ip,&info->lohi[m].lo) < 0)
			r = m - 1;
		else
			return true;
	}
	return false;
} /* bbl_do_match */

/* @brief Perform a match against a packet
 *
 * @param skb packet to match against
 * @param par xtables-specific information for this match
 * @return True if match successful, false if no match found
 */
static bool bbl_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct bbl_mtinfo6 *info = (struct bbl_mtinfo6 *)par->matchinfo;
	const struct ipv6hdr *iph6 = ipv6_hdr(skb);
	bool hit = false;

	if (info->flags & (XT_BBL_SRC | XT_BBL_BOTH)) {
		hit = bbl_do_match(info,iph6->saddr);
		/* XXX: removable debug block * /
		if (hit)
			D("saddr %pI6 matches\n", &iph6->saddr);
		/* */
	}
	if (!hit && info->flags & (XT_BBL_DST | XT_BBL_BOTH)) {
		hit = bbl_do_match(info,iph6->daddr);
		/* XXX: removable debug block * /
		if (hit)
			D("daddr %pI6 matches\n", &iph6->daddr);
		/* */
	}
	/* XXX: there's advice to use this tricky expression.  Measure speed
	 *      and choose.
	 */
	/* return !!hit ^ !!(info->flags & XT_BBL_INVERT); */
	if (info->flags & XT_BBL_INVERT)
		return !hit;
	return hit;
} /* bbl_mt */

/* Define the match module */
static struct xt_match bbl_mt_reg[] __read_mostly = {
	{
		.name           = "bigblocklist6",
		.revision       = 1,
		.family         = NFPROTO_IPV6,
		.match          = bbl_mt,
		.checkentry	= bbl_check,
		.destroy	= bbl_destroy,
		.matchsize      = sizeof(struct bbl_mtinfo6),
		.me             = THIS_MODULE,
	},
};

/* Initialize the module
 *
 * @return 0 for success, <0 for error
 */
static int __init bbl_mt_init(void)
{
	printk("bigblocklist: exposing bitfield as "
			XT_BBL_DEVNAM "\n");
	bbl_dev_major = register_blkdev(0,XT_BBL_DEVNAM);
	if (bbl_dev_major < 0) {
		E("failed to register block device\n");
		return bbl_dev_major;
	}

	return xt_register_matches(bbl_mt_reg, ARRAY_SIZE(bbl_mt_reg));
} /* bbl_mt_init */

/* Exit the module */
static void __exit bbl_mt_exit(void)
{
	printk("bigblocklist: removing block device "
			XT_BBL_DEVNAM "\n");
	unregister_blkdev(bbl_dev_major,XT_BBL_DEVNAM);

	xt_unregister_matches(bbl_mt_reg, ARRAY_SIZE(bbl_mt_reg));
} /* bbl_mt_exit */

module_init(bbl_mt_init);
module_exit(bbl_mt_exit);
