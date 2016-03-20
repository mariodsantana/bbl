/* xt_bigblocklist - Xtables module to match against a large IP list   *
 * Copyright © Mario D. Santana, 2015   All rights reserved.           *
 */

/* This module works in the following way.
 * 0. Initialize "giant bitfield" array of 8-bit type
 *		1 bit for every possible IPv4 address
 * 		2**32 bits == 2**29 Bytes == 536,870,912 Bytes
 *      uint8_t bitfield[(2**29)]
 * 1. "Byte Index" = most significant bits of __be32 IP address
 *      #define index (ip >> 3) --> number 0 to 536,870,911
 * 2. "Bit Index" within that Byte is 3 least significant bits
 *      #define fieldoffset (ip & (2**3-1))  --> number 0 to 7
 * 3. the fieldoffset'th bit says whether if IP is in the list
 *      #define mask (1 << fieldoffset)  --> single bit in position 0-7
 * 4. IP is in list if bitfield[index] & mask
 *      return bitfield[ip >> 3] & (1 << (ip & 7))
 *
 * Note that we use the ip value in network byte order, so that consecutive
 * bits in the field don't always correspond to consecutive IP addresses.
 * This means the bitmap isn't portable between different-endian systems.
 */

#include <linux/fs.h>                 /* file and blk_dev ops */
#include <linux/ip.h>                 /* ip address manipulation */
#include <linux/module.h>             /* I'm a kernel module */
#include <linux/netfilter/x_tables.h> /* I'm a xt module */
#include <linux/blkdev.h>             /* I'm a block device driver */
#include "xt_bigblocklist.h"

MODULE_AUTHOR("Mario D. Santana");
MODULE_DESCRIPTION("Xtables: Big Blocklist");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_bigblocklist");

#define D(flags,...) if (flags & XT_BBL_VERBOSE) \
			pr_debug("bigblocklist: " __VA_ARGS__)
#define P(flags,...) if (flags & XT_BBL_VERBOSE) \
			pr_info("bigblocklist: " __VA_ARGS__)
#define E(...) printk(KERN_ERR "bigblocklist: " __VA_ARGS__)

/* Managing refcount for each match instance happens inside a critical section
 *
 * Would love to use per-rule mutex in the mtinfo struct, but don't know how
 * to initialize it from userspace when the mtinfo struct is initialized.
 */
static DEFINE_MUTEX(bbl_refcount_mutex);

/* Major device number for block device.  Set to 0 to let kernel choose. */
static int bbl_dev_major = 0;

/* Bitfield showing which device numbers are already in use. */
static uint32_t bbl_dev_minors = 0;

/* There's one block device per match instance, so width of this variable is
 * the maximum number of match instances to be brought up.  Since each match
 * instance also has its own IP bitfield of 1<<29, a 32-bit int here means
 * this module can use up more than 1<<34 Bytes of RAM, or ~17GB.
 */
#define BBL_MAXDEVS  (sizeof(bbl_dev_minors)*8)

/* each match instance has its own block device, this is the device info */
struct bbl_dev {
	struct request_queue *q;
	struct gendisk *gd;
	spinlock_t lock;
	int devnum;
};

/* Managing the bbl_dev_minors count happens inside a critical section */
static DEFINE_MUTEX(bbl_dev_minors_mutex);

/* Define the block device */
static struct block_device_operations bbl_dev_ops = {
	.owner           = THIS_MODULE,
};

/* Perform the read/write ops for the block device.
 *
 * @param q empty IO request queue
 * @param b BIO to process
 */
static void bbl_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev;
	struct bio_vec bvec;
	struct bvec_iter i;
	uint8_t *bfp;
	void *buf;
	struct bbl_mtinfo *info;

	bdev  = bio->bi_bdev;
	info  = bdev->bd_disk->private_data;
	if (bio_end_sector(bio) > get_capacity(bdev->bd_disk)) {
		D("won't process IO request past end of bitfield\n");
		bio_endio(bio,-EIO);
		return;
	}

	bfp = info->bitfield + (bio->bi_iter.bi_sector*512);
	if (bio->bi_rw & REQ_DISCARD) {
		bio_for_each_segment(bvec,bio,i) {
			D("zeroing %u bytes starting at %d\n",
					bvec.bv_len, bfp-info->bitfield);
			memset(bfp,0,bvec.bv_len);
			bfp += bvec.bv_len;
		}
		bio_endio(bio,0);
		return;
	}

	bio_for_each_segment(bvec, bio, i) {
		buf = kmap(bvec.bv_page) + bvec.bv_offset;
		if (bio_data_dir(bio) == READ) {
			D("reading %u bytes starting at %u\n",
					bvec.bv_len, bfp-info->bitfield);
			memcpy(buf,bfp,bvec.bv_len);
		} else {
			D("writing %u bytes starting at %u\n",
					bvec.bv_len, bfp-info->bitfield);
			memcpy(bfp,buf,bvec.bv_len);
		}
		kunmap(bvec.bv_page);
		bfp += bvec.bv_len;
	}
	bio_endio(bio,0);
} /* bbl_make_request */

/* Initialize block device functionality
 *
 * @param info module-specific data blob
 * @return 0 on success, <0 otherwise
 */
static int bbl_dev_setup(struct bbl_mtinfo *info)
{
	int err = -EIO;
	struct bbl_dev *dev;

	/* create device struct, init lock & devnum */
	dev = info->dev = kmalloc(sizeof(struct bbl_dev),GFP_KERNEL);
	if (dev == NULL) {
		E("failed to kmalloc block device management\n");
		goto out;
	}
	spin_lock_init(&dev->lock);
	if (mutex_lock_interruptible(&bbl_dev_minors_mutex) < 0) {
		D("bbl_dev_setup: failed to lock dev_minors mutex!  bail with EAGAIN\n");
		return -EAGAIN;
	}
	for (dev->devnum=0; dev->devnum < BBL_MAXDEVS; dev->devnum++)
		if (! (bbl_dev_minors & (1<<dev->devnum)) )
			break;
	if (dev->devnum >= BBL_MAXDEVS) {
		mutex_unlock(&bbl_dev_minors_mutex);
		E("maximum number of devices reached: %u\n", BBL_MAXDEVS);
		err = -EMFILE;
		goto out_free_dev;
	}
	bbl_dev_minors |= (1<<dev->devnum);
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
	dev->q->limits.discard_granularity = 1;
	dev->q->limits.max_discard_sectors = UINT_MAX;
	dev->q->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, dev->q);

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
	snprintf(dev->gd->disk_name,32,XT_BBL_DEVNAM "-%c",dev->devnum+'a');
	set_capacity(dev->gd, (1<<29)/512);
	add_disk(dev->gd);
	return 0;

out_free_queue:
	blk_cleanup_queue(dev->q);
out_free_dev_num:
	bbl_dev_minors &= ~(1<<dev->devnum);
out_free_dev:
	kfree(dev);
out:
	return err;
} /* bbl_dev_setup */

/* Manage reference counts, initialize bitmap & blockdev if first reference.
 *
 * @param par xtables-specific information for this attempted match
 * @return 0 on success, <0 otherwise
 */
static int bbl_check(const struct xt_mtchk_param *par)
{
	struct bbl_mtinfo *info = (struct bbl_mtinfo *)par->matchinfo;
	int ret;

	if (mutex_lock_interruptible(&bbl_refcount_mutex) < 0) {
		D("failed to lock refcount mutex!  bail with EAGAIN\n");
		return -EAGAIN;
	}
	info->refcount++;
	mutex_unlock(&bbl_refcount_mutex);
	if (info->refcount > 1) {
		D("have %d references, check function won't set up again\n",
				info->refcount-1);
		return 0;
	}

	if (info->bitfield == NULL) {
		D("new bitmap\n");
		info->bitfield = vzalloc(1<<29);
		if (info->bitfield == NULL) {
			E("failed to vzalloc bitmap memory\n");
			return -ENOMEM;
		}
	}
	P("initializing block IO\n");
	ret = bbl_dev_setup(info);
	if (ret < 0) {
		E("failed to initialize block IO\n");
		vfree(info->bitfield);
	}
	return ret;
} /* bbl_check */

/* Decrease reference counts on module resources, release if appropriate
 *
 * @param par xtables-specific information for this attempted match
 */
static void bbl_destroy(const struct xt_mtdtor_param *par)
{
	struct bbl_mtinfo *info = (struct bbl_mtinfo *)par->matchinfo;
	struct bbl_dev *dev = info->dev;
	int ret;

	ret = mutex_lock_interruptible(&bbl_refcount_mutex);
	if (ret < 0)
		D("bbl_destroy: failed to lock refcount mutex! proceeding anyway\n");
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
		D("bbl_destroy: failed to lock dev_minors mutex! proceeding anyway\n");
	bbl_dev_minors ^= (1<<dev->devnum);
	if (ret == 0)
		mutex_unlock(&bbl_dev_minors_mutex);
	kfree(info->dev);

	P("vfree()ing bigblocklist data at %p\n", info->bitfield);
	if (info->bitfield)
		vfree(info->bitfield);
} /* bbl_destroy */

#define check_bitfield(bf,addr) bf[addr >> 3] & (1 << (addr & 7));

/* @brief Perform a match against a packet
 *
 * @param skb packet to match against
 * @param par xtables-specific information for this attempted match
 * @return True if match successful, false if no match found
 */
static bool bbl_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct bbl_mtinfo *info = (struct bbl_mtinfo *)par->matchinfo;
	const struct iphdr *iph = ip_hdr(skb);
	bool hit = false;

	if (info->flags & (XT_BBL_SRC | XT_BBL_BOTH)) {
		hit = check_bitfield(info->bitfield,iph->saddr);
		/* XXX: removable debug block * /
		if (hit) {
			uint32_t ip = ntohl(iph->saddr);
			D("saddr matches %pI4 at byte %u, bit %u\n",
					&ip, iph->saddr >> 3,
					(1 << (iph->saddr & 7)));
		} /* */
	}
	if (!hit && info->flags & (XT_BBL_DST | XT_BBL_BOTH)) {
		hit = check_bitfield(info->bitfield,iph->daddr);
		/* XXX: removable debug block * /
		if (hit) {
			uint32_t ip = ntohl(iph->daddr);
			D("daddr matches %pI4 at byte %u, bit %u\n",
					&ip, iph->daddr >> 3,
					(1 << (iph->daddr & 7)));
		} /* */
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
		.name           = "bigblocklist",
		.revision       = 1,
		.family         = NFPROTO_IPV4,
		.match          = bbl_mt,
		.checkentry	= bbl_check,
		.destroy	= bbl_destroy,
		.matchsize      = sizeof(struct bbl_mtinfo),
		.me             = THIS_MODULE,
	},
};

/* Initialize the module
 *
 * @return 0 for success, <0 for error
 */
static int __init bbl_mt_init(void)
{
	printk("bigblocklist: exposing bitfield as " XT_BBL_DEVNAM "\n");
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
	printk("bigblocklist: removing block device " XT_BBL_DEVNAM "\n");
	unregister_blkdev(bbl_dev_major,XT_BBL_DEVNAM);

	xt_unregister_matches(bbl_mt_reg, ARRAY_SIZE(bbl_mt_reg));
} /* bbl_mt_exit */

module_init(bbl_mt_init);
module_exit(bbl_mt_exit);
