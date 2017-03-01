/*
 * Benchmarking page allocator: Cross CPU moving cost
 *
 * This benchmark tried to isolate the cost associated with allocating
 * a page on one CPU and freeing it on another.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/time.h>
#include <linux/time_bench.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/list.h>

static int verbose=1;

/* Quick and dirty way to unselect some of the benchmark tests, by
 * encoding this in a module parameter flag.  This is useful when
 * wanting to perf benchmark a specific benchmark test.
 *
 * Hint: Bash shells support writing binary number like: $((2#101010))
 * Use like:
 *  modprobe page_bench05_cross_cpu loops=$((10**7))  run_flags=$((2#010))
 */
static unsigned long run_flags = 0xFFFFFFFF;
module_param(run_flags, ulong, 0);
MODULE_PARM_DESC(run_flags, "Hack way to limit bench to run");
/* Count the bit number from the enum */
enum benchmark_bit {
	bit_run_bench_order0_compare,
};
#define bit(b)	(1 << (b))
#define run_or_return(b) do { if (!(run_flags & (bit(b)))) return; } while (0)

#define DEFAULT_ORDER 0
static int page_order = DEFAULT_ORDER;
module_param(page_order, uint, 0);
MODULE_PARM_DESC(page_order, "Parameter page order to use in bench");

static uint32_t loops = 1000000;
module_param(loops, uint, 0);
MODULE_PARM_DESC(loops, "Iteration loops");

/* Most simple case for comparison */
static int time_single_cpu_page_alloc_put(
	struct time_bench_record *rec, void *data)
{
	gfp_t gfp_mask = (GFP_ATOMIC | ___GFP_NORETRY);
	struct page *my_page;
	int i;

	time_bench_start(rec);
	/** Loop to measure **/
	for (i = 0; i < rec->loops; i++) {
		my_page = alloc_page(gfp_mask);
		if (unlikely(my_page == NULL))
			return 0;
		put_page(my_page);
	}
	time_bench_stop(rec, i);
	return i;
}

void noinline run_bench_order0_compare(uint32_t loops)
{
	run_or_return(bit_run_bench_order0_compare);
	/* For comparison: order-0 same cpu */
	time_bench_loop(loops, 0, "single_cpu_page_alloc_put",
			NULL, time_single_cpu_page_alloc_put);
}

/* TODO: Need a super efficient way to transfer objects between two
 * CPUs, as the purpose is to isolate the cost the page allocator code
 * of touching the page.
 *
 * Idea(1): Could use ptr_ring as it can avoid the CPU
 *          producer/consumer head/tail memory bouncing.
 *
 * Idea(2): Do bulking into a queue, that don't have the
 *          producer/consumer head/tail memory bouncing problem, like
 *          ptr_ring.
 */


int run_timing_tests(void)
{
	run_bench_order0_compare(loops);

	return 0;
}

static int __init page_bench05_module_init(void)
{
	if (verbose)
		pr_info("Loaded\n");

	if (run_timing_tests() < 0) {
		return -ECANCELED;
	}

	return 0;
}
module_init(page_bench05_module_init);

static void __exit page_bench05_module_exit(void)
{
	if (verbose)
		pr_info("Unloaded\n");
}
module_exit(page_bench05_module_exit);

MODULE_DESCRIPTION("Benchmarking page alloactor: Cross CPU cost");
MODULE_AUTHOR("Jesper Dangaard Brouer <netoptimizer@brouer.com>");
MODULE_LICENSE("GPL");