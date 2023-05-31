/*******************************************************************************

  Macros to compile Intel PRO/1000 Linux driver almost-as-is for Mac OS X.
 
*******************************************************************************/

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <os/log.h>
#include <libkern/libkern.h>
#include <mach/clock_types.h>
#include <IOKit/IOLib.h>

typedef __int64_t s64;
typedef __int32_t s32;
typedef __int16_t s16;
typedef __int8_t s8;
typedef __uint64_t u64;
typedef __uint32_t u32;
typedef __uint16_t u16;
typedef __uint8_t u8;
typedef u16 __u16;
typedef u8 __u8;
typedef u32 __u32;
typedef u64 __u64;

#ifndef __le16
#define __le16 __uint16_t
#endif
#ifndef __le32
#define __le32 __uint32_t
#endif
#ifndef __le64
#define __le64 __uint64_t
#endif
#ifndef __be16
#define __be16 __uint16_t
#endif
#ifndef __be32
#define __be32 __uint32_t
#endif
#ifndef __be64
#define __be64 __uint64_t
#endif

#define VLAN_PRIO_MASK        0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT        13

# define __force

static inline __le64 __cpu_to_le64p(const __u64 *p)
{
    return (__force __le64)*p;
}
static inline __u64 __le64_to_cpup(const __le64 *p)
{
    return (__force __u64)*p;
}
static inline __le32 __cpu_to_le32p(const __u32 *p)
{
    return (__force __le32)*p;
}
static inline __u32 __le32_to_cpup(const __le32 *p)
{
    return (__force __u32)*p;
}
static inline __le16 __cpu_to_le16p(const __u16 *p)
{
    return (__force __le16)*p;
}
static inline __u16 __le16_to_cpup(const __le16 *p)
{
    return (__force __u16)*p;
}

#define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
#define __cpu_to_be16(x) ((__force __be16)__swab16((x)))

#define le16_to_cpup __le16_to_cpup
#define le64_to_cpup __be64_to_cpup
#define le32_to_cpup __le32_to_cpup
#define cpu_to_be16p __cpu_to_be16p
#define cpu_to_le64s __cpu_to_le64s
#define le64_to_cpus __le64_to_cpus

#define cpu_to_be16 __cpu_to_be16

#define    sk_buff    __mbuf

#define    __iomem volatile

#define    dma_addr_t    IOPhysicalAddress

#define    ____cacheline_aligned_in_smp

#define    netdev_features_t    __uint32_t

#define cpu_to_le16(x)    OSSwapHostToLittleConstInt16(x)
#define cpu_to_le32(x)    OSSwapHostToLittleConstInt32(x)
#define    cpu_to_le64(x)    OSSwapHostToLittleConstInt64(x)
#define    le16_to_cpu(x)    OSSwapLittleToHostInt16(x)
#define    le32_to_cpu(x)    OSSwapLittleToHostInt32(x)
#define    be16_to_cpu(x)    OSSwapBigToHostInt16(x)

#define    writel(val, reg)    _OSWriteInt32(reg, 0, val)
#define    writew(val, reg)    _OSWriteInt16(reg, 0, val)
#define    readl(reg)    _OSReadInt32(reg, 0)
#define    readw(reg)    _OSReadInt16(reg, 0)
#define read_barrier_depends()

#define intelWriteMem8(reg, val8)       _OSWriteInt8((baseAddr), (reg), (val8))
#define intelWriteMem16(reg, val16)     OSWriteLittleInt16((baseAddr), (reg), (val16))
#define intelWriteMem32(reg, val32)     OSWriteLittleInt32((baseAddr), (reg), (val32))
#define intelReadMem8(reg)              _OSReadInt8((baseAddr), (reg))
#define intelReadMem16(reg)             OSReadLittleInt16((baseAddr), (reg))
#define intelReadMem32(reg)             OSReadLittleInt32((baseAddr), (reg))
#define intelFlush()                    OSReadLittleInt32((baseAddr), (E1000_STATUS))

#define NET_SKB_PAD 32

#ifdef    ALIGN
#undef    ALIGN
#endif
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#if __LP64__
#define BITS_PER_LONG 64
#elif __LP32__
#define BITS_PER_LONG 32
#endif

#define BITS_TO_LONGS(bits) \
(((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)

/* GFP_ATOMIC means both !wait (__GFP_WAIT not set) and use emergency pool */
#define GFP_ATOMIC      0

typedef unsigned int __u32;

#undef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)    dma_addr_t ADDR_NAME
#undef DEFINE_DMA_UNMAP_LEN
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)        __u32 LEN_NAME
#undef dma_unmap_addr
#define dma_unmap_addr(PTR, ADDR_NAME)        ((PTR)->ADDR_NAME)
#undef dma_unmap_addr_set
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)    (((PTR)->ADDR_NAME) = (VAL))
#undef dma_unmap_len
#define dma_unmap_len(PTR, LEN_NAME)        ((PTR)->LEN_NAME)
#undef dma_unmap_len_set
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))


#define    prefetch(x)
#define    prefetchw(x)
//#define    unlikely(x)    (x)
#define unlikely(x) __builtin_expect(!!(x), 0)
//#define    likely(x)    (x)
#define likely(x) __builtin_expect(!!(x), 1)
#define    BUG()

union ktime {
    s64    tv64;
};

typedef union ktime ktime_t;        /* Kill this */

typedef struct seqcount {
    unsigned sequence;
} seqcount_t;

struct u64_stats_sync {
#if BITS_PER_LONG == 32
    seqcount_t    seq;
#endif
};

typedef s64 time64_t;
typedef u64 timeu64_t;

struct timespec64 {
    time64_t    tv_sec;            /* seconds */
    long        tv_nsec;        /* nanoseconds */
};

#define TIME64_MAX            ((s64)~((u64)1 << 63))
#define KTIME_MAX            ((s64)~((u64)1 << 63))
#define KTIME_SEC_MAX            (KTIME_MAX / NSEC_PER_SEC)

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC    1000L
//#define NSEC_PER_USEC    1000L
//#define NSEC_PER_MSEC    1000000L
//#define USEC_PER_SEC    1000000L
//#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

#define BUG_ON(x) assert(x)

/**
 * ktime_set - Set a ktime_t variable from a seconds/nanoseconds value
 * @secs:    seconds to set
 * @nsecs:    nanoseconds to set
 *
 * Return: The ktime_t representation of the value.
 */
static inline ktime_t ktime_set(const s64 secs, const unsigned long nsecs)
{
    if (unlikely(secs >= KTIME_SEC_MAX))
        return (ktime_t){ .tv64 = KTIME_MAX };

    return (ktime_t) { .tv64 = secs * (long)NSEC_PER_SEC + (s64)nsecs };
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
#define ktime_sub(lhs, rhs) \
        ({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })

/* Add two ktime_t variables. res = lhs + rhs: */
#define ktime_add(lhs, rhs) \
        ({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })

/*
 * Add a ktime_t variable and a scalar nanosecond value.
 * res = kt + nsval:
 */
#define ktime_add_ns(kt, nsval) \
        ({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })

/*
 * Subtract a scalar nanosecod from a ktime_t variable
 * res = kt - nsval:
 */
#define ktime_sub_ns(kt, nsval) \
        ({ (ktime_t){ .tv64 = (kt).tv64 - (nsval) }; })

/* convert a timespec to ktime_t format: */
/*static inline ktime_t timespec_to_ktime(struct timespec ts)
{
    return ktime_set(ts.tv_sec, ts.tv_nsec);
}*/

/* convert a timespec64 to ktime_t format: */
static inline ktime_t timespec64_to_ktime(struct timespec64 ts)
{
    return ktime_set(ts.tv_sec, ts.tv_nsec);
}

/* convert a timeval to ktime_t format: */
/*static inline ktime_t timeval_to_ktime(struct timeval tv)
{
    return ktime_set(tv.tv_sec, tv.tv_usec * NSEC_PER_USEC);
}*/

/* Map the ktime_t to timespec conversion to ns_to_timespec function */
#define ktime_to_timespec(kt)        ns_to_timespec((kt).tv64)

/* Map the ktime_t to timespec conversion to ns_to_timespec function */
#define ktime_to_timespec64(kt)        ns_to_timespec64((kt).tv64)

/* Map the ktime_t to timeval conversion to ns_to_timeval function */
#define ktime_to_timeval(kt)        ns_to_timeval((kt).tv64)

/* Convert ktime_t to nanoseconds - NOP in the scalar storage format: */
#define ktime_to_ns(kt)            ((kt).tv64)


/**
 * ktime_equal - Compares two ktime_t variables to see if they are equal
 * @cmp1:    comparable1
 * @cmp2:    comparable2
 *
 * Compare two ktime_t variables.
 *
 * Return: 1 if equal.
 */
static inline int ktime_equal(const ktime_t cmp1, const ktime_t cmp2)
{
    return cmp1.tv64 == cmp2.tv64;
}

/**
 * ktime_compare - Compares two ktime_t variables for less, greater or equal
 * @cmp1:    comparable1
 * @cmp2:    comparable2
 *
 * Return: ...
 *   cmp1  < cmp2: return <0
 *   cmp1 == cmp2: return 0
 *   cmp1  > cmp2: return >0
 */
static inline int ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
{
    if (cmp1.tv64 < cmp2.tv64)
        return -1;
    if (cmp1.tv64 > cmp2.tv64)
        return 1;
    return 0;
}

/**
 * ktime_after - Compare if a ktime_t value is bigger than another one.
 * @cmp1:    comparable1
 * @cmp2:    comparable2
 *
 * Return: true if cmp1 happened after cmp2.
 */
static inline bool ktime_after(const ktime_t cmp1, const ktime_t cmp2)
{
    return ktime_compare(cmp1, cmp2) > 0;
}

/**
 * ktime_before - Compare if a ktime_t value is smaller than another one.
 * @cmp1:    comparable1
 * @cmp2:    comparable2
 *
 * Return: true if cmp1 happened before cmp2.
 */
static inline bool ktime_before(const ktime_t cmp1, const ktime_t cmp2)
{
    return ktime_compare(cmp1, cmp2) < 0;
}
#if 0
#if BITS_PER_LONG < 64
extern s64 __ktime_divns(const ktime_t kt, s64 div);
static inline s64 ktime_divns(const ktime_t kt, s64 div)
{
    /*
     * Negative divisors could cause an inf loop,
     * so bug out here.
     */
    BUG_ON(div < 0);
    if (__builtin_constant_p(div) && !(div >> 32)) {
        s64 ns = kt.tv64;
        u64 tmp = ns < 0 ? -ns : ns;

        do_div(tmp, div);
        return ns < 0 ? -tmp : tmp;
    } else {
        return __ktime_divns(kt, div);
    }
}
#else /* BITS_PER_LONG < 64 */
static inline s64 ktime_divns(const ktime_t kt, s64 div)
{
    /*
     * 32-bit implementation cannot handle negative divisors,
     * so catch them on 64bit as well.
     */
    WARN_ON(div < 0);
    return kt.tv64 / div;
}
#endif

static inline s64 ktime_to_us(const ktime_t kt)
{
    return ktime_divns(kt, NSEC_PER_USEC);
}

static inline s64 ktime_to_ms(const ktime_t kt)
{
    return ktime_divns(kt, NSEC_PER_MSEC);
}

static inline s64 ktime_us_delta(const ktime_t later, const ktime_t earlier)
{
       return ktime_to_us(ktime_sub(later, earlier));
}

static inline s64 ktime_ms_delta(const ktime_t later, const ktime_t earlier)
{
    return ktime_to_ms(ktime_sub(later, earlier));
}

#endif

static inline ktime_t ktime_add_us(const ktime_t kt, const u64 usec)
{
    return ktime_add_ns(kt, (s64)usec * (s64)NSEC_PER_USEC);
}

static inline ktime_t ktime_add_ms(const ktime_t kt, const u64 msec)
{
    return ktime_add_ns(kt, (s64)msec * (s64)NSEC_PER_MSEC);
}

static inline ktime_t ktime_sub_us(const ktime_t kt, const u64 usec)
{
    return ktime_sub_ns(kt, (s64)usec * (s64)NSEC_PER_USEC);
}

extern ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs);

/**
 * ktime_to_timespec_cond - convert a ktime_t variable to timespec
 *                format only if the variable contains data
 * @kt:        the ktime_t variable to convert
 * @ts:        the timespec variable to store the result in
 *
 * Return: %true if there was a successful conversion, %false if kt was 0.
 */
/*
static inline bool ktime_to_timespec_cond(const ktime_t kt,
                               struct timespec *ts)
{
    if (kt.tv64) {
        *ts = ktime_to_timespec(kt);
        return true;
    } else {
        return false;
    }
}*/

/**
 * ktime_to_timespec64_cond - convert a ktime_t variable to timespec64
 *                format only if the variable contains data
 * @kt:        the ktime_t variable to convert
 * @ts:        the timespec variable to store the result in
 *
 * Return: %true if there was a successful conversion, %false if kt was 0.
 */
/*static inline bool ktime_to_timespec64_cond(const ktime_t kt,
                               struct timespec64 *ts)
{
    if (kt.tv64) {
        *ts = ktime_to_timespec64(kt);
        return true;
    } else {
        return false;
    }
}*/

/*
 * The resolution of the clocks. The resolution value is returned in
 * the clock_getres() system call to give application programmers an
 * idea of the (in)accuracy of timers. Timer values are rounded up to
 * this resolution values.
 */
#define LOW_RES_NSEC        TICK_NSEC
#define KTIME_LOW_RES        (ktime_t){ .tv64 = LOW_RES_NSEC }

static inline ktime_t ns_to_ktime(u64 ns)
{
    static const ktime_t ktime_zero = { .tv64 = 0 };

    return ktime_add_ns(ktime_zero, (s64)ns);
}

static inline ktime_t ms_to_ktime(u64 ms)
{
    static const ktime_t ktime_zero = { .tv64 = 0 };

    return ktime_add_ms(ktime_zero, ms);
}

struct net_device_stats {
    unsigned long    rx_packets;                /* total packets received       */
    unsigned long    tx_packets;                /* total packets transmitted    */
    unsigned long    rx_bytes;                /* total bytes received         */
    unsigned long    tx_bytes;                /* total bytes transmitted      */
    unsigned long    rx_errors;                /* bad packets received         */
    unsigned long    tx_errors;                /* packet transmit problems     */
    unsigned long    rx_dropped;                /* no space in linux buffers    */
    unsigned long    tx_dropped;                /* no space available in linux  */
    unsigned long    multicast;                /* multicast packets received   */
    unsigned long    collisions;

    /* detailed rx_errors: */
    unsigned long    rx_length_errors;
    unsigned long    rx_over_errors;            /* receiver ring buff overflow  */
    unsigned long    rx_crc_errors;            /* recved pkt with crc error    */
    unsigned long    rx_frame_errors;        /* recv'd frame alignment error */
    unsigned long    rx_fifo_errors;            /* recv'r fifo overrun          */
    unsigned long    rx_missed_errors;        /* receiver missed packet       */

    /* detailed tx_errors */
    unsigned long    tx_aborted_errors;
    unsigned long    tx_carrier_errors;
    unsigned long    tx_fifo_errors;
    unsigned long    tx_heartbeat_errors;
    unsigned long    tx_window_errors;

    /* for cslip etc */
    unsigned long    rx_compressed;
    unsigned long    tx_compressed;
};

struct list_head {
    struct list_head *next, *prev;
};

struct timer_list {
    struct list_head entry;
    unsigned long expires;

    //spinlock_t lock;
    unsigned long magic;

    void (*function)(unsigned long);
    unsigned long data;

    //struct tvec_t_base_s *base;
};

struct work_struct {
    unsigned long pending;
    struct list_head entry;
    void (*func)(void *);
    void *data;
    void *wq_data;
    struct timer_list timer;
};

/* hlist_* code - double linked lists */
struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

static inline void __hlist_del(struct hlist_node *n)
{
    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;
    *pprev = next;
    if (next)
    next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
    __hlist_del(n);
    n->next = NULL;
    n->pprev = NULL;
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
    struct hlist_node *first = h->first;
    n->next = first;
    if (first)
        first->pprev = &n->next;
    h->first = n;
    n->pprev = &h->first;
}

static inline int hlist_empty(const struct hlist_head *h)
{
    return !h->first;
}
#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

#ifndef rcu_head
struct __kc_callback_head {
    struct __kc_callback_head *next;
    void (*func)(struct callback_head* head);
};
#define rcu_head __kc_callback_head
#endif
#ifndef kfree_rcu
/* this is placed here due to a lack of rcu_barrier in previous kernels */
#define kfree_rcu(_ptr, _offset) kfree(_ptr)
#endif /* kfree_rcu */

#ifndef rounddown_pow_of_two
#define rounddown_pow_of_two(n) \
__builtin_constant_p(n) ? ( \
(n == 1) ? 0 : \
(1UL << ilog2(n))) : \
(1UL << (fls_long(n) - 1))
#endif

#define pci_device_is_present(x) 1

#define ETH_ALEN        6            /* Octets in one ethernet addr   */
#define ETH_HLEN        14            /* Total octets in header.       */
#define ETH_ZLEN        60            /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500        /* Max. octets in payload        */
#define ETH_FRAME_LEN    1514        /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN        4            /* Octets in the FCS*/

#define ETH_P_8021Q 0x8100

#define VLAN_HLEN        4            /* The additional bytes (on top of the Ethernet header) that VLAN requires. */
#define VLAN_ETH_ALEN    6            /* Octets in one ethernet addr   */
#define VLAN_ETH_HLEN    18            /* Total octets in header.       */
#define VLAN_ETH_ZLEN    64            /* Min. octets in frame sans FCS */
#define VLAN_VID_MASK           0x0fff /* VLAN Identifier */
#define VLAN_N_VID              4096

#define IFF_PROMISC     0x100           /* receive all packets          */
#define IFF_ALLMULTI    0x200           /* receive all multicast packets*/

#define NET_IP_ALIGN    2

#define NETIF_F_SG              1       /* Scatter/gather IO. */
#define NETIF_F_IP_CSUM         2       /* Can checksum TCP/UDP over IPv4. */
#define NETIF_F_NO_CSUM         4       /* Does not require checksum. F.e. loopack. */
#define NETIF_F_HW_CSUM         8       /* Can checksum all the packets. */
#define NETIF_F_IPV6_CSUM       16      /* Can checksum TCP/UDP over IPV6 */
#define NETIF_F_HIGHDMA         32      /* Can DMA to high memory. */
#define NETIF_F_FRAGLIST        64      /* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX      128     /* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX      256     /* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER  512     /* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED 1024    /* Device cannot handle VLAN packets */
#define NETIF_F_GSO             2048    /* Enable software GSO. */

#define NETIF_F_GRO             16384   /* Generic receive offload */
#define NETIF_F_LRO             32768   /* large receive offload */

#define NETIF_F_SCTP_CSUM       (1 << 25) /* SCTP checksum offload */
//#define NETIF_F_RXHASH          (1 << 28) /* Receive hashing offload */
#define NETIF_F_RXCSUM          (1 << 29) /* Receive checksumming offload */

#define DUPLEX_HALF             0x00
#define DUPLEX_FULL             0x01

//#if (65536/PAGE_SIZE + 2) < 16
//#define MAX_SKB_FRAGS 16UL
//#else
//#define MAX_SKB_FRAGS (65536/PAGE_SIZE + 2)
//#endif

#define MAX_SKB_FRAGS 80

#define PCI_COMMAND             0x04    /* 16 bits */
#define    PCI_EXP_DEVCTL    8
#define    PCI_EXP_DEVCTL_CERE    0x0001    /* Correctable Error Reporting En. */
#define    PCI_EXP_LNKCTL    16
#define PCIE_LINK_STATE_L0S     1
#define PCIE_LINK_STATE_L1 2

#define  PCI_STATUS_REC_TARGET_ABORT    0x1000 /* Master ack of " */
#define  PCI_STATUS_REC_MASTER_ABORT    0x2000 /* Set on master abort */
#define  PCI_STATUS_SIG_SYSTEM_ERROR    0x4000 /* Set when we drive SERR */

#define MDIO_EEE_100TX  0x0002  /* Advertise 100TX EEE cap */
#define MDIO_EEE_1000T  0x0004  /* Advertise 1000T EEE cap */

#define MAX_NUMNODES 1
#define first_online_node 0
#define node_online(node) ((node) == 0)
#define ether_crc_le(length, data) _kc_ether_crc_le(length, data)
#ifndef is_zero_ether_addr
#define is_zero_ether_addr _kc_is_zero_ether_addr
static inline int _kc_is_zero_ether_addr(const u8 *addr)
{
    return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}
#endif
#ifndef is_multicast_ether_addr
#define is_multicast_ether_addr _kc_is_multicast_ether_addr
static inline int _kc_is_multicast_ether_addr(const u8 *addr)
{
    return addr[0] & 0x01;
}
#endif /* is_multicast_ether_addr */

static inline unsigned int _kc_ether_crc_le(int length, unsigned char *data)
{
    unsigned int crc = 0xffffffff;  /* Initial value. */
    while(--length >= 0) {
        unsigned char current_octet = *data++;
        int bit;
        for (bit = 8; --bit >= 0; current_octet >>= 1) {
            if ((crc ^ current_octet) & 1) {
                crc >>= 1;
                crc ^= 0xedb88320U;
            } else
                crc >>= 1;
        }
    }
    return crc;
}

#define    EIO            5
#define ENOENT        2
#define    ENOMEM        12
#define    EBUSY        16
#define EINVAL      22  /* Invalid argument */
#define ENOTSUP        524
#define EOPNOTSUPP     ENOTSUP

/*****************************************************************************/
#define msleep(x)    IOSleep(x)
#define udelay(x)    IODelay(x)

#define mdelay(x)    for(int i = 0; i < x; i++ )udelay(1000)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define usleep_range(min, max)    msleep(DIV_ROUND_UP(min, 1000))


/*****************************************************************************/

#define DMA_BIT_MASK(n)    (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))


#ifdef __cplusplus
class AppleIGC;
#else
typedef void IOBufferMemoryDescriptor;
typedef void IOPCIDevice;
typedef void IOEthernetController;
typedef void IOTimerEventSource;
typedef void AppleIGC;
#endif

#define    wmb() atomic_thread_fence(memory_order_release)
#define    rmb() atomic_thread_fence(memory_order_acquire)
#define    mmiowb()
#define    smp_mb()    mb()
#define    smp_rmb() rmb()
#define mb() atomic_thread_fence(memory_order_seq_cst)
#define    dma_rmb() atomic_thread_fence(memory_order_acquire)

#define    __MODULE_STRING(s)    "x"

/** DPRINTK specific variables*/
#define DRV 0x00
#define PROBE 0x01

#define PFX "igc: "

#ifdef APPLE_OS_LOG

extern os_log_t igc_logger;

/** Have to redefine log types as macOS log doesn't have warning for DPRINTK*/
#define K_LOG_TYPE_NOTICE OS_LOG_TYPE_DEFAULT
#define K_LOG_TYPE_INFO OS_LOG_TYPE_INFO
#define K_LOG_TYPE_DEBUG OS_LOG_TYPE_DEBUG
#define K_LOG_TYPE_WARNING OS_LOG_TYPE_ERROR
#define K_LOG_TYPE_ERROR OS_LOG_TYPE_FAULT

#define    pr_debug(args...)    os_log_info(igc_logger, PFX args)
#define    pr_err(args...)      os_log_error(igc_logger, PFX args)
#define    dev_warn(dev,args...)    os_log_error(igc_logger, PFX##dev args)
#define    dev_info(dev,args...)    os_log_info(igbclogger, PFX##dev args)

#define IGB_ERR(args...) pr_err("IGBERR " PFX args)

#ifdef    __APPLE__
#define DPRINTK(nlevel, klevel, fmt, args...) \
    os_log_with_type(igb_logger, K_LOG_TYPE_##klevel, PFX fmt, args)
#else
#define DPRINTK(nlevel, klevel, fmt, args...) \
    (void)((NETIF_MSG_##nlevel & adapter->msg_enable) && \
    printk(KERN_##klevel PFX "%s: %s: " fmt, adapter->netdev->name, \
        __func__ , ## args))
#endif

#else

#ifdef CR_DEBUG
#define    pr_debug(args...)    IOLog(PFX args)
#define    pr_err(args...)      IOLog(PFX args)
#define    dev_warn(dev,args...)    IOLog(PFX args)
#define    dev_info(dev,args...)    IOLog(PFX args)
#define netdev_dbg(dev, args...) IOLog(PFX args)
#define netdev_err(dev, args...) IOLog(PFX args)
#define netdev_info(dev, args...) IOLog(PFX args)
#else
#define    pr_debug(args...)
#define    pr_err(args...)      IOLog(PFX args)
#define    dev_warn(dev,args...)    IOLog(PFX args)
#define    dev_info(dev,args...)    IOLog(PFX args)
#define netdev_dbg(dev, args...)
#define netdev_err(dev, args...) IOLog(PFX args)
#define netdev_info(dev, args...) IOLog(PFX args)
#endif

#define IGB_ERR(args...) pr_err("IGBERR " PFX args)

#define DPRINTK(nlevel, klevel, fmt, args...) IOLog(PFX fmt, ##args)

#endif /* APPLE_OS_LOG */

#define    in_interrupt()    (0)

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)
#define    __devinit
#define    __devexit
#define WARN_ON(x) (x)

#define min_t(type,x,y) \
    ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })

#define        iphdr    ip
struct net_device { void* dummy; };
struct ifreq { void* dummy; };

enum irqreturn {
    IRQ_NONE,
    IRQ_HANDLED,
    IRQ_WAKE_THREAD,
};
typedef enum irqreturn irqreturn_t;

typedef struct sk_buff_head {
    struct sk_buff    *next;
    struct sk_buff    *prev;
    u32        qlen;
    //spinlock_t    lock;
} sk_buff_head;

typedef struct napi_struct {
    struct list_head        poll_list;
    unsigned long           state;
    int                     weight;
    int                     (*poll)(struct napi_struct *, int);

    unsigned int            gro_count;
    //struct net_device       *dev;
    struct list_head        dev_list;
    struct sk_buff          *gro_list;
    struct sk_buff          *skb;
} napi_struct;

struct msix_entry {
    u32     vector; /* kernel uses to write allocated vector */
    u16     entry;  /* driver uses to specify entry, OS writes */
};

#define IFNAMSIZ        16
#define    ____cacheline_internodealigned_in_smp

enum netdev_tx {
    __NETDEV_TX_MIN  = -100,     /* make sure enum is signed */
    NETDEV_TX_OK     = 0x00,        /* driver took care of packet */
    NETDEV_TX_BUSY   = 0x10,        /* driver tx path was busy*/
    NETDEV_TX_LOCKED = 0x20,        /* driver tx lock was already taken */
};
typedef enum netdev_tx netdev_tx_t;

#define max_t(type, x, y) ({                    \
    type __max1 = (x);                      \
    type __max2 = (y);                      \
    __max1 > __max2 ? __max1: __max2; })

static inline int test_bit(int nr, const volatile unsigned long * addr) {
    return (*addr & (1<<nr)) != 0;
}

static inline void set_bit(int nr, volatile unsigned long * addr) {
    *addr |= (1 << nr);
}

static inline void clear_bit(int nr, volatile unsigned long * addr) {
    *addr &= ~(1 << nr);
}


#define BIT_MASK(nr)        ((1ul) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)        ((nr) / BITS_PER_LONG)

static inline int test_and_set_bit(int nr, volatile unsigned long * addr) {
    unsigned long mask = BIT_MASK(nr);
    long old;

    addr += BIT_WORD(nr);

    old = __sync_fetch_and_or(addr, mask);
    return !!(old & mask);
}


static inline int is_valid_ether_addr(const u8 *addr)
{
    return !is_multicast_ether_addr(addr) && !is_zero_ether_addr(addr);
}

static inline void random_ether_addr(u8 *addr)
{
    u_int32_t temp[2];
    temp[0] = random();
    temp[1] = random();
    
    bcopy(temp,addr,ETH_ALEN);
    addr [0] &= 0xfe;       /* clear multicast bit */
    addr [0] |= 0x02;       /* set local assignment bit (IEEE802) */
}

static inline unsigned ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
    const u16 *a = (const u16 *) addr1;
    const u16 *b = (const u16 *) addr2;
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

/**
 * eth_zero_addr - Assign zero address
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Assign the zero address to the given address array.
 */
static inline void eth_zero_addr(u8 *addr)
{
    memset(addr, 0x00, ETH_ALEN);
}

#ifdef HAVE_VLAN_RX_REGISTER
#define VLAN_GROUP_ARRAY_LEN          4096
#define VLAN_GROUP_ARRAY_SPLIT_PARTS  8
#define VLAN_GROUP_ARRAY_PART_LEN     (VLAN_GROUP_ARRAY_LEN/VLAN_GROUP_ARRAY_SPLIT_PARTS)
 
struct vlan_group {
    struct IOEthernetController **vlan_devices_arrays[VLAN_GROUP_ARRAY_SPLIT_PARTS];
};


#endif

#define container_of(ptr, type, member) ({ \
    const typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)( (char *)__mptr - offsetof(type,member) );})

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#ifndef READ_ONCE
#define READ_ONCE(_x) ACCESS_ONCE(_x)
#endif

#define fallthrough do {} while (0)  /* fallthrough */

#ifndef BIT
#define BIT(nr)         (1UL << (nr))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#endif /* _KCOMPAT_H_ */
