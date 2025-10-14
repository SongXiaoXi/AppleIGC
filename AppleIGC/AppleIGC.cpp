#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <stdint.h>
#include <stdatomic.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOFilterInterruptEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

extern "C" {
#include <sys/kpi_mbuf.h>
#include <net/ethernet.h>
}

extern "C" {
#include "kcompat.h"
#include "igc.h"
}

#include "AppleIGC.hpp"

#define USE_HW_UDPCSUM 0
#define CAN_RECOVER_STALL    0

#define NETIF_F_TSO
#define NETIF_F_TSO6

#define M_PKTHDR        0x0002

/* IPv6 flags are not defined in 10.6 headers. */
enum {
    CSUM_TCPIPv6             = 0x0020,
    CSUM_UDPIPv6             = 0x0040
};

#define    RELEASE(x)    {if(x)x->release();x=NULL;}

static inline ip* ip_hdr(mbuf_t skb)
{
    return (ip*)((u8*)mbuf_data(skb) + ETHER_HDR_LEN);
}

static inline struct tcphdr* tcp_hdr(mbuf_t skb)
{
    struct ip* iph = ip_hdr(skb);
    return (struct tcphdr*)((u8*)iph + (iph->ip_hl << 2));
}

static inline struct ip6_hdr* ip6_hdr(mbuf_t skb) {
    uint8_t *data = (uint8_t*)mbuf_data(skb);
    size_t pkt_len = mbuf_len(skb);

    if (pkt_len < ETHER_HDR_LEN + sizeof(struct ip6_hdr))
        return NULL;

    return (struct ip6_hdr*)(data + ETHER_HDR_LEN);
}

static inline struct tcphdr* tcp6_hdr(mbuf_t skb) {
    uint8_t *data = (uint8_t*)mbuf_data(skb);
    size_t pkt_len = mbuf_len(skb);

    struct ip6_hdr *ip6 = ip6_hdr(skb);
    if (!ip6)
        return NULL;

    uint8_t next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    size_t offset = ETHER_HDR_LEN + sizeof(struct ip6_hdr);

    while (offset < pkt_len && next_header != IPPROTO_TCP) {
        if (offset + 2 > pkt_len)
            return NULL;

        uint8_t ext_nxt = *(data + offset);
        uint8_t ext_len = *(data + offset + 1);

        size_t hdr_len;
        switch (next_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
            hdr_len = (ext_len + 1) * 8;
            break;
        case IPPROTO_FRAGMENT:
            hdr_len = 8;
            break;
        case IPPROTO_AH:
            hdr_len = (ext_len + 2) * 4;
            break;
        default:
            return NULL;
        }

        if (offset + hdr_len > pkt_len)
            return NULL;

        next_header = ext_nxt;
        offset += hdr_len;
    }

    if (next_header != IPPROTO_TCP ||
        offset + sizeof(struct tcphdr) > pkt_len) {
        return NULL;
    }

    return (struct tcphdr*)(data + offset);
}

static void* kzalloc(size_t size)
{
    void* p = IOMalloc(size);
    if(p){
        bzero(p, size);
    } else {
        pr_err("kzalloc: failed size = %d\n", (int)size );
    }
    return p;
}

static void* kcalloc(size_t num, size_t size)
{
    void* p = IOMalloc(num * size);
    if(p){
        bzero(p, num * size);
    } else {
        pr_err("kcalloc: failed num = %d, size = %d\n", (int)num, (int)size );
    }
    return p;
}

static void kfree(void* p, size_t size)
{
    IOFree(p, size);
}


static void* vzalloc(size_t size)
{
    void* p = IOMallocAligned(size, PAGE_SIZE);
    if(p){
        bzero(p, size);
    } else {
        pr_err("vzalloc: failed size = %d\n", (int)size );
    }
    return p;
}

static void vfree(void* p, size_t size) {
    IOFreeAligned(p, size);
}

static void netif_carrier_off(IOEthernetController* netdev){
    ((AppleIGC*)netdev)->setCarrier(false);
}

static void netif_carrier_on(IOEthernetController* netdev){
    ((AppleIGC*)netdev)->setCarrier(true);
}


static void netif_tx_start_all_queues(IOEthernetController* netdev){
    ((AppleIGC*)netdev)->startTxQueue();
}

static void netif_tx_wake_all_queues(IOEthernetController* netdev){
    ((AppleIGC*)netdev)->startTxQueue();
}


static void netif_tx_stop_all_queues(IOEthernetController* netdev){
    ((AppleIGC*)netdev)->stopTxQueue();
}

static igc_adapter* netdev_priv(IOEthernetController* netdev)
{
    return ((AppleIGC*)netdev)->adapter();
}

static int netif_running(IOEthernetController* netdev)
{
    return ((AppleIGC*)netdev)->running();
}
#ifndef __PRIVATE_SPI__
static int netif_queue_stopped(IOEthernetController* netdev)
{
    return ((AppleIGC*)netdev)->queueStopped() || ((AppleIGC*)netdev)->Stalled();
}
#endif

static int netif_carrier_ok(IOEthernetController* netdev)
{
    return ((AppleIGC*)netdev)->carrier();
}

static void netif_wake_queue(IOEthernetController* netdev)
{
    netif_tx_wake_all_queues(netdev);
}

static void netif_stop_queue(IOEthernetController* netdev)
{
    netif_tx_stop_all_queues(netdev);
}


static mbuf_t netdev_alloc_skb_ip_align(IOEthernetController* netdev, u16 rx_buffer_len)
{
    mbuf_t skb = netdev->allocatePacket(rx_buffer_len);
    mbuf_pkthdr_setlen(skb, 0);
    return skb;
}

static __be16 vlan_get_protocol(struct sk_buff *skb)
{
    iphdr* p = (iphdr*)mbuf_pkthdr_header(skb);
    return p->ip_p;
}

#define    jiffies    _jiffies()
static u64 _jiffies()
{
#if defined(MAC_OS_X_VERSION_10_6)
    clock_sec_t seconds;
    clock_usec_t microsecs;
#else
    uint32_t seconds;
    uint32_t microsecs;
#endif
    clock_get_system_microtime(&seconds, &microsecs);
    return  seconds * 100 + microsecs / 10000; // 10 ms
}
#define    HZ    250

static int time_after(u64 a, u64 b)
{
    if(a > b)
        return 1;
    return 0;
}

#define schedule_work(a)    (*(a))->setTimeoutMS(1)

static int pci_enable_device_mem(IOPCIDevice *dev)
{
    if(dev->setMemoryEnable(true))
        return 0;
    return -EINVAL;
}


#define    skb_record_rx_queue(skb,n)

#define PCI_MSI_FLAGS           2       /* Various flags */
#define PCI_MSI_FLAGS_QMASK    0x0e    /* Maximum queue size available */
static int pci_enable_msi_block(IOPCIDevice *dev )
{
    unsigned int nvec = 1;
    int status = -EINVAL, maxvec;
    u16 msgctl;

    u8 pos;

    if (dev->findPCICapability(kIOPCIMSICapability, &pos) == 0)
        return -EINVAL;
    msgctl = dev->configRead16(pos+PCI_MSI_FLAGS);
    maxvec = 1 << ((msgctl & PCI_MSI_FLAGS_QMASK) >> 1);
    if (nvec > maxvec)
        return maxvec;
    
#if 0
    status = pci_msi_check_device(dev, nvec, kIOPCIMSICapability);
    if (status)
        return status;
    
    /* Check whether driver already requested MSI-X irqs */
    if (dev->msix_enabled) {
        return -EINVAL;
    }
#endif
#if 0
    // OS specific chain
    status = msi_capability_init(dev, nvec);
#endif
    return status;
}


#define DRV_SUMMARY    "Intel(R) 2.5G Ethernet Linux Driver"

#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define IGC_XDP_PASS        0
#define IGC_XDP_CONSUMED    BIT(0)
#define IGC_XDP_TX        BIT(1)
#define IGC_XDP_REDIRECT    BIT(2)

static int debug = -1;


char igc_driver_name[] = "igc";
static const char igc_driver_string[] = DRV_SUMMARY;
static const char igc_copyright[] =
    "Copyright(c) 2018 Intel Corporation.";

static const struct igc_info *igc_info_tbl[] = {
    [board_base] = &igc_base_info,
};

enum latency_range {
    lowest_latency = 0,
    low_latency = 1,
    bulk_latency = 2,
    latency_invalid = 255
};

void igc_reset(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    struct igc_fc_info *fc = &hw->fc;
    u32 pba, hwm;

    /* Repartition PBA for greater than 9k MTU if required */
    pba = IGC_PBA_34K;

    /* flow control settings
     * The high water mark must be low enough to fit one full frame
     * after transmitting the pause frame.  As such we must have enough
     * space to allow for us to complete our current transmit and then
     * receive the frame that is in progress from the link partner.
     * Set it to:
     * - the full Rx FIFO size minus one full Tx plus one full Rx frame
     */
    hwm = (pba << 10) - (adapter->max_frame_size + MAX_JUMBO_FRAME_SIZE);

    fc->high_water = hwm & 0xFFFFFFF0;    /* 16-byte granularity */
    fc->low_water = fc->high_water - 16;
    fc->pause_time = 0xFFFF;
    fc->send_xon = 1;
    fc->current_mode = fc->requested_mode;

    hw->mac.ops.reset_hw(hw);

    if (hw->mac.ops.init_hw(hw))
        netdev_err(dev, "Error on hardware initialization\n");

    /* Re-establish EEE setting */
    igc_set_eee_i225(hw, true, true, true);

    if (!netif_running(adapter->netdev))
        igc_power_down_phy_copper_base(&adapter->hw);

    /* Enable HW to recognize an 802.1Q VLAN Ethernet packet */
    wr32(IGC_VET, ETH_P_8021Q);
#ifdef HAVE_PTP_CLOCK
    /* Re-enable PTP, where applicable. */
    igc_ptp_reset(adapter);
#endif

    /* Re-enable TSN offloading, where applicable. */
    //igc_tsn_reset(adapter);

    igc_get_phy_info(hw);
}

/**
 * igc_power_up_link - Power up the phy link
 * @adapter: address of board private structure
 */
static void igc_power_up_link(struct igc_adapter *adapter)
{
    igc_reset_phy(&adapter->hw);

    igc_power_up_phy_copper(&adapter->hw);

    igc_setup_link(&adapter->hw);
}

/**
 * igc_release_hw_control - release control of the h/w to f/w
 * @adapter: address of board private structure
 *
 * igc_release_hw_control resets CTRL_EXT:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that the
 * driver is no longer loaded.
 */
static void igc_release_hw_control(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    u32 ctrl_ext;
    
    // hackintosh supported pci-e hot plugin?
    //if (!pci_device_is_present(adapter->pdev))
    //    return;

    /* Let firmware take over control of h/w */
    ctrl_ext = rd32(IGC_CTRL_EXT);
    wr32(IGC_CTRL_EXT,
         ctrl_ext & ~IGC_CTRL_EXT_DRV_LOAD);
}

/**
 * igc_get_hw_control - get control of the h/w from f/w
 * @adapter: address of board private structure
 *
 * igc_get_hw_control sets CTRL_EXT:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that
 * the driver is loaded.
 */
static void igc_get_hw_control(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    u32 ctrl_ext;

    /* Let firmware know the driver has taken over */
    ctrl_ext = rd32(IGC_CTRL_EXT);
    wr32(IGC_CTRL_EXT,
         ctrl_ext | IGC_CTRL_EXT_DRV_LOAD);
}

static
void igc_unmap_tx_buffer(struct device *dev, struct igc_tx_buffer *buf)
{
#ifndef __APPLE__
    dma_unmap_single(dev, dma_unmap_addr(buf, dma),
             dma_unmap_len(buf, len), DMA_TO_DEVICE);
#endif
    dma_unmap_len_set(buf, len, 0);
}

void igc_unmap_and_free_tx_resource(struct igc_ring *ring,
                                    struct igc_tx_buffer *tx_buffer)
{
    if (tx_buffer->skb) {
#ifdef __APPLE__
        ring->netdev->freePacket(tx_buffer->skb);
#else
        dev_kfree_skb_any(tx_buffer->skb);
        if (dma_unmap_len(tx_buffer, len))
            dma_unmap_single(ring->dev,
                             dma_unmap_addr(tx_buffer, dma),
                             dma_unmap_len(tx_buffer, len),
                             DMA_TO_DEVICE);
    } else if (dma_unmap_len(tx_buffer, len)) {
        dma_unmap_page(ring->dev,
                       dma_unmap_addr(tx_buffer, dma),
                       dma_unmap_len(tx_buffer, len),
                       DMA_TO_DEVICE);
#endif
    }
    tx_buffer->next_to_watch = NULL;
    tx_buffer->skb = NULL;
    dma_unmap_len_set(tx_buffer, len, 0);
    /* buffer_info must be completely set up in the transmit path */
}

/**
 * igc_clean_tx_ring - Free Tx Buffers
 * @tx_ring: ring to be cleaned
 */
static void igc_clean_tx_ring(struct igc_ring *tx_ring)
{
    struct igc_tx_buffer *buffer_info;
    unsigned long size;
    u16 i;

    if (!tx_ring->tx_buffer_info)
        return;
    /* Free all the Tx ring sk_buffs */

    for (i = 0; i < tx_ring->count; i++) {
        buffer_info = &tx_ring->tx_buffer_info[i];
        igc_unmap_and_free_tx_resource(tx_ring, buffer_info);
    }

#ifndef __APPLE__
    netdev_tx_reset_queue(txring_txq(tx_ring));
#endif /* __APPLE__ */
    
    size = sizeof(struct igc_tx_buffer) * tx_ring->count;
    memset(tx_ring->tx_buffer_info, 0, size);

    /* Zero out the descriptor ring */
    memset(tx_ring->desc, 0, tx_ring->size);

    tx_ring->next_to_use = 0;
    tx_ring->next_to_clean = 0;
}

/**
 * igc_free_tx_resources - Free Tx Resources per Queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 */
void igc_free_tx_resources(struct igc_ring *tx_ring)
{
    igc_clean_tx_ring(tx_ring);

    vfree(tx_ring->tx_buffer_info, sizeof(struct igc_rx_buffer) * tx_ring->count);
    tx_ring->tx_buffer_info = NULL;

    /* if not set, then don't free */
    if (!tx_ring->desc)
        return;
#ifdef __APPLE__
    if(tx_ring->pool){
        tx_ring->pool->complete();
        tx_ring->pool->release();
        tx_ring->pool = NULL;
    }
#else
    dma_free_coherent(tx_ring->dev, tx_ring->size,
              tx_ring->desc, tx_ring->dma);
#endif
    tx_ring->desc = NULL;
}

/**
 * igc_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 */
static void igc_free_all_tx_resources(struct igc_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_tx_queues; i++)
        igc_free_tx_resources(adapter->tx_ring[i]);
}

/**
 * igc_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 */
static void igc_clean_all_tx_rings(struct igc_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_tx_queues; i++)
        if (adapter->tx_ring[i])
            igc_clean_tx_ring(adapter->tx_ring[i]);
}

/**
 * igc_setup_tx_resources - allocate Tx resources (Descriptors)
 * @tx_ring: tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 */
int igc_setup_tx_resources(struct igc_ring *tx_ring)
{
    int size = 0;

    size = sizeof(struct igc_tx_buffer) * tx_ring->count;
    tx_ring->tx_buffer_info = (igc_tx_buffer*)vzalloc(size);
    if (!tx_ring->tx_buffer_info)
        goto err;

    /* round up to nearest 4K */
    tx_ring->size = tx_ring->count * sizeof(union igc_adv_tx_desc);
    tx_ring->size = ALIGN(tx_ring->size, 4096);
#ifdef __APPLE__
    tx_ring->pool= IOBufferMemoryDescriptor::inTaskWithOptions( kernel_task,
                            kIODirectionInOut | kIOMemoryPhysicallyContiguous,
                            (vm_size_t)(tx_ring->size), PAGE_SIZE );
    
    if (!tx_ring->pool)
        goto err;
    tx_ring->pool->prepare();
    tx_ring->desc = tx_ring->pool->getBytesNoCopy();
    tx_ring->dma = tx_ring->pool->getPhysicalAddress();
#else
    tx_ring->desc = dma_alloc_coherent(dev, tx_ring->size,
                       &tx_ring->dma, GFP_KERNEL);

    if (!tx_ring->desc)
        goto err;
#endif

    tx_ring->next_to_use = 0;
    tx_ring->next_to_clean = 0;

    return 0;

err:
    vfree(tx_ring->tx_buffer_info, size);
    netdev_err(ndev, "Unable to allocate memory for Tx descriptor ring\n");
    return -ENOMEM;
}

/**
 * igc_setup_all_tx_resources - wrapper to allocate Tx resources for all queues
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 */
static int igc_setup_all_tx_resources(struct igc_adapter *adapter)
{
    //struct net_device *dev = adapter->netdev;
    int i, err = 0;

    for (i = 0; i < adapter->num_tx_queues; i++) {
        err = igc_setup_tx_resources(adapter->tx_ring[i]);
        if (err) {
            netdev_err(dev, "Error on Tx queue %u setup\n", i);
            for (i--; i >= 0; i--)
                igc_free_tx_resources(adapter->tx_ring[i]);
            break;
        }
    }

    return err;
}

static void igc_clean_rx_ring_page_shared(struct igc_ring *rx_ring)
{
    u16 i = rx_ring->next_to_clean;

#ifdef __APPLE__
    if (rx_ring->skb) {
        rx_ring->netdev->freePacket(rx_ring->skb);
    }
#else
    dev_kfree_skb(rx_ring->skb);
#endif
    rx_ring->skb = NULL;

    /* Free all the Rx ring sk_buffs */
    while (i != rx_ring->next_to_alloc) {
        struct igc_rx_buffer *buffer_info = &rx_ring->rx_buffer_info[i];

        /* Invalidate cache lines that may have been written to by
         * device so that we avoid corrupting memory.
         */
#ifdef __APPLE__
        buffer_info->page->complete();
        buffer_info->page->release();
#else
        dma_sync_single_range_for_cpu(rx_ring->dev,
                          buffer_info->dma,
                          buffer_info->page_offset,
                          igc_rx_bufsz(rx_ring),
                          DMA_FROM_DEVICE);

        /* free resources associated with mapping */
        dma_unmap_page_attrs(rx_ring->dev,
                     buffer_info->dma,
                     igc_rx_pg_size(rx_ring),
                     DMA_FROM_DEVICE,
                     IGC_RX_DMA_ATTR);
        __page_frag_cache_drain(buffer_info->page,
                    buffer_info->pagecnt_bias);
#endif
        i++;
        if (i == rx_ring->count)
            i = 0;
    }
}

/**
 * igc_clean_rx_ring - Free Rx Buffers per Queue
 * @ring: ring to free buffers from
 */
static void igc_clean_rx_ring(struct igc_ring *ring)
{
//    if (ring->xsk_pool)
//        igc_clean_rx_ring_xsk_pool(ring);
//    else
        igc_clean_rx_ring_page_shared(ring);

    clear_ring_uses_large_buffer(ring);

    ring->next_to_alloc = 0;
    ring->next_to_clean = 0;
    ring->next_to_use = 0;
}

/**
 * igc_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 */
static void igc_clean_all_rx_rings(struct igc_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_rx_queues; i++)
        if (adapter->rx_ring[i])
            igc_clean_rx_ring(adapter->rx_ring[i]);
}

/**
 * igc_free_rx_resources - Free Rx Resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 */
void igc_free_rx_resources(struct igc_ring *rx_ring)
{
    igc_clean_rx_ring(rx_ring);


    vfree(rx_ring->rx_buffer_info,sizeof(struct igc_rx_buffer) * rx_ring->count);
    rx_ring->rx_buffer_info = NULL;

    /* if not set, then don't free */
    if (!rx_ring->desc)
        return;
#ifdef __APPLE__
    if(rx_ring->pool){
        rx_ring->pool->complete();
        rx_ring->pool->release();
        rx_ring->pool = NULL;
    }
#else
    dma_free_coherent(rx_ring->dev, rx_ring->size,
              rx_ring->desc, rx_ring->dma);
#endif
    
    rx_ring->desc = NULL;
}

/**
 * igc_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 */
static void igc_free_all_rx_resources(struct igc_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_rx_queues; i++)
        igc_free_rx_resources(adapter->rx_ring[i]);
}

/**
 * igc_setup_rx_resources - allocate Rx resources (Descriptors)
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 */
int igc_setup_rx_resources(struct igc_ring *rx_ring)
{
    //u8 index = rx_ring->queue_index;
    int size, desc_len;//, res;

    size = sizeof(struct igc_rx_buffer) * rx_ring->count;
    rx_ring->rx_buffer_info = (igc_rx_buffer*)vzalloc(size);
    if (!rx_ring->rx_buffer_info)
        goto err;

    desc_len = sizeof(union igc_adv_rx_desc);

    /* Round up to nearest 4K */
    rx_ring->size = rx_ring->count * desc_len;
    rx_ring->size = ALIGN(rx_ring->size, 4096);
#ifdef __APPLE__
    rx_ring->pool= IOBufferMemoryDescriptor::inTaskWithOptions( kernel_task,
                                kIODirectionInOut | kIOMemoryPhysicallyContiguous,
                                (vm_size_t)(rx_ring->size), PAGE_SIZE );
    
    if (!rx_ring->pool)
        goto err;
    rx_ring->pool->prepare();
    rx_ring->desc = rx_ring->pool->getBytesNoCopy();
    rx_ring->dma = rx_ring->pool->getPhysicalAddress();
#else
    rx_ring->desc = dma_alloc_coherent(dev, rx_ring->size,
                       &rx_ring->dma, GFP_KERNEL);

    if (!rx_ring->desc)
        goto err;
#endif
    
    rx_ring->next_to_alloc = 0;
    rx_ring->next_to_clean = 0;
    rx_ring->next_to_use = 0;

    return 0;

err:
    vfree(rx_ring->rx_buffer_info, size);
    rx_ring->rx_buffer_info = NULL;
    netdev_err(ndev, "Unable to allocate memory for Rx descriptor ring\n");
    return -ENOMEM;
}

/**
 * igc_setup_all_rx_resources - wrapper to allocate Rx resources
 *                                (Descriptors) for all queues
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 */
static int igc_setup_all_rx_resources(struct igc_adapter *adapter)
{
    int i, err = 0;

    for (i = 0; i < adapter->num_rx_queues; i++) {
        err = igc_setup_rx_resources(adapter->rx_ring[i]);
        if (err) {
            netdev_err(dev, "Error on Rx queue %u setup\n", i);
            for (i--; i >= 0; i--)
                igc_free_rx_resources(adapter->rx_ring[i]);
            break;
        }
    }

    return err;
}

/**
 * igc_configure_rx_ring - Configure a receive ring after Reset
 * @adapter: board private structure
 * @ring: receive ring to be configured
 *
 * Configure the Rx unit of the MAC after a reset.
 */
static void igc_configure_rx_ring(struct igc_adapter *adapter,
                  struct igc_ring *ring)
{
    struct igc_hw *hw = &adapter->hw;
    union igc_adv_rx_desc *rx_desc;
    int reg_idx = ring->reg_idx;
    u32 srrctl = 0, rxdctl = 0;
    u64 rdba = ring->dma;
    u32 buf_size;

    /* disable the queue */
    wr32(IGC_RXDCTL(reg_idx), 0);

    /* Set DMA base address registers */
    wr32(IGC_RDBAL(reg_idx),
         rdba & 0x00000000ffffffffULL);
    wr32(IGC_RDBAH(reg_idx), rdba >> 32);
    wr32(IGC_RDLEN(reg_idx),
         ring->count * sizeof(union igc_adv_rx_desc));

    /* initialize head and tail */
    ring->tail = adapter->io_addr + IGC_RDT(reg_idx);
    wr32(IGC_RDH(reg_idx), 0);
    writel(0, ring->tail);

    /* reset next-to- use/clean to place SW in sync with hardware */
    ring->next_to_clean = 0;
    ring->next_to_use = 0;

    if (ring_uses_large_buffer(ring))
        buf_size = IGC_RXBUFFER_3072;
    else
        buf_size = IGC_RXBUFFER_2048;

    srrctl = IGC_RX_HDR_LEN << IGC_SRRCTL_BSIZEHDRSIZE_SHIFT;
    srrctl |= buf_size >> IGC_SRRCTL_BSIZEPKT_SHIFT;
    srrctl |= IGC_SRRCTL_DESCTYPE_ADV_ONEBUF;

    wr32(IGC_SRRCTL(reg_idx), srrctl);

    rxdctl |= IGC_RX_PTHRESH;
    rxdctl |= IGC_RX_HTHRESH << 8;
    rxdctl |= IGC_RX_WTHRESH << 16;

    /* initialize rx_buffer_info */
    memset(ring->rx_buffer_info, 0,
           sizeof(struct igc_rx_buffer) * ring->count);

    /* initialize Rx descriptor 0 */
    rx_desc = IGC_RX_DESC(ring, 0);
    rx_desc->wb.upper.length = 0;

    /* enable receive descriptor fetching */
    rxdctl |= IGC_RXDCTL_QUEUE_ENABLE;

    wr32(IGC_RXDCTL(reg_idx), rxdctl);
}

/**
 * igc_configure_rx - Configure receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 */
static void igc_configure_rx(struct igc_adapter *adapter)
{
    int i;

    /* Setup the HW Rx Head and Tail Descriptor Pointers and
     * the Base and Length of the Rx Descriptor Ring
     */
    for (i = 0; i < adapter->num_rx_queues; i++)
        igc_configure_rx_ring(adapter, adapter->rx_ring[i]);
}

/**
 * igc_configure_tx_ring - Configure transmit ring after Reset
 * @adapter: board private structure
 * @ring: tx ring to configure
 *
 * Configure a transmit ring after a reset.
 */
static void igc_configure_tx_ring(struct igc_adapter *adapter,
                  struct igc_ring *ring)
{
    struct igc_hw *hw = &adapter->hw;
    int reg_idx = ring->reg_idx;
    u64 tdba = ring->dma;
    u32 txdctl = 0;

    /* disable the queue */
    wr32(IGC_TXDCTL(reg_idx), 0);
    wrfl();
    mdelay(10);

    wr32(IGC_TDLEN(reg_idx),
         ring->count * sizeof(union igc_adv_tx_desc));
    wr32(IGC_TDBAL(reg_idx),
         tdba & 0x00000000ffffffffULL);
    wr32(IGC_TDBAH(reg_idx), tdba >> 32);

    ring->tail = adapter->io_addr + IGC_TDT(reg_idx);
    wr32(IGC_TDH(reg_idx), 0);
    writel(0, ring->tail);

    txdctl |= IGC_TX_PTHRESH;
    txdctl |= IGC_TX_HTHRESH << 8;
    txdctl |= IGC_TX_WTHRESH << 16;

    txdctl |= IGC_TXDCTL_QUEUE_ENABLE;
    wr32(IGC_TXDCTL(reg_idx), txdctl);
}

/**
 * igc_configure_tx - Configure transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 */
static void igc_configure_tx(struct igc_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_tx_queues; i++)
        igc_configure_tx_ring(adapter, adapter->tx_ring[i]);
}

/**
 * igc_setup_mrqc - configure the multiple receive queue control registers
 * @adapter: Board private structure
 */
#define NETDEV_RSS_KEY_LEN 52
static u8 netdev_rss_key[NETDEV_RSS_KEY_LEN];

void netdev_rss_key_fill(void *buffer, size_t len)
{
    BUG_ON(len > sizeof(netdev_rss_key));
#warning get random
    //net_get_random_once(netdev_rss_key, sizeof(netdev_rss_key));
    memcpy(buffer, netdev_rss_key, len);
}

static void igc_setup_mrqc(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    u32 j, num_rx_queues;
    u32 mrqc, rxcsum;
    u32 rss_key[10];

    netdev_rss_key_fill(rss_key, sizeof(rss_key));
    for (j = 0; j < 10; j++)
        wr32(IGC_RSSRK(j), rss_key[j]);

    num_rx_queues = adapter->rss_queues;

    if (adapter->rss_indir_tbl_init != num_rx_queues) {
        for (j = 0; j < IGC_RETA_SIZE; j++)
            adapter->rss_indir_tbl[j] =
            (j * num_rx_queues) / IGC_RETA_SIZE;
        adapter->rss_indir_tbl_init = num_rx_queues;
    }
    //igc_write_rss_indir_tbl(adapter);

    /* Disable raw packet checksumming so that RSS hash is placed in
     * descriptor on writeback.  No need to enable TCP/UDP/IP checksum
     * offloads as they are enabled by default
     */
    rxcsum = rd32(IGC_RXCSUM);
    rxcsum |= IGC_RXCSUM_PCSD;

    /* Enable Receive Checksum Offload for SCTP */
    rxcsum |= IGC_RXCSUM_CRCOFL;

    /* Don't need to set TUOFL or IPOFL, they default to 1 */
    wr32(IGC_RXCSUM, rxcsum);

    /* Generate RSS hash based on packet types, TCP/UDP
     * port numbers and/or IPv4/v6 src and dst addresses
     */
    mrqc = IGC_MRQC_RSS_FIELD_IPV4 |
           IGC_MRQC_RSS_FIELD_IPV4_TCP |
           IGC_MRQC_RSS_FIELD_IPV6 |
           IGC_MRQC_RSS_FIELD_IPV6_TCP |
           IGC_MRQC_RSS_FIELD_IPV6_TCP_EX;

    if (adapter->flags & IGC_FLAG_RSS_FIELD_IPV4_UDP)
        mrqc |= IGC_MRQC_RSS_FIELD_IPV4_UDP;
    if (adapter->flags & IGC_FLAG_RSS_FIELD_IPV6_UDP)
        mrqc |= IGC_MRQC_RSS_FIELD_IPV6_UDP;

    mrqc |= IGC_MRQC_ENABLE_RSS_MQ;

    wr32(IGC_MRQC, mrqc);
}

/**
 * igc_setup_rctl - configure the receive control registers
 * @adapter: Board private structure
 */
static void igc_setup_rctl(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    u32 rctl;

    rctl = rd32(IGC_RCTL);

    rctl &= ~(3 << IGC_RCTL_MO_SHIFT);
    rctl &= ~(IGC_RCTL_LBM_TCVR | IGC_RCTL_LBM_MAC);

    rctl |= IGC_RCTL_EN | IGC_RCTL_BAM | IGC_RCTL_RDMTS_HALF |
        (hw->mac.mc_filter_type << IGC_RCTL_MO_SHIFT);

    /* enable stripping of CRC. Newer features require
     * that the HW strips the CRC.
     */
    rctl |= IGC_RCTL_SECRC;

    /* disable store bad packets and clear size bits. */
    rctl &= ~(IGC_RCTL_SBP | IGC_RCTL_SZ_256);

    /* enable LPE to allow for reception of jumbo frames */
    rctl |= IGC_RCTL_LPE;

    /* disable queue 0 to prevent tail write w/o re-config */
    wr32(IGC_RXDCTL(0), 0);

    /* This is useful for sniffing bad packets. */
#if NETIF_F_RXALL
    if (adapter->netdev->features() & NETIF_F_RXALL) {
        /* UPE and MPE will be handled by normal PROMISC logic
         * in set_rx_mode
         */
        rctl |= (IGC_RCTL_SBP | /* Receive bad packets */
             IGC_RCTL_BAM | /* RX All Bcast Pkts */
             IGC_RCTL_PMCF); /* RX All MAC Ctrl Pkts */

        rctl &= ~(IGC_RCTL_DPF | /* Allow filtered pause */
              IGC_RCTL_CFIEN); /* Disable VLAN CFIEN Filter */
    }
#endif

    wr32(IGC_RCTL, rctl);
}

/**
 * igc_setup_tctl - configure the transmit control registers
 * @adapter: Board private structure
 */
static void igc_setup_tctl(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    u32 tctl;

    /* disable queue 0 which icould be enabled by default */
    wr32(IGC_TXDCTL(0), 0);

    /* Program the Transmit Control Register */
    tctl = rd32(IGC_TCTL);
    tctl &= ~IGC_TCTL_CT;
    tctl |= IGC_TCTL_PSP | IGC_TCTL_RTLC |
        (IGC_COLLISION_THRESHOLD << IGC_CT_SHIFT);

    /* Enable transmits */
    tctl |= IGC_TCTL_EN;

    wr32(IGC_TCTL, tctl);
}

/**
 * igc_set_mac_filter_hw() - Set MAC address filter in hardware
 * @adapter: Pointer to adapter where the filter should be set
 * @index: Filter index
 * @type: MAC address filter type (source or destination)
 * @addr: MAC address
 * @queue: If non-negative, queue assignment feature is enabled and frames
 *         matching the filter are enqueued onto 'queue'. Otherwise, queue
 *         assignment is disabled.
 */
static void igc_set_mac_filter_hw(struct igc_adapter *adapter, int index,
                  enum igc_mac_filter_type type,
                  const u8 *addr, int queue)
{
    struct igc_hw *hw = &adapter->hw;
    u32 ral, rah;

    if (WARN_ON(index >= hw->mac.rar_entry_count))
        return;

    ral = le32_to_cpup((__le32 *)(addr));
    rah = le16_to_cpup((__le16 *)(addr + 4));

    if (type == IGC_MAC_FILTER_TYPE_SRC) {
        rah &= ~IGC_RAH_ASEL_MASK;
        rah |= IGC_RAH_ASEL_SRC_ADDR;
    }

    if (queue >= 0) {
        rah &= ~IGC_RAH_QSEL_MASK;
        rah |= (queue << IGC_RAH_QSEL_SHIFT);
        rah |= IGC_RAH_QSEL_ENABLE;
    }

    rah |= IGC_RAH_AV;

    wr32(IGC_RAL(index), ral);
    wr32(IGC_RAH(index), rah);

    netdev_dbg(dev, "MAC address filter set in HW: index %d", index);
}

/**
 * igc_clear_mac_filter_hw() - Clear MAC address filter in hardware
 * @adapter: Pointer to adapter where the filter should be cleared
 * @index: Filter index
 */
static void igc_clear_mac_filter_hw(struct igc_adapter *adapter, int index)
{
    struct igc_hw *hw = &adapter->hw;

    if (WARN_ON(index >= hw->mac.rar_entry_count))
        return;

    wr32(IGC_RAL(index), 0);
    wr32(IGC_RAH(index), 0);

    netdev_dbg(dev, "MAC address filter cleared in HW: index %d", index);
}

/* Set default MAC address for the PF in the first RAR entry */
static void igc_set_default_mac_filter(struct igc_adapter *adapter)
{
    u8 *addr = adapter->hw.mac.addr;

    netdev_dbg(dev, "Set default MAC address filter: address %pM", addr);

    igc_set_mac_filter_hw(adapter, 0, IGC_MAC_FILTER_TYPE_DST, addr, -1);
}

/**
 *  igc_write_mc_addr_list - write multicast addresses to MTA
 *  @netdev: network interface device structure
 *
 *  Writes multicast address list to the MTA hash table.
 *  Returns: -ENOMEM on failure
 *           0 on no addresses written
 *           X on writing X addresses to MTA
 **/

#define IGC_EMPTY_FRAME_SIZE 60

static void igc_tx_ctxtdesc(struct igc_ring *tx_ring,
                __le32 launch_time, bool first_flag,
                u32 vlan_macip_lens, u32 type_tucmd,
                u32 mss_l4len_idx)
{
    struct igc_adv_tx_context_desc *context_desc;
    u16 i = tx_ring->next_to_use;

    context_desc = IGC_TX_CTXTDESC(tx_ring, i);

    i++;
    tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

    /* set bits to identify this as an advanced context descriptor */
    type_tucmd |= IGC_TXD_CMD_DEXT | IGC_ADVTXD_DTYP_CTXT;

    /* For i225, context index must be unique per ring. */
    if (test_bit(IGC_RING_FLAG_TX_CTX_IDX, &tx_ring->flags))
        mss_l4len_idx |= tx_ring->reg_idx << 4;

    if (first_flag)
        mss_l4len_idx |= IGC_ADVTXD_TSN_CNTX_FIRST;

    context_desc->vlan_macip_lens    = cpu_to_le32(vlan_macip_lens);
    context_desc->type_tucmd_mlhl    = cpu_to_le32(type_tucmd);
    context_desc->mss_l4len_idx    = cpu_to_le32(mss_l4len_idx);
    context_desc->launch_time    = launch_time;
}

static void igc_tx_csum(struct igc_ring *tx_ring, struct igc_tx_buffer *first,
            __le32 launch_time, bool first_flag)
{
    struct sk_buff *skb = first->skb;
    u32 vlan_macip_lens = 0;
    u32 type_tucmd = 0;
    u32 mss_l4len_idx = 0;
#define     DEMAND_IPv6 (CSUM_TCPIPv6|CSUM_UDPIPv6)
#define     DEMAND_IPv4 (IONetworkController::kChecksumIP|IONetworkController::kChecksumTCP|IONetworkController::kChecksumUDP)
#define     DEMAND_MASK (DEMAND_IPv6|DEMAND_IPv4)

    UInt32 checksumDemanded;
    tx_ring->netdev->getChecksumDemand(skb, IONetworkController::kChecksumFamilyTCPIP, &checksumDemanded);
    checksumDemanded &= DEMAND_MASK;

    const int  ehdrlen = ETHER_HDR_LEN;
    if(checksumDemanded == 0){
        if (!(first->tx_flags & IGC_TX_FLAGS_VLAN))
            return;
    } else {
        int  ip_hlen;
        u8* packet;
        
        /* Set the ether header length */
        packet = (u8*)mbuf_data(skb) + ehdrlen;
        ssize_t len = mbuf_len(skb) - ehdrlen;

        if(checksumDemanded & DEMAND_IPv6){        // IPv6
            struct ip6_hdr* ip6 = (struct ip6_hdr*)packet;
            u_int8_t nexthdr;
            do {
                if ((u8*)&ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt - packet < len) {
                    nexthdr = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
                } else {
                    break;
                }
                ip6++;
            } while(nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP && nexthdr != IPPROTO_ICMPV6);
            ip_hlen = (int)((u8*)ip6 - packet);
        } else {
            struct ip *ip = (struct ip *)packet;
            ip_hlen = ip->ip_hl << 2;
            if(ip_hlen == 0)
                ip_hlen = sizeof(struct ip);
            type_tucmd |= IGC_ADVTXD_TUCMD_IPV4;
        }
        vlan_macip_lens |= ip_hlen;
        
        if(checksumDemanded & IONetworkController::kChecksumTCP){
            type_tucmd |= IGC_ADVTXD_TUCMD_L4T_TCP;
            struct tcphdr* tcph = tcp_hdr(skb);
            mss_l4len_idx = (tcph->th_off << 2) << IGC_ADVTXD_L4LEN_SHIFT;
        } else if(checksumDemanded & CSUM_TCPIPv6){
            type_tucmd |= IGC_ADVTXD_TUCMD_L4T_TCP;
            struct tcphdr* tcph = tcp6_hdr(skb);
            if (tcph != NULL) {
                mss_l4len_idx = (tcph->th_off << 2) << IGC_ADVTXD_L4LEN_SHIFT;
            }
        } else if(checksumDemanded & (IONetworkController::kChecksumUDP|CSUM_UDPIPv6)){
            mss_l4len_idx = sizeof(struct udphdr) << IGC_ADVTXD_L4LEN_SHIFT;
        }
        
        first->tx_flags |= IGC_TX_FLAGS_CSUM;
    }
    vlan_macip_lens |= ehdrlen << IGC_ADVTXD_MACLEN_SHIFT;

    vlan_macip_lens |= first->tx_flags & IGC_TX_FLAGS_VLAN_MASK;

    igc_tx_ctxtdesc(tx_ring, launch_time, first_flag,
            vlan_macip_lens, type_tucmd, mss_l4len_idx);
}

static int __igc_maybe_stop_tx(struct igc_ring *tx_ring, const u16 size)
{
#ifndef __APPLE__
    struct net_device *netdev = tx_ring->netdev;

    netif_stop_subqueue(netdev, tx_ring->queue_index);

    /* memory barriier comment */
    smp_mb();

    /* We need to check again in a case another CPU has just
     * made room available.
     */
    if (igc_desc_unused(tx_ring) < size)
        return -EBUSY;

    /* A reprieve! */
    netif_wake_subqueue(netdev, tx_ring->queue_index);

    u64_stats_update_begin(&tx_ring->tx_syncp2);
    tx_ring->tx_stats.restart_queue2++;
    u64_stats_update_end(&tx_ring->tx_syncp2);

    return 0;
#else
    return -EBUSY;
#endif
}

static inline int igc_maybe_stop_tx(struct igc_ring *tx_ring, const u16 size)
{
    if (igc_desc_unused(tx_ring) >= size)
        return 0;
    return __igc_maybe_stop_tx(tx_ring, size);
}

#define IGC_SET_FLAG(_input, _flag, _result) \
    (((_flag) <= (_result)) ?                \
     ((u32)((_input) & (_flag)) * ((_result) / (_flag))) :    \
     ((u32)((_input) & (_flag)) / ((_flag) / (_result))))

static u32 igc_tx_cmd_type(struct sk_buff *skb, u32 tx_flags)
{
    /* set type for advanced descriptor with frame checksum insertion */
    u32 cmd_type = IGC_ADVTXD_DTYP_DATA |
               IGC_ADVTXD_DCMD_DEXT |
               IGC_ADVTXD_DCMD_IFCS;

    /* set HW vlan bit if vlan is present */
    cmd_type |= IGC_SET_FLAG(tx_flags, IGC_TX_FLAGS_VLAN,
                 IGC_ADVTXD_DCMD_VLE);

    /* set segmentation bits for TSO */
    cmd_type |= IGC_SET_FLAG(tx_flags, IGC_TX_FLAGS_TSO,
                 (IGC_ADVTXD_DCMD_TSE));

    /* set timestamp bit if present */
    cmd_type |= IGC_SET_FLAG(tx_flags, IGC_TX_FLAGS_TSTAMP,
                 (IGC_ADVTXD_MAC_TSTAMP));

    /* insert frame checksum */
    //cmd_type ^= IGC_SET_FLAG(skb->no_fcs, 1, IGC_ADVTXD_DCMD_IFCS);

    return cmd_type;
}

static void igc_tx_olinfo_status(struct igc_ring *tx_ring,
                 union igc_adv_tx_desc *tx_desc,
                 u32 tx_flags, unsigned int paylen)
{
    u32 olinfo_status = paylen << IGC_ADVTXD_PAYLEN_SHIFT;

    /* insert L4 checksum */
    olinfo_status |= (tx_flags & IGC_TX_FLAGS_CSUM) *
              ((IGC_TXD_POPTS_TXSM << 8) /
              IGC_TX_FLAGS_CSUM);

    /* insert IPv4 checksum */
    olinfo_status |= (tx_flags & IGC_TX_FLAGS_IPV4) *
              (((IGC_TXD_POPTS_IXSM << 8)) /
              IGC_TX_FLAGS_IPV4);

    tx_desc->read.olinfo_status = cpu_to_le32(olinfo_status);
}

static int igc_tx_map(struct igc_ring *tx_ring,
              struct igc_tx_buffer *first,
              const u8 hdr_len, struct IOPhysicalSegment *vec, UInt32 frags)
{
    struct sk_buff *skb = first->skb;
    struct igc_tx_buffer *tx_buffer;
    union igc_adv_tx_desc *tx_desc;
    u32 tx_flags = first->tx_flags;
    //skb_frag_t *frag;
    u16 i = tx_ring->next_to_use;

    UInt32 k,count;

    // check real count
    count = 0;
    for (k = 0; k < frags; k++){
        count += (vec[k].length + (IGC_MAX_DATA_PER_TXD-1))/IGC_MAX_DATA_PER_TXD;
    }
    if (igc_desc_unused(tx_ring) < count + 3) {
        pr_err("Unexpected igc_desc_unused (< %d + 3\n", count);
        return FALSE;
    }
    
    IOPhysicalLength size;
    dma_addr_t dma;
    u32 cmd_type;

    cmd_type = igc_tx_cmd_type(skb, tx_flags);
    tx_desc = IGC_TX_DESC(tx_ring, i);

    igc_tx_olinfo_status(tx_ring, tx_desc, tx_flags, mbuf_pkthdr_len(skb) - hdr_len);

    dma = vec[0].location;
    size = vec[0].length;
    
    tx_buffer = first;
#ifdef __APPLE__
    for (k=1;;k++)
#else
    for (frag = &skb_shinfo(skb)->frags[0];; frag++)
#endif
    {
        /* record length, and DMA address */
        dma_unmap_len_set(tx_buffer, len, size);
        dma_unmap_addr_set(tx_buffer, dma, dma);

        tx_desc->read.buffer_addr = cpu_to_le64(dma);

        while (unlikely(size > IGC_MAX_DATA_PER_TXD)) {
            tx_desc->read.cmd_type_len =
                cpu_to_le32(cmd_type ^ IGC_MAX_DATA_PER_TXD);

            i++;
            tx_desc++;
            if (i == tx_ring->count) {
                tx_desc = IGC_TX_DESC(tx_ring, 0);
                i = 0;
            }
            tx_desc->read.olinfo_status = 0;

            dma += IGC_MAX_DATA_PER_TXD;
            size -= IGC_MAX_DATA_PER_TXD;

            tx_desc->read.buffer_addr = cpu_to_le64(dma);
        }
#ifdef __APPLE__
        if(k >= frags)
            break;
#else
        if (likely(!data_len))
            break;
#endif
        tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type ^ size);

        i++;
        tx_desc++;
        if (i == tx_ring->count) {
            tx_desc = IGC_TX_DESC(tx_ring, 0);
            i = 0;
        }
        tx_desc->read.olinfo_status = 0;
#ifdef __APPLE__
        dma = vec[k].location;
        size = vec[k].length;
#else
        size = skb_frag_size(frag);
        data_len -= size;

        dma = skb_frag_dma_map(tx_ring->dev, frag, 0,
                       size, DMA_TO_DEVICE);
#endif

        tx_buffer = &tx_ring->tx_buffer_info[i];
    }

    /* write last descriptor with RS and EOP bits */
    cmd_type |= size | IGC_TXD_DCMD;
    tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
#ifndef __APPLE__
    netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount);
#endif

    /* set the timestamp */
    first->time_stamp = jiffies;
    //skb_tx_timestamp(skb);

    /* Force memory writes to complete before letting h/w know there
     * are new descriptors to fetch.  (Only applicable for weak-ordered
     * memory model archs, such as IA-64).
     *
     * We also need this memory barrier to make certain all of the
     * status bits have been updated before next_to_watch is written.
     */
    wmb();

    /* set next_to_watch value indicating a packet is present */
    first->next_to_watch = tx_desc;

    i++;
    if (i == tx_ring->count)
        i = 0;

    tx_ring->next_to_use = i;

    /* Make sure there is space in the ring for the next send. */
    igc_maybe_stop_tx(tx_ring, DESC_NEEDED);

    //if (netif_xmit_stopped(txring_txq(tx_ring)) || !netdev_xmit_more()) {
    //if (netif_queue_stopped(tx_ring->netdev) || tx_ring->netdev->txCursor()->) {
        writel(i, tx_ring->tail);
    //}

    return true;
#ifndef __APPLE__
dma_error:
    netdev_err(tx_ring->netdev, "TX DMA map failed\n");
    tx_buffer = &tx_ring->tx_buffer_info[i];

    /* clear dma mappings for failed tx_buffer_info map */
    while (tx_buffer != first) {
        if (dma_unmap_len(tx_buffer, len))
            igc_unmap_tx_buffer(tx_ring->dev, tx_buffer);

        if (i-- == 0)
            i += tx_ring->count;
        tx_buffer = &tx_ring->tx_buffer_info[i];
    }

    if (dma_unmap_len(tx_buffer, len))
        igc_unmap_tx_buffer(tx_ring->dev, tx_buffer);

    dev_kfree_skb_any(tx_buffer->skb);
    tx_buffer->skb = NULL;

    tx_ring->next_to_use = i;

    return -1;
#endif
}
    
#ifdef __APPLE__
// copy from bsd/netinet/in_cksum.c
union s_util {
    char    c[2];
    u_short s;
};

union l_util {
    u_int16_t s[2];
    u_int32_t l;
};

union q_util {
    u_int16_t s[4];
    u_int32_t l[2];
    u_int64_t q;
};
    
#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE16                                                    \
{                                                                    \
q_util.q = sum;                                                        \
l_util.l = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3];    \
sum = l_util.s[0] + l_util.s[1];                                    \
ADDCARRY(sum);                                                        \
}
    
static inline u_short
in_pseudo(u_int a, u_int b, u_int c)
{
    u_int64_t sum;
    union q_util q_util;
    union l_util l_util;
    
    sum = (u_int64_t) a + b + c;
    REDUCE16;
    return (sum);
}

// copy from bsd/netinet6/in6_cksum.c
    
static inline u_short
in_pseudo6(struct ip6_hdr *ip6, int nxt, u_int32_t len)
{
    u_int16_t *w;
    int sum = 0;
    union {
        u_int16_t phs[4];
        struct {
            u_int32_t    ph_len;
            u_int8_t    ph_zero[3];
            u_int8_t    ph_nxt;
        } ph __attribute__((__packed__));
    } uph;
    
    bzero(&uph, sizeof (uph));
    
    /*
     * First create IP6 pseudo header and calculate a summary.
     */
    w = (u_int16_t *)&ip6->ip6_src;
    uph.ph.ph_len = htonl(len);
    uph.ph.ph_nxt = nxt;
    
    /* IPv6 source address */
    sum += w[0];
    if (!IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
        sum += w[1];
    sum += w[2]; sum += w[3]; sum += w[4]; sum += w[5];
    sum += w[6]; sum += w[7];
    /* IPv6 destination address */
    sum += w[8];
    if (!IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
        sum += w[9];
    sum += w[10]; sum += w[11]; sum += w[12]; sum += w[13];
    sum += w[14]; sum += w[15];
    /* Payload length and upper layer identifier */
    sum += uph.phs[0];  sum += uph.phs[1];
    sum += uph.phs[2];  sum += uph.phs[3];
    
    return (u_short)sum;
}
#endif

#define kMinL4HdrOffsetV4 34
#define kMinL4HdrOffsetV6 54

static int igc_tso(struct igc_ring *tx_ring,
           struct igc_tx_buffer *first,
           __le32 launch_time, bool first_flag,
           u8 *hdr_len)
{
    u32 vlan_macip_lens, type_tucmd, mss_l4len_idx;
    struct sk_buff *skb = first->skb;
    mbuf_tso_request_flags_t request;
    u_int32_t mssValue;
    if(mbuf_get_tso_requested(skb, &request, &mssValue) || request == 0 )
        return 0;


    /* ADV DTYP TUCMD MKRLOC/ISCSIHEDLEN */
    type_tucmd = IGC_ADVTXD_TUCMD_L4T_TCP;

    size_t dataLen = mbuf_pkthdr_len(skb);
    struct tcphdr* tcph;
    int ip_len;
    if (request & MBUF_TSO_IPV4) {
        struct ip *iph;
        iph = ip_hdr(skb);
        tcph = tcp_hdr(skb);
        ip_len = (int)((u8*)tcph - (u8*)iph);
        iph->ip_len = 0;
        iph->ip_sum = 0;
        tcph->th_sum = in_pseudo(iph->ip_src.s_addr, iph->ip_dst.s_addr, htonl(IPPROTO_TCP));

        type_tucmd |= IGC_ADVTXD_TUCMD_IPV4;
        first->tx_flags |= IGC_TX_FLAGS_TSO |
        IGC_TX_FLAGS_CSUM |
        IGC_TX_FLAGS_IPV4;
    } else {
        struct ip6_hdr *iph = ip6_hdr(skb);
        tcph = tcp6_hdr(skb);
        if (tcph == NULL) {
            return 0;
        }
        ip_len = (int)((u8*)tcph - (u8*)iph);
        iph->ip6_ctlun.ip6_un1.ip6_un1_plen = 0;
        tcph->th_sum = in_pseudo6(iph, IPPROTO_TCP, 0);
            
        first->tx_flags |= IGC_TX_FLAGS_TSO |
        IGC_TX_FLAGS_CSUM;
    }
    
    /* compute header lengths */
    u32 l4len = tcph->th_off << 2;
    *hdr_len = ETHER_HDR_LEN + ip_len + l4len;

    u16 gso_segs = ((dataLen - *hdr_len) + (mssValue-1))/mssValue;
    
    /* update gso size and bytecount with header size */
    first->gso_segs = gso_segs;
    first->bytecount += (first->gso_segs - 1) * *hdr_len;
    
    /* MSS L4LEN IDX */
    mss_l4len_idx = l4len << IGC_ADVTXD_L4LEN_SHIFT;
    mss_l4len_idx |= mssValue << IGC_ADVTXD_MSS_SHIFT;
    /* VLAN MACLEN IPLEN */
    vlan_macip_lens = ip_len;
    vlan_macip_lens |= ETHER_HDR_LEN << IGC_ADVTXD_MACLEN_SHIFT;
    vlan_macip_lens |= first->tx_flags & IGC_TX_FLAGS_VLAN_MASK;

    igc_tx_ctxtdesc(tx_ring, launch_time, first_flag,
            vlan_macip_lens, type_tucmd, mss_l4len_idx);

    return 1;
}

#ifdef HAVE_TX_MQ
static inline struct igc_ring *igc_tx_queue_mapping(struct igc_adapter *adapter,
                            struct sk_buff *skb)
{
    unsigned int r_idx = skb->queue_mapping;

    if (r_idx >= adapter->num_tx_queues)
        r_idx = r_idx % adapter->num_tx_queues;

    return adapter->tx_ring[r_idx];
}
#else
#define igc_tx_queue_mapping(_adapter, _skb) ((_adapter)->tx_ring[0])
#endif

#ifndef __APPLE__    // see outputPacket()
static netdev_tx_t igc_xmit_frame(struct sk_buff *skb,
                  struct net_device *netdev)
{
    struct igc_adapter *adapter = netdev_priv(netdev);

    /* The minimum packet size with TCTL.PSP set is 17 so pad the skb
     * in order to meet this minimum size requirement.
     */
    if (skb->len < 17) {
        if (skb_padto(skb, 17))
            return NETDEV_TX_OK;
        skb->len = 17;
    }

    return igc_xmit_frame_ring(skb, igc_tx_queue_mapping(adapter, skb));
}
#endif

static void igc_rx_checksum(struct igc_ring *ring,
                union igc_adv_rx_desc *rx_desc,
                struct sk_buff *skb)
{
    //skb_checksum_none_assert(skb);

    /* Ignore Checksum bit is set */
    if (igc_test_staterr(rx_desc, IGC_RXD_STAT_IXSM))
        return;

    /* Rx checksum disabled via ethtool */
    if (!(ring->netdev->features() & NETIF_F_RXCSUM))
        return;

    /* TCP/UDP checksum error bit is set */
    if (igc_test_staterr(rx_desc,
                 IGC_RXDEXT_STATERR_L4E |
                 IGC_RXDEXT_STATERR_IPE)) {
        /* work around errata with sctp packets where the TCPE aka
         * L4E bit is set incorrectly on 64 byte (60 byte w/o crc)
         * packets (aka let the stack check the crc32c)
         */
#if __APPLE__
        if (!((mbuf_pkthdr_len(skb) == 60) &&
              test_bit(IGC_RING_FLAG_RX_SCTP_CSUM, &ring->flags)))
            ring->rx_stats.csum_err++;
#else
        if (!(skb->len == 60 &&
              test_bit(IGC_RING_FLAG_RX_SCTP_CSUM, &ring->flags))) {
            u64_stats_update_begin(&ring->rx_syncp);
            ring->rx_stats.csum_err++;
            u64_stats_update_end(&ring->rx_syncp);
        }
#endif
        /* let the stack verify checksum errors */
        return;
    }
#ifdef  __APPLE__
    UInt32 flag = 0;
    /*if (igc_test_staterr(rx_desc, IGC_RXD_STAT_IPCS)) {
        flag |= IONetworkController::kChecksumIP;
    }*/
    if (igc_test_staterr(rx_desc, (IGC_RXD_STAT_TCPCS))){
        flag |= IONetworkController::kChecksumTCP | CSUM_TCPIPv6;
    }
    if (igc_test_staterr(rx_desc, (IGC_RXD_STAT_UDPCS))){
        flag |= IONetworkController::kChecksumUDP | CSUM_UDPIPv6;
    }
    if(flag)
        ring->netdev->rxChecksumOK(skb, flag);
#else
    /* It must be a TCP or UDP packet with a valid checksum */
    if (igc_test_staterr(rx_desc, IGC_RXD_STAT_TCPCS |
                      IGC_RXD_STAT_UDPCS))
        skb->ip_summed = CHECKSUM_UNNECESSARY;

    netdev_dbg(ring->netdev, "cksum success: bits %08X\n",
           le32_to_cpu(rx_desc->wb.upper.status_error));
#endif
}

#ifdef NETIF_F_RXHASH
static inline void igc_rx_hash(struct igc_ring *ring,
                   union igc_adv_rx_desc *rx_desc,
                   struct sk_buff *skb)
{
    if (ring->netdev->features() & NETIF_F_RXHASH)
        skb_set_hash(skb,
                 le32_to_cpu(rx_desc->wb.lower.hi_dword.rss),
                 PKT_HASH_TYPE_L3);
}
#endif

static void igc_rx_vlan(struct igc_ring *rx_ring,
            union igc_adv_rx_desc *rx_desc,
            struct sk_buff *skb)
{
    AppleIGC *dev = rx_ring->netdev;
    u16 vid;
#ifdef NETIF_F_HW_VLAN_CTAG_RX
    if ((dev->features() & NETIF_F_HW_VLAN_CTAG_RX) &&
        igc_test_staterr(rx_desc, IGC_RXD_STAT_VP))
#else
        if ((dev->features() & NETIF_F_HW_VLAN_RX) &&
            igc_test_staterr(rx_desc, IGC_RXD_STAT_VP))
#endif
    {
        if (igc_test_staterr(rx_desc, IGC_RXDEXT_STATERR_LB) &&
            test_bit(IGC_RING_FLAG_RX_LB_VLAN_BSWAP, &rx_ring->flags))
            vid = be16_to_cpu((__force __be16)rx_desc->wb.upper.vlan);
        else
            vid = le16_to_cpu(rx_desc->wb.upper.vlan);
#ifdef HAVE_VLAN_RX_REGISTER
        dev->setVid(skb, vid);
#else
        __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
#endif
    }
}

/**
 * igc_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in order
 * to populate the hash, checksum, VLAN, protocol, and other fields within the
 * skb.
 */
static void igc_process_skb_fields(struct igc_ring *rx_ring,
                   union igc_adv_rx_desc *rx_desc,
                   struct sk_buff *skb)
{
#ifdef NETIF_F_RXHASH
    igc_rx_hash(rx_ring, rx_desc, skb);
#endif

    igc_rx_checksum(rx_ring, rx_desc, skb);

    igc_rx_vlan(rx_ring, rx_desc, skb);

    skb_record_rx_queue(skb, rx_ring->queue_index);
#ifndef __APPLE__
    skb->protocol = eth_type_trans(skb, rx_ring->netdev);
#endif
}
#ifdef HAVE_VLAN_RX_REGISTER
static void igc_vlan_mode(IOEthernetController *netdev, struct vlan_group *vlgrp)
#else
static void igc_vlan_mode(IOEthernetController *netdev, netdev_features_t features)
#endif
{
    bool enable;
    struct igc_adapter *adapter = netdev_priv(netdev);
#ifdef __APPLE__
    enable = !!vlgrp;
#else
#ifdef HAVE_VLAN_RX_REGISTER
    enable = !!vlgrp;

    igc_irq_disable(adapter);

    adapter->vlgrp = vlgrp;

    if (!test_bit(__IGB_DOWN, &adapter->state))
        igb_irq_enable(adapter);
#else
#ifdef NETIF_F_HW_VLAN_CTAG_RX
    enable = !!(features & NETIF_F_HW_VLAN_CTAG_RX);
#else
    enable = !!(features & NETIF_F_HW_VLAN_RX);
#endif
#endif
#endif
    struct igc_hw *hw = &adapter->hw;
    u32 ctrl;

    ctrl = rd32(IGC_CTRL);

    if (enable) {
        /* enable VLAN tag insert/strip */
        ctrl |= IGC_CTRL_VME;
    } else {
        /* disable VLAN tag insert/strip */
        ctrl &= ~IGC_CTRL_VME;
    }
    wr32(IGC_CTRL, ctrl);
}

static void igc_restore_vlan(struct igc_adapter *adapter)
{
#ifdef    __APPLE__
    igc_vlan_mode(adapter->netdev, adapter->vlgrp);
#else /* __APPLE__ */
    igc_vlan_mode(adapter->netdev, adapter->netdev->features);
#endif
}

static int page_count(IOBufferMemoryDescriptor *page) {
    IOByteCount resident, dirty;
    page->getPageCounts(&resident, &dirty);
    return (int)(resident + dirty);
}

static struct igc_rx_buffer *igc_get_rx_buffer(struct igc_ring *rx_ring,
                           const unsigned int size,
                           int *rx_buffer_pgcnt)
{
    struct igc_rx_buffer *rx_buffer;

    rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
    *rx_buffer_pgcnt =
#if (PAGE_SIZE < 8192)
#if __APPLE__
    page_count(rx_buffer->page);
#else
        page_count(rx_buffer->page);
#endif
#else
        0;
#endif
    prefetchw(rx_buffer->page);

    /* we are reusing so sync this buffer for CPU use */
#ifdef    __APPLE__
#else
    dma_sync_single_range_for_cpu(rx_ring->dev,
                      rx_buffer->dma,
                      rx_buffer->page_offset,
                      size,
                      DMA_FROM_DEVICE);

    rx_buffer->pagecnt_bias--;
#endif

    return rx_buffer;
}

static void igc_rx_buffer_flip(struct igc_rx_buffer *buffer,
                   unsigned int truesize)
{
#if (PAGE_SIZE < 8192)
    buffer->page_offset ^= truesize;
#else
    buffer->page_offset += truesize;
#endif
}

static unsigned int igc_get_rx_frame_truesize(struct igc_ring *ring,
                          unsigned int size)
{
    unsigned int truesize;

#if (PAGE_SIZE < 8192)
    truesize = igc_rx_pg_size(ring) / 2;
#else
    truesize = ring_uses_build_skb(ring) ?
           SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
           SKB_DATA_ALIGN(IGC_SKB_PAD + size) :
           SKB_DATA_ALIGN(size);
#endif
    return truesize;
}

/**
 * igc_add_rx_frag - Add contents of Rx buffer to sk_buff
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: size of buffer to be added
 *
 * This function will add the data contained in rx_buffer->page to the skb.
 */
static void igc_add_rx_frag(struct igc_ring *rx_ring,
                struct igc_rx_buffer *rx_buffer,
                struct sk_buff *skb,
                unsigned int size)
{
#ifdef __APPLE__
    IOBufferMemoryDescriptor *page = rx_buffer->page;

    unsigned char *va = (u8*)page->getBytesNoCopy() + rx_buffer->page_offset;
    size_t orig_len = mbuf_pkthdr_len(skb);
    if (unlikely(mbuf_copyback(skb, orig_len, size,
                      va, MBUF_WAITOK))) {
        pr_err("Unexpected mbuf_copyback()\n");
    }
#else
    unsigned int truesize;

#if (PAGE_SIZE < 8192)
    truesize = igc_rx_pg_size(rx_ring) / 2;
#else
    truesize = ring_uses_build_skb(rx_ring) ?
           SKB_DATA_ALIGN(IGC_SKB_PAD + size) :
           SKB_DATA_ALIGN(size);
#endif
    skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buffer->page,
            rx_buffer->page_offset, size, truesize);

    igc_rx_buffer_flip(rx_buffer, truesize);
#endif
}

#ifndef __APPLE__
static struct sk_buff *igc_build_skb(struct igc_ring *rx_ring,
                     struct igc_rx_buffer *rx_buffer,
                     struct xdp_buff *xdp)
{
    unsigned int size = xdp->data_end - xdp->data;
    unsigned int truesize = igc_get_rx_frame_truesize(rx_ring, size);
    unsigned int metasize = xdp->data - xdp->data_meta;
    struct sk_buff *skb;

    /* prefetch first cache line of first page */
    net_prefetch(xdp->data_meta);

    /* build an skb around the page buffer */
    skb = napi_build_skb(xdp->data_hard_start, truesize);
    if (unlikely(!skb))
        return NULL;

    /* update pointers within the skb to store the data */
    skb_reserve(skb, xdp->data - xdp->data_hard_start);
    __skb_put(skb, size);
    if (metasize)
        skb_metadata_set(skb, metasize);

    igc_rx_buffer_flip(rx_buffer, truesize);
    return skb;
}

static struct sk_buff *igc_construct_skb(struct igc_ring *rx_ring,
                     struct igc_rx_buffer *rx_buffer,
                     struct xdp_buff *xdp,
                     ktime_t timestamp)
{
    unsigned int metasize = xdp->data - xdp->data_meta;
    unsigned int size = xdp->data_end - xdp->data;
    unsigned int truesize = igc_get_rx_frame_truesize(rx_ring, size);
    void *va = xdp->data;
    unsigned int headlen;
    struct sk_buff *skb;

    /* prefetch first cache line of first page */
    net_prefetch(xdp->data_meta);

    /* allocate a skb to store the frags */
    skb = napi_alloc_skb(&rx_ring->q_vector->napi,
                 IGC_RX_HDR_LEN + metasize);
    if (unlikely(!skb))
        return NULL;

    if (timestamp)
        skb_hwtstamps(skb)->hwtstamp = timestamp;

    /* Determine available headroom for copy */
    headlen = size;
    if (headlen > IGC_RX_HDR_LEN)
        headlen = eth_get_headlen(skb->dev, va, IGC_RX_HDR_LEN);

    /* align pull length to size of long to optimize memcpy performance */
    memcpy(__skb_put(skb, headlen + metasize), xdp->data_meta,
           ALIGN(headlen + metasize, sizeof(long)));

    if (metasize) {
        skb_metadata_set(skb, metasize);
        __skb_pull(skb, metasize);
    }

    /* update all of the pointers */
    size -= headlen;
    if (size) {
        skb_add_rx_frag(skb, 0, rx_buffer->page,
                (va + headlen) - page_address(rx_buffer->page),
                size, truesize);
        igc_rx_buffer_flip(rx_buffer, truesize);
    } else {
        rx_buffer->pagecnt_bias++;
    }

    return skb;
}

#endif

/**
 * igc_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: rx descriptor ring to store buffers on
 * @old_buff: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 */
static void igc_reuse_rx_page(struct igc_ring *rx_ring,
                  struct igc_rx_buffer *old_buff)
{
    u16 nta = rx_ring->next_to_alloc;
    struct igc_rx_buffer *new_buff;

    new_buff = &rx_ring->rx_buffer_info[nta];

    /* update, and store next to alloc */
    nta++;
    rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

    /* Transfer page from old buffer to new buffer.
     * Move each member individually to avoid possible store
     * forwarding stalls.
     */
    new_buff->dma        = old_buff->dma;
    new_buff->page        = old_buff->page;
    new_buff->page_offset    = old_buff->page_offset;
    //new_buff->pagecnt_bias    = old_buff->pagecnt_bias;
}
#ifndef __APPLE__
static bool igc_can_reuse_rx_page(struct igc_rx_buffer *rx_buffer,
                  int rx_buffer_pgcnt)
{
    unsigned int pagecnt_bias = rx_buffer->pagecnt_bias;
    struct page *page = rx_buffer->page;

    /* avoid re-using remote and pfmemalloc pages */
    if (!dev_page_is_reusable(page))
        return false;

#if (PAGE_SIZE < 8192)
    /* if we are only owner of page we can reuse it */
    if (unlikely((rx_buffer_pgcnt - pagecnt_bias) > 1))
        return false;
#else
#define IGC_LAST_OFFSET \
    (SKB_WITH_OVERHEAD(PAGE_SIZE) - IGC_RXBUFFER_2048)

    if (rx_buffer->page_offset > IGC_LAST_OFFSET)
        return false;
#endif

    /* If we have drained the page fragment pool we need to update
     * the pagecnt_bias and page count so that we fully restock the
     * number of references the driver holds.
     */
    if (unlikely(pagecnt_bias == 1)) {
        page_ref_add(page, USHRT_MAX - 1);
        rx_buffer->pagecnt_bias = USHRT_MAX;
    }

    return true;
}
#endif

/**
 * igc_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 */
static bool igc_is_non_eop(struct igc_ring *rx_ring,
               union igc_adv_rx_desc *rx_desc)
{
    u32 ntc = rx_ring->next_to_clean + 1;

    /* fetch, update, and store next to clean */
    ntc = (ntc < rx_ring->count) ? ntc : 0;
    rx_ring->next_to_clean = ntc;

    prefetch(IGC_RX_DESC(rx_ring, ntc));

    if (likely(igc_test_staterr(rx_desc, IGC_RXD_STAT_EOP)))
        return false;

    return true;
}

/**
 * igc_cleanup_headers - Correct corrupted or empty headers
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being fixed
 *
 * Address the case where we are pulling data in on pages only
 * and as such no data is present in the skb header.
 *
 * In addition if skb is not at least 60 bytes we need to pad it so that
 * it is large enough to qualify as a valid Ethernet frame.
 *
 * Returns true if an error was encountered and skb was freed.
 */
static bool igc_cleanup_headers(struct igc_ring *rx_ring,
                union igc_adv_rx_desc *rx_desc,
                struct sk_buff *skb)
{
#ifdef __APPLE__
    if (unlikely((igc_test_staterr(rx_desc,
                                   IGC_RXDEXT_STATERR_RXE)))) {
        AppleIGC* netdev = (AppleIGC*)rx_ring->netdev;
        netdev->getNetStats()->inputErrors += 1;
        netdev->freePacket(skb);
        return true;
    }
#else
    /* XDP packets use error pointer so abort at this point */
    if (IS_ERR(skb))
        return true;

    if (unlikely(igc_test_staterr(rx_desc, IGC_RXDEXT_STATERR_RXE))) {
        struct net_device *netdev = rx_ring->netdev;

        if (!(netdev->features & NETIF_F_RXALL)) {
            dev_kfree_skb_any(skb);
            return true;
        }
    }

    /* if eth_skb_pad returns an error the skb was freed */
    if (eth_skb_pad(skb))
        return true;
#endif
    return false;
}
static void igc_put_rx_buffer(struct igc_ring *rx_ring,
                  struct igc_rx_buffer *rx_buffer,
                  int rx_buffer_pgcnt)
{
    
#if 0
    if (igc_can_reuse_rx_page(rx_buffer, rx_buffer_pgcnt)) {
        /* hand second half of page back to the ring */
        igc_reuse_rx_page(rx_ring, rx_buffer);
    } else {
        /* We are not reusing the buffer so unmap it and free
         * any references we are holding to it
         */
        dma_unmap_page_attrs(rx_ring->dev, rx_buffer->dma,
                     igc_rx_pg_size(rx_ring), DMA_FROM_DEVICE,
                     IGC_RX_DMA_ATTR);
        __page_frag_cache_drain(rx_buffer->page,
                    rx_buffer->pagecnt_bias);
    }

#endif
    /* clear contents of rx_buffer */
    rx_buffer->page = NULL;
}

static inline unsigned int igc_rx_offset(struct igc_ring *rx_ring)
{
    //struct igc_adapter *adapter = rx_ring->q_vector->adapter;

    if (ring_uses_build_skb(rx_ring))
        return IGC_SKB_PAD;
    //if (igc_xdp_is_enabled(adapter))
    //    return XDP_PACKET_HEADROOM;

    return 0;
}

static bool igc_alloc_mapped_page(struct igc_ring *rx_ring,
                  struct igc_rx_buffer *bi)
{
#ifdef __APPLE__
    dma_addr_t dma;

    /* since we are recycling buffers we should seldom need to alloc */
    if (likely(bi->page))
        return true;

    /* alloc new page for storage */
    bi->page =     IOBufferMemoryDescriptor::inTaskWithOptions( kernel_task,
                            kIODirectionInOut | kIOMemoryPhysicallyContiguous,
                            PAGE_SIZE, PAGE_SIZE );

    if (unlikely(!bi->page)) {
        pr_err("Failed to alloc new page for storage from IOBufferMemoryDescriptor\n");
        rx_ring->rx_stats.alloc_failed++;
        return false;
    }

    /* map page for use */
    bi->page->prepare();
    dma = bi->page->getPhysicalAddress();

    bi->dma = dma;
#else /** __APPLE__ */
    struct page *page = bi->page;
    dma_addr_t dma;

    /* since we are recycling buffers we should seldom need to alloc */
    if (likely(page))
        return true;

    /* alloc new page for storage */
    page = dev_alloc_pages(igc_rx_pg_order(rx_ring));
    if (unlikely(!page)) {
        rx_ring->rx_stats.alloc_failed++;
        return false;
    }

    /* map page for use */
    dma = dma_map_page_attrs(rx_ring->dev, page, 0,
                 igc_rx_pg_size(rx_ring),
                 DMA_FROM_DEVICE,
                 IGC_RX_DMA_ATTR);

    /* if mapping failed free memory back to system since
     * there isn't much point in holding memory we can't use
     */
    if (dma_mapping_error(rx_ring->dev, dma)) {
        __free_page(page);

        rx_ring->rx_stats.alloc_failed++;
        return false;
    }

    bi->dma = dma;
    bi->page = page;
    page_ref_add(page, USHRT_MAX - 1);
    bi->pagecnt_bias = USHRT_MAX;
#endif
    bi->page_offset = igc_rx_offset(rx_ring);

    return true;
}

/**
 * igc_alloc_rx_buffers - Replace used receive buffers; packet split
 * @rx_ring: rx descriptor ring
 * @cleaned_count: number of buffers to clean
 */
static void igc_alloc_rx_buffers(struct igc_ring *rx_ring, u16 cleaned_count)
{
    union igc_adv_rx_desc *rx_desc;
    u16 i = rx_ring->next_to_use;
    struct igc_rx_buffer *bi;
    //u16 bufsz;

    /* nothing to do */
    if (!cleaned_count)
        return;

    rx_desc = IGC_RX_DESC(rx_ring, i);
    bi = &rx_ring->rx_buffer_info[i];
    i -= rx_ring->count;

    //bufsz = igc_rx_bufsz(rx_ring);

    do {
        if (!igc_alloc_mapped_page(rx_ring, bi))
            break;

        /* sync the buffer for use by the device */
#ifndef __APPLE__
        dma_sync_single_range_for_device(rx_ring->dev, bi->dma,
                         bi->page_offset, bufsz,
                         DMA_FROM_DEVICE);
#endif

        /* Refresh the desc even if buffer_addrs didn't change
         * because each write-back erases this info.
         */
        rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + bi->page_offset);

        rx_desc++;
        bi++;
        i++;
        if (unlikely(!i)) {
            rx_desc = IGC_RX_DESC(rx_ring, 0);
            bi = rx_ring->rx_buffer_info;
            i -= rx_ring->count;
        }

        /* clear the length for the next_to_use descriptor */
        rx_desc->wb.upper.length = 0;

        cleaned_count--;
    } while (cleaned_count);

    i += rx_ring->count;

    if (rx_ring->next_to_use != i) {
        /* record the next descriptor to use */
        rx_ring->next_to_use = i;

        /* update next to alloc since we have filled the ring */
        rx_ring->next_to_alloc = i;

        /* Force memory writes to complete before letting h/w
         * know there are new descriptors to fetch.  (Only
         * applicable for weak-ordered memory model archs,
         * such as IA-64).
         */
        wmb();
        writel(i, rx_ring->tail);
    }
}

static void igc_update_rx_stats(struct igc_q_vector *q_vector,
                unsigned int packets, unsigned int bytes)
{
    struct igc_ring *ring = q_vector->rx.ring;
    //u64_stats_update_begin(&ring->rx_syncp);
    ring->rx_stats.packets += packets;
    ring->rx_stats.bytes += bytes;
    //u64_stats_update_end(&ring->rx_syncp);

    q_vector->rx.total_packets += packets;
    q_vector->rx.total_bytes += bytes;
}

static struct sk_buff *igc_fetch_rx_buffer(struct igc_ring *rx_ring,
                                              union igc_adv_rx_desc *rx_desc,
                                              struct sk_buff *skb, unsigned int size) {
    struct igc_rx_buffer *rx_buffer;
#ifdef    __APPLE__
//    IOBufferMemoryDescriptor *page;
#else
    struct page *page;
#endif
    
    rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];

//    page = rx_buffer->page;
    prefetchw(page);

    if (likely(!skb)) {
#ifndef    __APPLE__
        void *page_addr = page_address(page) +
        rx_buffer->page_offset;
#endif /** __APPLE__ **/
        /* prefetch first cache line of first page */
        prefetch(page_addr);
#if L1_CACHE_BYTES < 128
        prefetch(page_addr + L1_CACHE_BYTES);
#endif
        
        /* allocate a skb to store the frags */
        skb = netdev_alloc_skb_ip_align(rx_ring->netdev,
                                        IGC_RX_HDR_LEN);
        if (unlikely(!skb)) {
            rx_ring->rx_stats.alloc_failed++;
            return NULL;
        }
        /*
         * we will be copying header into skb->data in
         * pskb_may_pull so it is in our interest to prefetch
         * it now to avoid a possible cache miss
         */
        prefetchw(skb->data);
    }
    
    /* we are reusing so sync this buffer for CPU use */
#ifdef    __APPLE__
#else
    dma_sync_single_range_for_cpu(rx_ring->dev,
                                  rx_buffer->dma,
                                  rx_buffer->page_offset,
                                  IGB_RX_BUFSZ,
                                  DMA_FROM_DEVICE);
#endif

    /* pull page into skb */
    igc_add_rx_frag(rx_ring, rx_buffer, skb, size);
    igc_reuse_rx_page(rx_ring, rx_buffer);

    /* clear contents of rx_buffer */
    rx_buffer->page = NULL;

    return skb;
}

static int igc_clean_rx_irq(struct igc_q_vector *q_vector, const int budget)
{
    unsigned int total_bytes = 0, total_packets = 0;
    struct igc_ring *rx_ring = q_vector->rx.ring;
    struct sk_buff *skb = rx_ring->skb;
    AppleIGC *netdev = q_vector->adapter->netdev;
    u16 cleaned_count = igc_desc_unused(rx_ring);

    while (likely(total_packets < budget)) {
        union igc_adv_rx_desc *rx_desc;
        unsigned int size;//, truesize;
        //ktime_t timestamp = 0;
        //struct xdp_buff xdp;
        //int pkt_offset = 0;
        //void *pktbuf;

        /* return some buffers to hardware, one at a time is too slow */
        if (cleaned_count >= IGC_RX_BUFFER_WRITE) {
            igc_alloc_rx_buffers(rx_ring, cleaned_count);
            cleaned_count = 0;
        }

        rx_desc = IGC_RX_DESC(rx_ring, rx_ring->next_to_clean);
        size = le16_to_cpu(rx_desc->wb.upper.length);
        if (!size)
            break;

        /* This memory barrier is needed to keep us from reading
         * any other fields out of the rx_desc until we know the
         * descriptor has been written back
         */
        dma_rmb();

        skb = igc_fetch_rx_buffer(rx_ring, rx_desc, skb, size);

        /* exit if we failed to retrieve a buffer */
        if (!skb) {
            rx_ring->rx_stats.alloc_failed++;
            break;
        }
        
        cleaned_count++;

        /* fetch next buffer in frame if non-eop */
        if (igc_is_non_eop(rx_ring, rx_desc))
            continue;

        /* verify the packet layout is correct */
        if (igc_cleanup_headers(rx_ring, rx_desc, skb)) {
            skb = NULL;
            continue;
        }

        /* probably a little skewed due to removing CRC */
#ifdef __APPLE__
        total_bytes += mbuf_pkthdr_len(skb);
#else
        total_bytes += skb->len;
#endif

        /* populate checksum, VLAN, and protocol */
        igc_process_skb_fields(rx_ring, rx_desc, skb);
#ifdef HAVE_VLAN_RX_REGISTER
        netdev->receive(skb);
#else
        napi_gro_receive(&q_vector->napi, skb);
#endif

        /* reset skb pointer */
        skb = NULL;

        /* update budget accounting */
        total_packets++;
    }
    if (total_packets != 0) {
        netdev->flushInputQueue();
    }

    /* place incomplete frames back on ring for completion */
    rx_ring->skb = skb;

    igc_update_rx_stats(q_vector, total_packets, total_bytes);

    if (cleaned_count)
        igc_alloc_rx_buffers(rx_ring, cleaned_count);

    return total_packets;
}

static void igc_update_tx_stats(struct igc_q_vector *q_vector,
                unsigned int packets, unsigned int bytes)
{
    struct igc_ring *ring = q_vector->tx.ring;
    //u64_stats_update_begin(&ring->tx_syncp);
    ring->tx_stats.bytes += bytes;
    ring->tx_stats.packets += packets;
    //u64_stats_update_end(&ring->tx_syncp);

    q_vector->tx.total_bytes += bytes;
    q_vector->tx.total_packets += packets;
}

/**
 * igc_clean_tx_irq - Reclaim resources after transmit completes
 * @q_vector: pointer to q_vector containing needed info
 * @napi_budget: Used to determine if we are in netpoll
 *
 * returns true if ring is completely cleaned
 */
static bool igc_clean_tx_irq(struct igc_q_vector *q_vector, int napi_budget)
{
    struct igc_adapter *adapter = q_vector->adapter;
    unsigned int total_bytes = 0, total_packets = 0;
    unsigned int budget = q_vector->tx.work_limit;
    struct igc_ring *tx_ring = q_vector->tx.ring;
    unsigned int i = tx_ring->next_to_clean;
    struct igc_tx_buffer *tx_buffer;
    union igc_adv_tx_desc *tx_desc;
    u32 xsk_frames = 0;
    if (test_bit(__IGC_DOWN, &adapter->state)) {
        return true;
    }

    tx_buffer = &tx_ring->tx_buffer_info[i];
    tx_desc = IGC_TX_DESC(tx_ring, i);
    i -= tx_ring->count;

    do {
        union igc_adv_tx_desc *eop_desc = tx_buffer->next_to_watch;

        /* if next_to_watch is not set then there is no work pending */
        if (!eop_desc)
            break;

        /* prevent any other reads prior to eop_desc */
        smp_rmb();

        /* if DD is not set pending work has not been completed */
        if (!(eop_desc->wb.status & cpu_to_le32(IGC_TXD_STAT_DD)))
            break;

        /* clear next_to_watch to prevent false hangs */
        tx_buffer->next_to_watch = NULL;

        /* update the statistics for this packet */
        total_bytes += tx_buffer->bytecount;
        total_packets += tx_buffer->gso_segs;
        
        /* free the skb */
        if (tx_buffer->skb) {
            adapter->netdev->freePacket(tx_buffer->skb);
        }
        tx_buffer->skb = NULL;
        
        switch (tx_buffer->type) {
        case IGC_TX_BUFFER_TYPE_XSK:
            xsk_frames++;
            break;
        case IGC_TX_BUFFER_TYPE_SKB:
            //napi_consume_skb(tx_buffer->skb, napi_budget);
            //igc_unmap_tx_buffer(tx_ring->, tx_buffer);
            dma_unmap_len_set(tx_buffer, len, 0);
            break;
        default:
            pr_err("Unknown Tx buffer type %d\n", tx_buffer->type);
            break;
        }

        /* clear last DMA location and unmap remaining buffers */
        while (tx_desc != eop_desc) {
            tx_buffer++;
            tx_desc++;
            i++;
            if (unlikely(!i)) {
                i -= tx_ring->count;
                tx_buffer = tx_ring->tx_buffer_info;
                tx_desc = IGC_TX_DESC(tx_ring, 0);
            }

            /* unmap any remaining paged data */
#ifdef __APPLE__
            dma_unmap_len_set(tx_buffer, len, 0);
#else
            if (dma_unmap_len(tx_buffer, len))
                igc_unmap_tx_buffer(tx_ring->dev, tx_buffer);
#endif
        }

        /* move us one more past the eop_desc for start of next pkt */
        tx_buffer++;
        tx_desc++;
        i++;
        if (unlikely(!i)) {
            i -= tx_ring->count;
            tx_buffer = tx_ring->tx_buffer_info;
            tx_desc = IGC_TX_DESC(tx_ring, 0);
        }

        /* issue prefetch for next Tx descriptor */
        prefetch(tx_desc);

        /* update budget accounting */
        budget--;
    } while (likely(budget));
#ifndef __APPLE__
    netdev_tx_completed_queue(txring_txq(tx_ring),
                  total_packets, total_bytes);
#endif
    i += tx_ring->count;
    tx_ring->next_to_clean = i;

    igc_update_tx_stats(q_vector, total_packets, total_bytes);

    if (test_bit(IGC_RING_FLAG_TX_DETECT_HANG, &tx_ring->flags)) {
        struct igc_hw *hw = &adapter->hw;

        /* Detect a transmit hang in hardware, this serializes the
         * check with the clearing of time_stamp and movement of i
         */
        clear_bit(IGC_RING_FLAG_TX_DETECT_HANG, &tx_ring->flags);
        if (tx_buffer->next_to_watch &&
            time_after(jiffies, tx_buffer->time_stamp +
            (adapter->tx_timeout_factor * HZ)) &&
            !(rd32(IGC_STATUS) & IGC_STATUS_TXOFF)) {
            /* detected Tx unit hang */
            netdev_err(tx_ring->netdev,
                   "Detected Tx Unit Hang\n"
                   "  Tx Queue             <%d>\n"
                   "  TDH                  <%x>\n"
                   "  TDT                  <%x>\n"
                   "  next_to_use          <%x>\n"
                   "  next_to_clean        <%x>\n"
                   "buffer_info[next_to_clean]\n"
                   "  time_stamp           <%lx>\n"
                   "  next_to_watch        <%p>\n"
                   "  jiffies              <%llx>\n"
                   "  desc.status          <%x>\n",
                   tx_ring->queue_index,
                   rd32(IGC_TDH(tx_ring->reg_idx)),
                   readl(tx_ring->tail),
                   tx_ring->next_to_use,
                   tx_ring->next_to_clean,
                   tx_buffer->time_stamp,
                   tx_buffer->next_to_watch,
                   jiffies,
                   tx_buffer->next_to_watch->wb.status);
#ifdef    __APPLE__
            netif_stop_queue(tx_ring->netdev);
#else
            netif_stop_subqueue(tx_ring->netdev,
                        tx_ring->queue_index);
#endif
            /* we are about to reset, no point in enabling stuff */
            return true;
        }
    }

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
    if (unlikely(total_packets &&
             netif_carrier_ok(tx_ring->netdev) &&
             igc_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD)) {
        /* Make sure that anybody stopping the queue after this
         * sees the new next_to_clean.
         */
        smp_mb();
#ifdef __APPLE__
#ifndef __PRIVATE_SPI__
        if (netif_queue_stopped(tx_ring->netdev) &&
            !(test_bit(__IGC_DOWN, &adapter->state))) {
            netif_wake_queue(tx_ring->netdev);
            tx_ring->tx_stats.restart_queue++;
        }
#else
        if (!test_bit(__IGC_DOWN, &adapter->state)) {
            netif_wake_queue(tx_ring->netdev);
        }
#endif
#else
        if (__netif_subqueue_stopped(tx_ring->netdev,
                         tx_ring->queue_index) &&
            !(test_bit(__IGC_DOWN, &adapter->state))) {
            netif_wake_subqueue(tx_ring->netdev,
                        tx_ring->queue_index);

            u64_stats_update_begin(&tx_ring->tx_syncp);
            tx_ring->tx_stats.restart_queue++;
            u64_stats_update_end(&tx_ring->tx_syncp);
        }
#endif
    }

    return !!budget;
}

static int igc_find_mac_filter(struct igc_adapter *adapter,
                   enum igc_mac_filter_type type, const u8 *addr)
{
    struct igc_hw *hw = &adapter->hw;
    int max_entries = hw->mac.rar_entry_count;
    u32 ral, rah;
    int i;

    for (i = 0; i < max_entries; i++) {
        ral = rd32(IGC_RAL(i));
        rah = rd32(IGC_RAH(i));

        if (!(rah & IGC_RAH_AV))
            continue;
        if (!!(rah & IGC_RAH_ASEL_SRC_ADDR) != type)
            continue;
        if ((rah & IGC_RAH_RAH_MASK) !=
            le16_to_cpup((__le16 *)(addr + 4)))
            continue;
        if (ral != le32_to_cpup((__le32 *)(addr)))
            continue;

        return i;
    }

    return -1;
}

static int igc_get_avail_mac_filter_slot(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    int max_entries = hw->mac.rar_entry_count;
    u32 rah;
    int i;

    for (i = 0; i < max_entries; i++) {
        rah = rd32(IGC_RAH(i));

        if (!(rah & IGC_RAH_AV))
            return i;
    }

    return -1;
}

/**
 * igc_add_mac_filter() - Add MAC address filter
 * @adapter: Pointer to adapter where the filter should be added
 * @type: MAC address filter type (source or destination)
 * @addr: MAC address
 * @queue: If non-negative, queue assignment feature is enabled and frames
 *         matching the filter are enqueued onto 'queue'. Otherwise, queue
 *         assignment is disabled.
 *
 * Return: 0 in case of success, negative errno code otherwise.
 */
static int igc_add_mac_filter(struct igc_adapter *adapter,
                  enum igc_mac_filter_type type, const u8 *addr,
                  int queue)
{
    int index;

    index = igc_find_mac_filter(adapter, type, addr);
    if (index >= 0)
        goto update_filter;

    index = igc_get_avail_mac_filter_slot(adapter);
    if (index < 0)
        return -ENOMEM;

    netdev_dbg(dev, "Add MAC address filter: index %d type %s address %pM queue %d\n",
           index, type == IGC_MAC_FILTER_TYPE_DST ? "dst" : "src",
           addr, queue);

update_filter:
    igc_set_mac_filter_hw(adapter, index, type, addr, queue);
    return 0;
}

/**
 * igc_del_mac_filter() - Delete MAC address filter
 * @adapter: Pointer to adapter where the filter should be deleted from
 * @type: MAC address filter type (source or destination)
 * @addr: MAC address
 */
static void igc_del_mac_filter(struct igc_adapter *adapter,
                   enum igc_mac_filter_type type, const u8 *addr)
{
    int index;

    index = igc_find_mac_filter(adapter, type, addr);
    if (index < 0)
        return;

    if (index == 0) {
        /* If this is the default filter, we don't actually delete it.
         * We just reset to its default value i.e. disable queue
         * assignment.
         */
        netdev_dbg(dev, "Disable default MAC filter queue assignment");

        igc_set_mac_filter_hw(adapter, 0, type, addr, -1);
    } else {
        netdev_dbg(dev, "Delete MAC address filter: index %d type %s address %pM\n",
               index,
               type == IGC_MAC_FILTER_TYPE_DST ? "dst" : "src",
               addr);

        igc_clear_mac_filter_hw(adapter, index);
    }
}

/**
 * igc_add_vlan_prio_filter() - Add VLAN priority filter
 * @adapter: Pointer to adapter where the filter should be added
 * @prio: VLAN priority value
 * @queue: Queue number which matching frames are assigned to
 *
 * Return: 0 in case of success, negative errno code otherwise.
 */
static int igc_add_vlan_prio_filter(struct igc_adapter *adapter, int prio,
                    int queue)
{
    struct igc_hw *hw = &adapter->hw;
    u32 vlanpqf;

    vlanpqf = rd32(IGC_VLANPQF);

    if (vlanpqf & IGC_VLANPQF_VALID(prio)) {
        netdev_dbg(dev, "VLAN priority filter already in use\n");
        return -ENOMEM;
    }

    vlanpqf |= IGC_VLANPQF_QSEL(prio, queue);
    vlanpqf |= IGC_VLANPQF_VALID(prio);

    wr32(IGC_VLANPQF, vlanpqf);

    netdev_dbg(dev, "Add VLAN priority filter: prio %d queue %d\n",
           prio, queue);
    return 0;
}

/**
 * igc_del_vlan_prio_filter() - Delete VLAN priority filter
 * @adapter: Pointer to adapter where the filter should be deleted from
 * @prio: VLAN priority value
 */
static void igc_del_vlan_prio_filter(struct igc_adapter *adapter, int prio)
{
    struct igc_hw *hw = &adapter->hw;
    u32 vlanpqf;

    vlanpqf = rd32(IGC_VLANPQF);

    vlanpqf &= ~IGC_VLANPQF_VALID(prio);
    vlanpqf &= ~IGC_VLANPQF_QSEL(prio, IGC_VLANPQF_QUEUE_MASK);

    wr32(IGC_VLANPQF, vlanpqf);

    netdev_dbg(adapter->netdev, "Delete VLAN priority filter: prio %d\n",
           prio);
}

static int igc_get_avail_etype_filter_slot(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    int i;

    for (i = 0; i < MAX_ETYPE_FILTER; i++) {
        u32 etqf = rd32(IGC_ETQF(i));

        if (!(etqf & IGC_ETQF_FILTER_ENABLE))
            return i;
    }

    return -1;
}

/**
 * igc_add_etype_filter() - Add ethertype filter
 * @adapter: Pointer to adapter where the filter should be added
 * @etype: Ethertype value
 * @queue: If non-negative, queue assignment feature is enabled and frames
 *         matching the filter are enqueued onto 'queue'. Otherwise, queue
 *         assignment is disabled.
 *
 * Return: 0 in case of success, negative errno code otherwise.
 */
static int igc_add_etype_filter(struct igc_adapter *adapter, u16 etype,
                int queue)
{
    struct igc_hw *hw = &adapter->hw;
    int index;
    u32 etqf;

    index = igc_get_avail_etype_filter_slot(adapter);
    if (index < 0)
        return -ENOMEM;

    etqf = rd32(IGC_ETQF(index));

    etqf &= ~IGC_ETQF_ETYPE_MASK;
    etqf |= etype;

    if (queue >= 0) {
        etqf &= ~IGC_ETQF_QUEUE_MASK;
        etqf |= (queue << IGC_ETQF_QUEUE_SHIFT);
        etqf |= IGC_ETQF_QUEUE_ENABLE;
    }

    etqf |= IGC_ETQF_FILTER_ENABLE;

    wr32(IGC_ETQF(index), etqf);

    netdev_dbg(adapter->netdev, "Add ethertype filter: etype %04x queue %d\n",
           etype, queue);
    return 0;
}

static int igc_find_etype_filter(struct igc_adapter *adapter, u16 etype)
{
    struct igc_hw *hw = &adapter->hw;
    int i;

    for (i = 0; i < MAX_ETYPE_FILTER; i++) {
        u32 etqf = rd32(IGC_ETQF(i));

        if ((etqf & IGC_ETQF_ETYPE_MASK) == etype)
            return i;
    }

    return -1;
}

/**
 * igc_del_etype_filter() - Delete ethertype filter
 * @adapter: Pointer to adapter where the filter should be deleted from
 * @etype: Ethertype value
 */
static void igc_del_etype_filter(struct igc_adapter *adapter, u16 etype)
{
    struct igc_hw *hw = &adapter->hw;
    int index;

    index = igc_find_etype_filter(adapter, etype);
    if (index < 0)
        return;

    wr32(IGC_ETQF(index), 0);

    netdev_dbg(adapter->netdev, "Delete ethertype filter: etype %04x\n",
           etype);
}
#define __AC(X,Y)    (X##Y)
#define _AC(X,Y)    __AC(X,Y)
#define _AT(T,X)    ((T)(X))
#define _UL(x)        (_AC(x, UL))
#define _ULL(x)        (_AC(x, ULL))
#define UL(x)        (_UL(x))
#define ULL(x)        (_ULL(x))
#define GENMASK(h, l) \
    (((~UL(0)) - (UL(1) << (l)) + 1) & \
     (~UL(0) >> (BITS_PER_LONG - 1 - (h))))

static int igc_flex_filter_select(struct igc_adapter *adapter,
                  struct igc_flex_filter *input,
                  u32 *fhft)
{
    struct igc_hw *hw = &adapter->hw;
    u8 fhft_index;
    u32 fhftsl;

    if (input->index >= MAX_FLEX_FILTER) {
        //dev_err(&adapter->pdev->dev, "Wrong Flex Filter index selected!\n");
        return -EINVAL;
    }

    /* Indirect table select register */
    fhftsl = rd32(IGC_FHFTSL);
    fhftsl &= ~IGC_FHFTSL_FTSL_MASK;
    switch (input->index) {
    case 0 ... 7:
        fhftsl |= 0x00;
        break;
    case 8 ... 15:
        fhftsl |= 0x01;
        break;
    case 16 ... 23:
        fhftsl |= 0x02;
        break;
    case 24 ... 31:
        fhftsl |= 0x03;
        break;
    }
    wr32(IGC_FHFTSL, fhftsl);

    /* Normalize index down to host table register */
    fhft_index = input->index % 8;

    *fhft = (fhft_index < 4) ? IGC_FHFT(fhft_index) :
        IGC_FHFT_EXT(fhft_index - 4);

    return 0;
}

static int igc_write_flex_filter_ll(struct igc_adapter *adapter,
                    struct igc_flex_filter *input)
{
    struct igc_hw *hw = &adapter->hw;
    u8 *data = input->data;
    u8 *mask = input->mask;
    u32 queuing;
    u32 fhft;
    u32 wufc;
    int ret;
    int i;

    /* Length has to be aligned to 8. Otherwise the filter will fail. Bail
     * out early to avoid surprises later.
     */
    if (input->length % 8 != 0) {
        //dev_err(dev, "The length of a flex filter has to be 8 byte aligned!\n");
        return -EINVAL;
    }

    /* Select corresponding flex filter register and get base for host table. */
    ret = igc_flex_filter_select(adapter, input, &fhft);
    if (ret)
        return ret;

    /* When adding a filter globally disable flex filter feature. That is
     * recommended within the datasheet.
     */
    wufc = rd32(IGC_WUFC);
    wufc &= ~IGC_WUFC_FLEX_HQ;
    wr32(IGC_WUFC, wufc);

    /* Configure filter */
    queuing = input->length & IGC_FHFT_LENGTH_MASK;
    queuing |= (input->rx_queue << IGC_FHFT_QUEUE_SHIFT) & IGC_FHFT_QUEUE_MASK;
    queuing |= (input->prio << IGC_FHFT_PRIO_SHIFT) & IGC_FHFT_PRIO_MASK;

    if (input->immediate_irq)
        queuing |= IGC_FHFT_IMM_INT;

    if (input->drop)
        queuing |= IGC_FHFT_DROP;

    wr32(fhft + 0xFC, queuing);

    /* Write data (128 byte) and mask (128 bit) */
    for (i = 0; i < 16; ++i) {
        const size_t data_idx = i * 8;
        const size_t row_idx = i * 16;
        u32 dw0 =
            (data[data_idx + 0] << 0) |
            (data[data_idx + 1] << 8) |
            (data[data_idx + 2] << 16) |
            (data[data_idx + 3] << 24);
        u32 dw1 =
            (data[data_idx + 4] << 0) |
            (data[data_idx + 5] << 8) |
            (data[data_idx + 6] << 16) |
            (data[data_idx + 7] << 24);
        u32 tmp;

        /* Write row: dw0, dw1 and mask */
        wr32(fhft + row_idx, dw0);
        wr32(fhft + row_idx + 4, dw1);

        /* mask is only valid for MASK(7, 0) */
        tmp = rd32(fhft + row_idx + 8);
        tmp &= ~GENMASK(7, 0);
        tmp |= mask[i];
        wr32(fhft + row_idx + 8, tmp);
    }

    /* Enable filter. */
    wufc |= IGC_WUFC_FLEX_HQ;
    if (input->index > 8) {
        /* Filter 0-7 are enabled via WUFC. The other 24 filters are not. */
        u32 wufc_ext = rd32(IGC_WUFC_EXT);

        wufc_ext |= (IGC_WUFC_EXT_FLX8 << (input->index - 8));

        wr32(IGC_WUFC_EXT, wufc_ext);
    } else {
        wufc |= (IGC_WUFC_FLX0 << input->index);
    }
    wr32(IGC_WUFC, wufc);

    //dev_dbg(&adapter->pdev->dev, "Added flex filter %u to HW.\n",
    //    input->index);

    return 0;
}

static void igc_flex_filter_add_field(struct igc_flex_filter *flex,
                      const void *src, unsigned int offset,
                      size_t len, const void *mask)
{
    int i;

    /* data */
    memcpy(&flex->data[offset], src, len);

    /* mask */
    for (i = 0; i < len; ++i) {
        const unsigned int idx = i + offset;
        const u8 *ptr = (const u8 *)mask;

        if (mask) {
            if (ptr[i] & 0xff)
                flex->mask[idx / 8] |= BIT(idx % 8);

            continue;
        }

        flex->mask[idx / 8] |= BIT(idx % 8);
    }
}

#define ENOSPC ENOMEM

static int igc_find_avail_flex_filter_slot(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    u32 wufc, wufc_ext;
    int i;

    wufc = rd32(IGC_WUFC);
    wufc_ext = rd32(IGC_WUFC_EXT);

    for (i = 0; i < MAX_FLEX_FILTER; i++) {
        if (i < 8) {
            if (!(wufc & (IGC_WUFC_FLX0 << i)))
                return i;
        } else {
            if (!(wufc_ext & (IGC_WUFC_EXT_FLX8 << (i - 8))))
                return i;
        }
    }

    return -ENOSPC;
}

static bool igc_flex_filter_in_use(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    u32 wufc, wufc_ext;

    wufc = rd32(IGC_WUFC);
    wufc_ext = rd32(IGC_WUFC_EXT);

    if (wufc & IGC_WUFC_FILTER_MASK)
        return true;

    if (wufc_ext & IGC_WUFC_EXT_FILTER_MASK)
        return true;

    return false;
}

static int igc_add_flex_filter(struct igc_adapter *adapter,
                   struct igc_nfc_rule *rule)
{
    struct igc_flex_filter flex = { };
    struct igc_nfc_filter *filter = &rule->filter;
    unsigned int eth_offset, user_offset;
    int ret, index;
    bool vlan;

    index = igc_find_avail_flex_filter_slot(adapter);
    if (index < 0)
        return -ENOSPC;

    /* Construct the flex filter:
     *  -> dest_mac [6]
     *  -> src_mac [6]
     *  -> tpid [2]
     *  -> vlan tci [2]
     *  -> ether type [2]
     *  -> user data [8]
     *  -> = 26 bytes => 32 length
     */
    flex.index    = index;
    flex.length   = 32;
    flex.rx_queue = rule->action;

    vlan = rule->filter.vlan_tci || rule->filter.vlan_etype;
    eth_offset = vlan ? 16 : 12;
    user_offset = vlan ? 18 : 14;

    /* Add destination MAC  */
    if (rule->filter.match_flags & IGC_FILTER_FLAG_DST_MAC_ADDR)
        igc_flex_filter_add_field(&flex, &filter->dst_addr, 0,
                      ETH_ALEN, NULL);

    /* Add source MAC */
    if (rule->filter.match_flags & IGC_FILTER_FLAG_SRC_MAC_ADDR)
        igc_flex_filter_add_field(&flex, &filter->src_addr, 6,
                      ETH_ALEN, NULL);

    /* Add VLAN etype */
    if (rule->filter.match_flags & IGC_FILTER_FLAG_VLAN_ETYPE)
        igc_flex_filter_add_field(&flex, &filter->vlan_etype, 12,
                      sizeof(filter->vlan_etype),
                      NULL);

    /* Add VLAN TCI */
    if (rule->filter.match_flags & IGC_FILTER_FLAG_VLAN_TCI)
        igc_flex_filter_add_field(&flex, &filter->vlan_tci, 14,
                      sizeof(filter->vlan_tci), NULL);

    /* Add Ether type */
    if (rule->filter.match_flags & IGC_FILTER_FLAG_ETHER_TYPE) {
        __be16 etype = cpu_to_be16(filter->etype);

        igc_flex_filter_add_field(&flex, &etype, eth_offset,
                      sizeof(etype), NULL);
    }

    /* Add user data */
    if (rule->filter.match_flags & IGC_FILTER_FLAG_USER_DATA)
        igc_flex_filter_add_field(&flex, &filter->user_data,
                      user_offset,
                      sizeof(filter->user_data),
                      filter->user_mask);

    /* Add it down to the hardware and enable it. */
    ret = igc_write_flex_filter_ll(adapter, &flex);
    if (ret)
        return ret;

    filter->flex_index = index;

    return 0;
}

static void igc_del_flex_filter(struct igc_adapter *adapter,
                u16 reg_index)
{
    struct igc_hw *hw = &adapter->hw;
    u32 wufc;

    /* Just disable the filter. The filter table itself is kept
     * intact. Another flex_filter_add() should override the "old" data
     * then.
     */
    if (reg_index > 8) {
        u32 wufc_ext = rd32(IGC_WUFC_EXT);

        wufc_ext &= ~(IGC_WUFC_EXT_FLX8 << (reg_index - 8));
        wr32(IGC_WUFC_EXT, wufc_ext);
    } else {
        wufc = rd32(IGC_WUFC);

        wufc &= ~(IGC_WUFC_FLX0 << reg_index);
        wr32(IGC_WUFC, wufc);
    }

    if (igc_flex_filter_in_use(adapter))
        return;

    /* No filters are in use, we may disable flex filters */
    wufc = rd32(IGC_WUFC);
    wufc &= ~IGC_WUFC_FLEX_HQ;
    wr32(IGC_WUFC, wufc);
}

static int igc_uc_sync(IOEthernetController *netdev, const unsigned char *addr)
{
    struct igc_adapter *adapter = netdev_priv(netdev);

    return igc_add_mac_filter(adapter, IGC_MAC_FILTER_TYPE_DST, addr, -1);
}

static int igc_uc_unsync(IOEthernetController *netdev, const unsigned char *addr)
{
    struct igc_adapter *adapter = netdev_priv(netdev);

    igc_del_mac_filter(adapter, IGC_MAC_FILTER_TYPE_DST, addr);
    return 0;
}

/**
 * igc_set_rx_mode - Secondary Unicast, Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 *
 * The set_rx_mode entry point is called whenever the unicast or multicast
 * address lists or the network interface flags are updated.  This routine is
 * responsible for configuring the hardware for proper unicast, multicast,
 * promiscuous mode, and all-multi behavior.
 */
static void igc_set_rx_mode(AppleIGC *netdev)
{
    struct igc_adapter *adapter = netdev_priv(netdev);
    struct igc_hw *hw = &adapter->hw;
    u32 rctl = 0, rlpml = MAX_JUMBO_FRAME_SIZE;
    int count;

    /* Check for Promiscuous and All Multicast modes */
    if (((AppleIGC*)netdev)->flags() & IFF_PROMISC) {
        rctl |= IGC_RCTL_UPE | IGC_RCTL_MPE;
    } else {
        if (((AppleIGC*)netdev)->flags() & IFF_ALLMULTI) {
            rctl |= IGC_RCTL_MPE;
        } else {
            /* Write addresses to the MTA, if the attempt fails
             * then we should just turn on promiscuous mode so
             * that we can at least receive multicast traffic
             */
            
            count = netdev->getMulticastListCount();
            if (count < 0)
                rctl |= IGC_RCTL_MPE;
        }
    }

    /* Write addresses to available RAR registers, if there is not
     * sufficient space to store all the addresses then enable
     * unicast promiscuous mode
     */
#ifdef HAVE_SET_RX_MODE
    if (__dev_uc_sync(netdev, igc_uc_sync, igc_uc_unsync))
        rctl |= IGC_RCTL_UPE;
#endif /* HAVE_SET_RX_MODE */
    /* update state of unicast and multicast */
    rctl |= rd32(IGC_RCTL) & ~(IGC_RCTL_UPE | IGC_RCTL_MPE);
    wr32(IGC_RCTL, rctl);

//#if (PAGE_SIZE < 8192)
//    if (adapter->max_frame_size <= IGC_MAX_FRAME_BUILD_SKB)
//        rlpml = IGC_MAX_FRAME_BUILD_SKB;
//#endif
    wr32(IGC_RLPML, rlpml);
}

/**
 * igc_configure - configure the hardware for RX and TX
 * @adapter: private board structure
 */
static void igc_configure(struct igc_adapter *adapter)
{
    AppleIGC *netdev = adapter->netdev;
    int i = 0;

    igc_get_hw_control(adapter);
    igc_set_rx_mode(netdev);

    igc_restore_vlan(adapter);

    igc_setup_tctl(adapter);
    igc_setup_mrqc(adapter);
    igc_setup_rctl(adapter);

    igc_set_default_mac_filter(adapter);
#if 0
    igc_restore_nfc_rules(adapter);
#endif

    igc_configure_tx(adapter);
    igc_configure_rx(adapter);

    igc_rx_fifo_flush_base(&adapter->hw);

    /* call igc_desc_unused which always leaves
     * at least 1 descriptor unused to make sure
     * next_to_use != next_to_clean
     */
    for (i = 0; i < adapter->num_rx_queues; i++) {
        struct igc_ring *ring = adapter->rx_ring[i];

        //if (ring->xsk_pool)
        //    igc_alloc_rx_buffers_zc(ring, igc_desc_unused(ring));
        //else
            igc_alloc_rx_buffers(ring, igc_desc_unused(ring));
    }
}

/**
 * igc_write_ivar - configure ivar for given MSI-X vector
 * @hw: pointer to the HW structure
 * @msix_vector: vector number we are allocating to a given ring
 * @index: row index of IVAR register to write within IVAR table
 * @offset: column offset of in IVAR, should be multiple of 8
 *
 * The IVAR table consists of 2 columns,
 * each containing an cause allocation for an Rx and Tx ring, and a
 * variable number of rows depending on the number of queues supported.
 */
static void igc_write_ivar(struct igc_hw *hw, int msix_vector,
               int index, int offset)
{
    u32 ivar = array_rd32(IGC_IVAR0, index);

    /* clear any bits that are currently set */
    ivar &= ~((u32)0xFF << offset);

    /* write vector and valid bit */
    ivar |= (msix_vector | IGC_IVAR_VALID) << offset;

    array_wr32(IGC_IVAR0, index, ivar);
}

static void igc_assign_vector(struct igc_q_vector *q_vector, int msix_vector)
{
    struct igc_adapter *adapter = q_vector->adapter;
    struct igc_hw *hw = &adapter->hw;
    int rx_queue = IGC_N0_QUEUE;
    int tx_queue = IGC_N0_QUEUE;

    if (q_vector->rx.ring)
        rx_queue = q_vector->rx.ring->reg_idx;
    if (q_vector->tx.ring)
        tx_queue = q_vector->tx.ring->reg_idx;

    switch (hw->mac.type) {
    case igc_i225:
        if (rx_queue > IGC_N0_QUEUE)
            igc_write_ivar(hw, msix_vector,
                       rx_queue >> 1,
                       (rx_queue & 0x1) << 4);
        if (tx_queue > IGC_N0_QUEUE)
            igc_write_ivar(hw, msix_vector,
                       tx_queue >> 1,
                       ((tx_queue & 0x1) << 4) + 8);
        q_vector->eims_value = BIT(msix_vector);
        break;
    default:
        //WARN_ONCE(hw->mac.type != igc_i225, "Wrong MAC type\n");
        break;
    }

    /* add q_vector eims value to global eims_enable_mask */
    adapter->eims_enable_mask |= q_vector->eims_value;

    /* configure q_vector to set itr on first interrupt */
    q_vector->set_itr = 1;
}

/**
 * igc_configure_msix - Configure MSI-X hardware
 * @adapter: Pointer to adapter structure
 *
 * igc_configure_msix sets up the hardware to properly
 * generate MSI-X interrupts.
 */
static void igc_configure_msix(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    int i, vector = 0;
    u32 tmp;

    adapter->eims_enable_mask = 0;

    /* set vector for other causes, i.e. link changes */
    switch (hw->mac.type) {
    case igc_i225:
        /* Turn on MSI-X capability first, or our settings
         * won't stick.  And it will take days to debug.
         */
        wr32(IGC_GPIE, IGC_GPIE_MSIX_MODE |
             IGC_GPIE_PBA | IGC_GPIE_EIAME |
             IGC_GPIE_NSICR);

        /* enable msix_other interrupt */
        adapter->eims_other = BIT(vector);
        tmp = (vector++ | IGC_IVAR_VALID) << 8;

        wr32(IGC_IVAR_MISC, tmp);
        break;
    default:
        /* do nothing, since nothing else supports MSI-X */
        break;
    } /* switch (hw->mac.type) */

    adapter->eims_enable_mask |= adapter->eims_other;

    for (i = 0; i < adapter->num_q_vectors; i++)
        igc_assign_vector(adapter->q_vector[i], vector++);

    wrfl();
}

/**
 * igc_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 */
static void igc_irq_enable(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    wr32(IGC_IMS, IMS_ENABLE_MASK | IGC_IMS_DRSTA);
    wr32(IGC_IAM, IMS_ENABLE_MASK | IGC_IMS_DRSTA);
}

/**
 * igc_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 */
static void igc_irq_disable(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;

    wr32(IGC_IAM, 0);
    wr32(IGC_IMC, ~0);
    wrfl();
#ifndef __APPLE__
    if (adapter->msix_entries) {
        int vector = 0, i;

        synchronize_irq(adapter->msix_entries[vector++].vector);

        for (i = 0; i < adapter->num_q_vectors; i++)
            synchronize_irq(adapter->msix_entries[vector++].vector);
    } else {
        synchronize_irq(adapter->pdev->irq);
    }
#endif
}

void igc_set_flag_queue_pairs(struct igc_adapter *adapter,
                  const u32 max_rss_queues)
{
    /* Determine if we need to pair queues. */
    /* If rss_queues > half of max_rss_queues, pair the queues in
     * order to conserve interrupts due to limited supply.
     */
    if (adapter->rss_queues > (max_rss_queues / 2))
        adapter->flags |= IGC_FLAG_QUEUE_PAIRS;
    else
        adapter->flags &= ~IGC_FLAG_QUEUE_PAIRS;
}

unsigned int igc_get_max_rss_queues(struct igc_adapter *adapter)
{
    return IGC_MAX_RX_QUEUES;
}

static void igc_init_queue_configuration(struct igc_adapter *adapter)
{
    u32 max_rss_queues;

    max_rss_queues = igc_get_max_rss_queues(adapter);
    
    adapter->rss_queues = min_t(u32, max_rss_queues, 16);

    igc_set_flag_queue_pairs(adapter, max_rss_queues);
}

/**
 * igc_reset_q_vector - Reset config for interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: Index of vector to be reset
 *
 * If NAPI is enabled it will delete any references to the
 * NAPI struct. This is preparation for igc_free_q_vector.
 */
static void igc_reset_q_vector(struct igc_adapter *adapter, int v_idx)
{
    struct igc_q_vector *q_vector = adapter->q_vector[v_idx];

    /* if we're coming from igc_set_interrupt_capability, the vectors are
     * not yet allocated
     */
    if (!q_vector)
        return;

    if (q_vector->tx.ring)
        adapter->tx_ring[q_vector->tx.ring->queue_index] = NULL;

    if (q_vector->rx.ring)
        adapter->rx_ring[q_vector->rx.ring->queue_index] = NULL;

    //netif_napi_del(&q_vector->napi);
}

/**
 * igc_free_q_vector - Free memory allocated for specific interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: Index of vector to be freed
 *
 * This function frees the memory allocated to the q_vector.
 */

static void igc_free_q_vector(struct igc_adapter *adapter, int v_idx)
{
    struct igc_q_vector *q_vector = adapter->q_vector[v_idx];

    adapter->q_vector[v_idx] = NULL;

    /* igc_get_stats64() might access the rings on this vector,
     * we must wait a grace period before freeing it.
     */
    if (q_vector)
        kfree(q_vector, q_vector->alloc_size);
}

/**
 * igc_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 */
static void igc_free_q_vectors(struct igc_adapter *adapter)
{
    int v_idx = adapter->num_q_vectors;

    adapter->num_tx_queues = 0;
    adapter->num_rx_queues = 0;
    adapter->num_q_vectors = 0;

    while (v_idx--) {
        igc_reset_q_vector(adapter, v_idx);
        igc_free_q_vector(adapter, v_idx);
    }
}

/**
 * igc_update_itr - update the dynamic ITR value based on statistics
 * @q_vector: pointer to q_vector
 * @ring_container: ring info to update the itr for
 *
 * Stores a new ITR value based on packets and byte
 * counts during the last interrupt.  The advantage of per interrupt
 * computation is faster updates and more accurate ITR for the current
 * traffic pattern.  Constants in this function were computed
 * based on theoretical maximum wire speed and thresholds were set based
 * on testing data as well as attempting to minimize response time
 * while increasing bulk throughput.
 * NOTE: These calculations are only valid when operating in a single-
 * queue environment.
 */
static void igc_update_itr(struct igc_q_vector *q_vector,
               struct igc_ring_container *ring_container)
{
    unsigned int packets = ring_container->total_packets;
    unsigned int bytes = ring_container->total_bytes;
    u8 itrval = ring_container->itr;

    /* no packets, exit with status unchanged */
    if (packets == 0)
        return;

    switch (itrval) {
    case lowest_latency:
        /* handle TSO and jumbo frames */
        if (bytes / packets > 8000)
            itrval = bulk_latency;
        else if ((packets < 5) && (bytes > 512))
            itrval = low_latency;
        break;
    case low_latency:  /* 50 usec aka 20000 ints/s */
        if (bytes > 10000) {
            /* this if handles the TSO accounting */
            if (bytes / packets > 8000)
                itrval = bulk_latency;
            else if ((packets < 10) || ((bytes / packets) > 1200))
                itrval = bulk_latency;
            else if ((packets > 35))
                itrval = lowest_latency;
        } else if (bytes / packets > 2000) {
            itrval = bulk_latency;
        } else if (packets <= 2 && bytes < 512) {
            itrval = lowest_latency;
        }
        break;
    case bulk_latency: /* 250 usec aka 4000 ints/s */
        if (bytes > 25000) {
            if (packets > 35)
                itrval = low_latency;
        } else if (bytes < 1500) {
            itrval = low_latency;
        }
        break;
    }

    /* clear work counters since we have the values we need */
    ring_container->total_bytes = 0;
    ring_container->total_packets = 0;

    /* write updated itr to ring container */
    ring_container->itr = itrval;
}

static void igc_set_itr(struct igc_q_vector *q_vector)
{
    struct igc_adapter *adapter = q_vector->adapter;
    u32 new_itr = q_vector->itr_val;
    u8 current_itr = 0;

    /* for non-gigabit speeds, just fix the interrupt rate at 4000 */
    switch (adapter->link_speed) {
    case SPEED_10:
    case SPEED_100:
        current_itr = 0;
        new_itr = IGC_4K_ITR;
        goto set_itr_now;
    default:
        break;
    }

    igc_update_itr(q_vector, &q_vector->tx);
    igc_update_itr(q_vector, &q_vector->rx);

    current_itr = max(q_vector->rx.itr, q_vector->tx.itr);

    /* conservative mode (itr 3) eliminates the lowest_latency setting */
    if (current_itr == lowest_latency &&
        ((q_vector->rx.ring && adapter->rx_itr_setting == 3) ||
        (!q_vector->rx.ring && adapter->tx_itr_setting == 3)))
        current_itr = low_latency;

    switch (current_itr) {
    /* counts and packets in update_itr are dependent on these numbers */
    case lowest_latency:
        new_itr = IGC_70K_ITR; /* 70,000 ints/sec */
        break;
    case low_latency:
        new_itr = IGC_20K_ITR; /* 20,000 ints/sec */
        break;
    case bulk_latency:
        new_itr = IGC_4K_ITR;  /* 4,000 ints/sec */
        break;
    default:
        break;
    }

set_itr_now:
    if (new_itr != q_vector->itr_val) {
        /* this attempts to bias the interrupt rate towards Bulk
         * by adding intermediate steps when interrupt rate is
         * increasing
         */
        new_itr = new_itr > q_vector->itr_val ?
              max((new_itr * q_vector->itr_val) /
              (new_itr + (q_vector->itr_val >> 2)),
              new_itr) : new_itr;
        /* Don't write the value here; it resets the adapter's
         * internal timer, and causes us to delay far longer than
         * we should between interrupts.  Instead, we write the ITR
         * value at the beginning of the next interrupt so the timing
         * ends up being correct.
         */
        q_vector->itr_val = new_itr;
        q_vector->set_itr = 1;
    }
}

static void igc_reset_interrupt_capability(struct igc_adapter *adapter)
{
    int v_idx = adapter->num_q_vectors;

    /*if (adapter->msix_entries) {
        //pci_disable_msix(adapter->pdev);
        kfree(adapter->msix_entries,sizeof(struct msix_entry));
        adapter->msix_entries = NULL;
    } else if (adapter->flags & IGC_FLAG_HAS_MSI) {
        //pci_disable_msi(adapter->pdev);
    }*/

    while (v_idx--)
        igc_reset_q_vector(adapter, v_idx);
}

/**
 * igc_set_interrupt_capability - set MSI or MSI-X if supported
 * @adapter: Pointer to adapter structure
 * @msix: boolean value for MSI-X capability
 *
 * Attempt to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 */
static void igc_set_interrupt_capability(struct igc_adapter *adapter,
                     bool msix)
{
    int numvecs, i;
    int err;

    if (!msix)
        goto msi_only;
    adapter->flags |= IGC_FLAG_HAS_MSIX;

    /* Number of supported queues. */
    adapter->num_rx_queues = adapter->rss_queues;

    adapter->num_tx_queues = adapter->rss_queues;

    /* start with one vector for every Rx queue */
    numvecs = adapter->num_rx_queues;

    /* if Tx handler is separate add 1 for every Tx queue */
    if (!(adapter->flags & IGC_FLAG_QUEUE_PAIRS))
        numvecs += adapter->num_tx_queues;

    /* store the number of vectors reserved for queues */
    adapter->num_q_vectors = numvecs;

    /* add 1 vector for link status interrupts */
    numvecs++;

    //adapter->msix_entries = (struct msix_entry *)kcalloc(numvecs, sizeof(struct msix_entry));

    //if (!adapter->msix_entries)
    //    return;
#ifndef __APPLE__
    /* populate entry values */
    for (i = 0; i < numvecs; i++)
        adapter->msix_entries[i].entry = i;

    err = pci_enable_msix_range(adapter->pdev,
                    adapter->msix_entries,
                    numvecs,
                    numvecs);
    if (err > 0)
        return;

    kfree(adapter->msix_entries, sizeof(struct msix_entry));
    adapter->msix_entries = NULL;
#endif
    igc_reset_interrupt_capability(adapter);

msi_only:
    adapter->flags &= ~IGC_FLAG_HAS_MSIX;

    adapter->rss_queues = 1;
    adapter->flags |= IGC_FLAG_QUEUE_PAIRS;
    adapter->num_rx_queues = 1;
    adapter->num_tx_queues = 1;
    adapter->num_q_vectors = 1;
//#ifndef __APPLE__
    if (!pci_enable_msi_block(adapter->pdev))
        adapter->flags |= IGC_FLAG_HAS_MSI;
//#endif
}

/**
 * igc_update_ring_itr - update the dynamic ITR value based on packet size
 * @q_vector: pointer to q_vector
 *
 * Stores a new ITR value based on strictly on packet size.  This
 * algorithm is less sophisticated than that used in igc_update_itr,
 * due to the difficulty of synchronizing statistics across multiple
 * receive rings.  The divisors and thresholds used by this function
 * were determined based on theoretical maximum wire speed and testing
 * data, in order to minimize response time while increasing bulk
 * throughput.
 * NOTE: This function is called only when operating in a multiqueue
 * receive environment.
 */
static void igc_update_ring_itr(struct igc_q_vector *q_vector)
{
    struct igc_adapter *adapter = q_vector->adapter;
    int new_val = q_vector->itr_val;
    int avg_wire_size = 0;
    unsigned int packets;

    /* For non-gigabit speeds, just fix the interrupt rate at 4000
     * ints/sec - ITR timer value of 120 ticks.
     */
    switch (adapter->link_speed) {
    case SPEED_10:
    case SPEED_100:
        new_val = IGC_4K_ITR;
        goto set_itr_val;
    default:
        break;
    }

    packets = q_vector->rx.total_packets;
    if (packets)
        avg_wire_size = q_vector->rx.total_bytes / packets;

    packets = q_vector->tx.total_packets;
    if (packets)
        avg_wire_size = max_t(u32, avg_wire_size,
                      q_vector->tx.total_bytes / packets);

    /* if avg_wire_size isn't set no work was done */
    if (!avg_wire_size)
        goto clear_counts;

    /* Add 24 bytes to size to account for CRC, preamble, and gap */
    avg_wire_size += 24;

    /* Don't starve jumbo frames */
    avg_wire_size = min(avg_wire_size, 3000);

    /* Give a little boost to mid-size frames */
    if (avg_wire_size > 300 && avg_wire_size < 1200)
        new_val = avg_wire_size / 3;
    else
        new_val = avg_wire_size / 2;

    /* conservative mode (itr 3) eliminates the lowest_latency setting */
    if (new_val < IGC_20K_ITR &&
        ((q_vector->rx.ring && adapter->rx_itr_setting == 3) ||
        (!q_vector->rx.ring && adapter->tx_itr_setting == 3)))
        new_val = IGC_20K_ITR;

set_itr_val:
    if (new_val != q_vector->itr_val) {
        q_vector->itr_val = new_val;
        q_vector->set_itr = 1;
    }
clear_counts:
    q_vector->rx.total_bytes = 0;
    q_vector->rx.total_packets = 0;
    q_vector->tx.total_bytes = 0;
    q_vector->tx.total_packets = 0;
}

static void igc_ring_irq_enable(struct igc_q_vector *q_vector)
{
    struct igc_adapter *adapter = q_vector->adapter;
    //struct igc_hw *hw = &adapter->hw;

    if ((q_vector->rx.ring && (adapter->rx_itr_setting & 3)) ||
        (!q_vector->rx.ring && (adapter->tx_itr_setting & 3))) {
        if (adapter->num_q_vectors == 1)
            igc_set_itr(q_vector);
        else
            igc_update_ring_itr(q_vector);
    }

    if (!test_bit(__IGC_DOWN, &adapter->state)) {
        //if (adapter->msix_entries)
        //    wr32(IGC_EIMS, q_vector->eims_value);
        //else
            igc_irq_enable(adapter);
    }
}

static void igc_add_ring(struct igc_ring *ring,
             struct igc_ring_container *head)
{
    head->ring = ring;
    head->count++;
}

/**
 * igc_cache_ring_register - Descriptor ring to register mapping
 * @adapter: board private structure to initialize
 *
 * Once we know the feature-set enabled for the device, we'll cache
 * the register offset the descriptor ring is assigned to.
 */
static void igc_cache_ring_register(struct igc_adapter *adapter)
{
    int i = 0, j = 0;

    switch (adapter->hw.mac.type) {
    case igc_i225:
    default:
        for (; i < adapter->num_rx_queues; i++)
            adapter->rx_ring[i]->reg_idx = i;
        for (; j < adapter->num_tx_queues; j++)
            adapter->tx_ring[j]->reg_idx = j;
        break;
    }
}

/**
 * igc_poll - NAPI Rx polling callback
 * @napi: napi polling structure
 * @budget: count of how many packets we should handle
 */
static int igc_poll(struct igc_q_vector *q_vector, int budget)
{
    //struct igc_q_vector *q_vector = container_of(napi,
    //                         struct igc_q_vector,
    //                         napi);
    struct igc_ring *rx_ring = q_vector->rx.ring;
    bool clean_complete = true;
    int work_done = 0;

    if (q_vector->tx.ring)
        clean_complete = igc_clean_tx_irq(q_vector, budget);

    if (rx_ring) {
        //int cleaned = rx_ring->xsk_pool ?
        //          igc_clean_rx_irq_zc(q_vector, budget) :
        //          igc_clean_rx_irq(q_vector, budget);
        int cleaned = igc_clean_rx_irq(q_vector, budget);
        work_done += cleaned;
        if (cleaned >= budget)
            clean_complete = false;
    }
#ifndef __APPLE__
    /* If all work not completed, return budget and keep polling */
    if (!clean_complete)
        return budget;
#endif
    /* Exit the polling mode, but don't re-enable interrupts if stack might
     * poll us due to busy-polling
     */
    //if (likely(napi_complete_done(napi, work_done)))
        igc_ring_irq_enable(q_vector);

    return min(work_done, budget - 1);
}

/**
 * igc_alloc_q_vector - Allocate memory for a single interrupt vector
 * @adapter: board private structure to initialize
 * @v_count: q_vectors allocated on adapter, used for ring interleaving
 * @v_idx: index of vector in adapter struct
 * @txr_count: total number of Tx rings to allocate
 * @txr_idx: index of first Tx ring to allocate
 * @rxr_count: total number of Rx rings to allocate
 * @rxr_idx: index of first Rx ring to allocate
 *
 * We allocate one q_vector.  If allocation fails we return -ENOMEM.
 */
static int igc_alloc_q_vector(struct igc_adapter *adapter,
                  unsigned int v_count, unsigned int v_idx,
                  unsigned int txr_count, unsigned int txr_idx,
                  unsigned int rxr_count, unsigned int rxr_idx)
{
    struct igc_q_vector *q_vector;
    struct igc_ring *ring;
    int ring_count;

    /* igc only supports 1 Tx and/or 1 Rx queue per vector */
    if (txr_count > 1 || rxr_count > 1)
        return -ENOMEM;

    ring_count = txr_count + rxr_count;

    /* allocate q_vector and rings */
    q_vector = adapter->q_vector[v_idx];
    if (!q_vector) {
        //q_vector = kzalloc(struct_size(q_vector, ring, ring_count),
        // GFP_KERNEL);
        q_vector = (struct igc_q_vector *)kzalloc(sizeof(struct igc_q_vector) +
                           (sizeof(struct igc_ring) * ring_count));
    } else {
        //memset(q_vector, 0, struct_size(q_vector, ring, ring_count));
        memset(q_vector, 0, sizeof(struct igc_q_vector) +
               (sizeof(struct igc_ring) * ring_count));
    }
    if (!q_vector)
        return -ENOMEM;
#ifdef    __APPLE__
    q_vector->alloc_size = sizeof(struct igc_q_vector) +
    (sizeof(struct igc_ring) * ring_count);
#endif
    /* initialize NAPI */
#ifndef __APPLE__
    netif_napi_add(adapter->netdev, &q_vector->napi, igc_poll);
#endif
    /* tie q_vector and adapter together */
    adapter->q_vector[v_idx] = q_vector;
    q_vector->adapter = adapter;

    /* initialize work limits */
    q_vector->tx.work_limit = adapter->tx_work_limit;

    /* initialize ITR configuration */
    q_vector->itr_register = adapter->io_addr + IGC_EITR(0);
    q_vector->itr_val = IGC_START_ITR;

    /* initialize pointer to rings */
    ring = q_vector->ring;

    /* initialize ITR */
    if (rxr_count) {
        /* rx or rx/tx vector */
        if (!adapter->rx_itr_setting || adapter->rx_itr_setting > 3)
            q_vector->itr_val = adapter->rx_itr_setting;
    } else {
        /* tx only vector */
        if (!adapter->tx_itr_setting || adapter->tx_itr_setting > 3)
            q_vector->itr_val = adapter->tx_itr_setting;
    }

    if (txr_count) {
        /* assign generic ring traits */
        //ring->dev = &adapter->pdev->dev;
        ring->netdev = adapter->netdev;

        /* configure backlink on ring */
        ring->q_vector = q_vector;

        /* update q_vector Tx values */
        igc_add_ring(ring, &q_vector->tx);

        /* apply Tx specific ring traits */
        ring->count = adapter->tx_ring_count;
        ring->queue_index = txr_idx;

        /* assign ring to adapter */
        adapter->tx_ring[txr_idx] = ring;

        /* push pointer to next ring */
        ring++;
    }

    if (rxr_count) {
        /* assign generic ring traits */
        //ring->dev = &adapter->pdev->dev;
        ring->netdev = adapter->netdev;

        /* configure backlink on ring */
        ring->q_vector = q_vector;

        /* update q_vector Rx values */
        igc_add_ring(ring, &q_vector->rx);

        /* apply Rx specific ring traits */
        ring->count = adapter->rx_ring_count;
        ring->queue_index = rxr_idx;

        /* assign ring to adapter */
        adapter->rx_ring[rxr_idx] = ring;
    }

    return 0;
}

/**
 * igc_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 */
static int igc_alloc_q_vectors(struct igc_adapter *adapter)
{
    int rxr_remaining = adapter->num_rx_queues;
    int txr_remaining = adapter->num_tx_queues;
    int rxr_idx = 0, txr_idx = 0, v_idx = 0;
    int q_vectors = adapter->num_q_vectors;
    int err;

    if (q_vectors >= (rxr_remaining + txr_remaining)) {
        for (; rxr_remaining; v_idx++) {
            err = igc_alloc_q_vector(adapter, q_vectors, v_idx,
                         0, 0, 1, rxr_idx);

            if (err)
                goto err_out;

            /* update counts and index */
            rxr_remaining--;
            rxr_idx++;
        }
    }

    for (; v_idx < q_vectors; v_idx++) {
        int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors - v_idx);
        int tqpv = DIV_ROUND_UP(txr_remaining, q_vectors - v_idx);

        err = igc_alloc_q_vector(adapter, q_vectors, v_idx,
                     tqpv, txr_idx, rqpv, rxr_idx);

        if (err)
            goto err_out;

        /* update counts and index */
        rxr_remaining -= rqpv;
        txr_remaining -= tqpv;
        rxr_idx++;
        txr_idx++;
    }

    return 0;

err_out:
    adapter->num_tx_queues = 0;
    adapter->num_rx_queues = 0;
    adapter->num_q_vectors = 0;

    while (v_idx--)
        igc_free_q_vector(adapter, v_idx);

    return -ENOMEM;
}

/**
 * igc_init_interrupt_scheme - initialize interrupts, allocate queues/vectors
 * @adapter: Pointer to adapter structure
 * @msix: boolean for MSI-X capability
 *
 * This function initializes the interrupts and allocates all of the queues.
 */
static int igc_init_interrupt_scheme(struct igc_adapter *adapter, bool msix)
{
    //struct net_device *dev = adapter->netdev;
    int err = 0;

    igc_set_interrupt_capability(adapter, msix);

    err = igc_alloc_q_vectors(adapter);
    if (err) {
        netdev_err(dev, "Unable to allocate memory for vectors\n");
        goto err_alloc_q_vectors;
    }

    igc_cache_ring_register(adapter);

    return 0;

err_alloc_q_vectors:
    igc_reset_interrupt_capability(adapter);
    return err;
}

/**
 * igc_sw_init - Initialize general software structures (struct igc_adapter)
 * @adapter: board private structure to initialize
 *
 * igc_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 */
static int igc_sw_init(struct igc_adapter *adapter)
{
    AppleIGC *netdev = adapter->netdev;

    /* set default ring sizes */
    adapter->tx_ring_count = IGC_DEFAULT_TXD;
    adapter->rx_ring_count = IGC_DEFAULT_RXD;

    /* set default ITR values */
    adapter->rx_itr_setting = IGC_DEFAULT_ITR;
    adapter->tx_itr_setting = IGC_DEFAULT_ITR;

    /* set default work limits */
    adapter->tx_work_limit = IGC_DEFAULT_TX_WORK;

    /* adjust max frame to be at least the size of a standard frame */
    adapter->max_frame_size = netdev->mtu() + ETH_HLEN + ETH_FCS_LEN +
                VLAN_HLEN;
    adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

    //mutex_init(&adapter->nfc_rule_lock);
    //INIT_LIST_HEAD(&adapter->nfc_rule_list);
    //adapter->nfc_rule_count = 0;

    //spin_lock_init(&adapter->stats64_lock);
    /* Assume MSI-X interrupts, will be checked during IRQ allocation */
    //adapter->flags |= IGC_FLAG_HAS_MSIX;

    igc_init_queue_configuration(adapter);

    /* This call may decrease the number of queues */
    if (igc_init_interrupt_scheme(adapter, false)) {
        netdev_err(netdev, "Unable to allocate memory for queues\n");
        return -ENOMEM;
    }

    /* Explicitly disable IRQ since the NIC can be in any state. */
    igc_irq_disable(adapter);

    set_bit(__IGC_DOWN, &adapter->state);

    return 0;
}

/**
 * igc_up - Open the interface and prepare it to handle traffic
 * @adapter: board private structure
 */
void igc_up(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;

    /* hardware has been reset, we need to reload some things */
    igc_configure(adapter);

    clear_bit(__IGC_DOWN, &adapter->state);
#ifndef __APPLE__
    for (i = 0; i < adapter->num_q_vectors; i++)
        napi_enable(&adapter->q_vector[i]->napi);
#endif
    //if (adapter->msix_entries)
    //    igc_configure_msix(adapter);
    //else
        igc_assign_vector(adapter->q_vector[0], 0);

    /* Clear any pending interrupts. */
    rd32(IGC_ICR);
    igc_irq_enable(adapter);

    netif_tx_start_all_queues(adapter->netdev);

    /* start the watchdog. */
    hw->mac.get_link_status = true;
#ifdef __APPLE__
    adapter->netdev->setTimers(TRUE);
#else
    schedule_work(&adapter->watchdog_task);
#endif
}

/**
 * igc_update_stats - Update the board statistics counters
 * @adapter: board private structure
 */
void igc_update_stats(struct igc_adapter *adapter)
{
    IONetworkStats * net_stats = adapter->netdev->getNetStats();
    IOEthernetStats * ether_stats = adapter->netdev->getEtherStats();
//    struct rtnl_link_stats64 *net_stats = &adapter->stats64;
//    struct pci_dev *pdev = adapter->pdev;
    struct igc_hw *hw = &adapter->hw;
    u64 _bytes, _packets;
    u64 bytes, packets;
    u32 mpc;
    int i;

    /* Prevent stats update while adapter is being reset, or if the pci
     * connection is down.
     */
    if (adapter->link_speed == 0)
        return;
#ifdef HAVE_PCI_ERS
    if (pci_channel_offline(pdev))
        return;
#endif
    
    packets = 0;
    bytes = 0;

    //rcu_read_lock();
    for (i = 0; i < adapter->num_rx_queues; i++) {
        struct igc_ring *ring = adapter->rx_ring[i];
        u32 rqdpc = rd32(IGC_RQDPC(i));

        if (hw->mac.type >= igc_i225)
            wr32(IGC_RQDPC(i), 0);

        if (rqdpc) {
            ring->rx_stats.drops += rqdpc;
        }

        _bytes = ring->rx_stats.bytes;
        _packets = ring->rx_stats.packets;
        
        bytes += _bytes;
        packets += _packets;
    }
    
    net_stats->inputPackets = (u32)packets;

    packets = 0;
    bytes = 0;
    for (i = 0; i < adapter->num_tx_queues; i++) {
        struct igc_ring *ring = adapter->tx_ring[i];

        _bytes = ring->tx_stats.bytes;
        _packets = ring->tx_stats.packets;
        bytes += _bytes;
        packets += _packets;
    }
    //net_stats->tx_bytes = bytes;
    net_stats->outputPackets = (u32)packets;
    //rcu_read_unlock();

    /* read stats registers */
    adapter->stats.crcerrs += rd32(IGC_CRCERRS);
    adapter->stats.gprc += rd32(IGC_GPRC);
    adapter->stats.gorc += rd32(IGC_GORCL);
    rd32(IGC_GORCH); /* clear GORCL */
    adapter->stats.bprc += rd32(IGC_BPRC);
    adapter->stats.mprc += rd32(IGC_MPRC);
    adapter->stats.roc += rd32(IGC_ROC);

    adapter->stats.prc64 += rd32(IGC_PRC64);
    adapter->stats.prc127 += rd32(IGC_PRC127);
    adapter->stats.prc255 += rd32(IGC_PRC255);
    adapter->stats.prc511 += rd32(IGC_PRC511);
    adapter->stats.prc1023 += rd32(IGC_PRC1023);
    adapter->stats.prc1522 += rd32(IGC_PRC1522);
    adapter->stats.tlpic += rd32(IGC_TLPIC);
    adapter->stats.rlpic += rd32(IGC_RLPIC);
    adapter->stats.hgptc += rd32(IGC_HGPTC);

    mpc = rd32(IGC_MPC);
    adapter->stats.mpc += mpc;
    //net_stats->rx_fifo_errors += mpc;
    adapter->stats.scc += rd32(IGC_SCC);
    adapter->stats.ecol += rd32(IGC_ECOL);
    adapter->stats.mcc += rd32(IGC_MCC);
    adapter->stats.latecol += rd32(IGC_LATECOL);
    adapter->stats.dc += rd32(IGC_DC);
    adapter->stats.rlec += rd32(IGC_RLEC);
    adapter->stats.xonrxc += rd32(IGC_XONRXC);
    adapter->stats.xontxc += rd32(IGC_XONTXC);
    adapter->stats.xoffrxc += rd32(IGC_XOFFRXC);
    adapter->stats.xofftxc += rd32(IGC_XOFFTXC);
    adapter->stats.fcruc += rd32(IGC_FCRUC);
    adapter->stats.gptc += rd32(IGC_GPTC);
    adapter->stats.gotc += rd32(IGC_GOTCL);
    rd32(IGC_GOTCH); /* clear GOTCL */
    adapter->stats.rnbc += rd32(IGC_RNBC);
    adapter->stats.ruc += rd32(IGC_RUC);
    adapter->stats.rfc += rd32(IGC_RFC);
    adapter->stats.rjc += rd32(IGC_RJC);
    adapter->stats.tor += rd32(IGC_TORH);
    adapter->stats.tot += rd32(IGC_TOTH);
    adapter->stats.tpr += rd32(IGC_TPR);

    adapter->stats.ptc64 += rd32(IGC_PTC64);
    adapter->stats.ptc127 += rd32(IGC_PTC127);
    adapter->stats.ptc255 += rd32(IGC_PTC255);
    adapter->stats.ptc511 += rd32(IGC_PTC511);
    adapter->stats.ptc1023 += rd32(IGC_PTC1023);
    adapter->stats.ptc1522 += rd32(IGC_PTC1522);

    adapter->stats.mptc += rd32(IGC_MPTC);
    adapter->stats.bptc += rd32(IGC_BPTC);

    adapter->stats.tpt += rd32(IGC_TPT);
    adapter->stats.colc += rd32(IGC_COLC);
    adapter->stats.colc += rd32(IGC_RERC);

    adapter->stats.algnerrc += rd32(IGC_ALGNERRC);

    adapter->stats.tsctc += rd32(IGC_TSCTC);

    adapter->stats.iac += rd32(IGC_IAC);

    /* Fill out the OS statistics structure */
    //net_stats->multicast = adapter->stats.mprc;
    net_stats->collisions = (uint32_t)adapter->stats.colc;

    /* Rx Errors */

    /* RLEC on some newer hardware can be incorrect so build
     * our own version based on RUC and ROC
     */
//    net_stats->rx_errors = adapter->stats.rxerrc +
//        adapter->stats.crcerrs + adapter->stats.algnerrc +
//        adapter->stats.ruc + adapter->stats.roc +
//        adapter->stats.cexterr;
//    net_stats->rx_length_errors = adapter->stats.ruc +
//                      adapter->stats.roc;
//    net_stats->rx_crc_errors = adapter->stats.crcerrs;
//    net_stats->rx_frame_errors = adapter->stats.algnerrc;
//    net_stats->rx_missed_errors = adapter->stats.mpc;
    net_stats->inputErrors = (u32)(adapter->stats.rxerrc +
        adapter->stats.crcerrs + adapter->stats.algnerrc +
        adapter->stats.ruc + adapter->stats.roc +
        adapter->stats.cexterr);
    ether_stats->dot3StatsEntry.frameTooLongs = (u32)adapter->stats.roc;
    ether_stats->dot3RxExtraEntry.frameTooShorts = (u32)adapter->stats.ruc;
    ether_stats->dot3StatsEntry.fcsErrors = (u32)adapter->stats.crcerrs;
    ether_stats->dot3StatsEntry.alignmentErrors = (u32)adapter->stats.algnerrc;
    ether_stats->dot3StatsEntry.missedFrames = (u32)adapter->stats.mpc;
    
    /* Tx Errors */
//    net_stats->tx_errors = adapter->stats.ecol +
//                   adapter->stats.latecol;
//    net_stats->tx_aborted_errors = adapter->stats.ecol;
//    net_stats->tx_window_errors = adapter->stats.latecol;
//    net_stats->tx_carrier_errors = adapter->stats.tncrs;
    //net_stats->outputErrors = (u32)(adapter->stats.ecol + adapter->stats.latecol);
    ether_stats->dot3StatsEntry.deferredTransmissions = (u32)adapter->stats.ecol;
    ether_stats->dot3StatsEntry.lateCollisions = (u32)adapter->stats.latecol;
    ether_stats->dot3StatsEntry.carrierSenseErrors = (u32)adapter->stats.tncrs;

    /* Tx Dropped needs to be maintained elsewhere */

    /* Management Stats */
    adapter->stats.mgptc += rd32(IGC_MGTPTC);
    adapter->stats.mgprc += rd32(IGC_MGTPRC);
    adapter->stats.mgpdc += rd32(IGC_MGTPDC);
}

/**
 * igc_down - Close the interface
 * @adapter: board private structure
 */
void igc_down(struct igc_adapter *adapter)
{
    AppleIGC *netdev = adapter->netdev;
    struct igc_hw *hw = &adapter->hw;
    u32 tctl, rctl;
    // int i = 0;

    set_bit(__IGC_DOWN, &adapter->state);

    //igc_ptp_suspend(adapter);

    //if (pci_device_is_present(adapter->pdev)) {
        /* disable receives in the hardware */
        rctl = rd32(IGC_RCTL);
        wr32(IGC_RCTL, rctl & ~IGC_RCTL_EN);
        /* flush and sleep below */
    //}
    /* set trans_start so we don't get spurious watchdogs during reset */
    //netif_trans_update(netdev);

    netif_carrier_off(netdev);
    netif_tx_stop_all_queues(netdev);

    if (pci_device_is_present(adapter->pdev)) {
        /* disable transmits in the hardware */
        tctl = rd32(IGC_TCTL);
        tctl &= ~IGC_TCTL_EN;
        wr32(IGC_TCTL, tctl);
        /* flush both disables and wait for them to finish */
        wrfl();
        usleep_range(10000, 20000);

        igc_irq_disable(adapter);
    }

    adapter->flags &= ~IGC_FLAG_NEED_LINK_UPDATE;
#ifndef __APPLE__
    for (i = 0; i < adapter->num_q_vectors; i++) {
        if (adapter->q_vector[i]) {
            napi_synchronize(&adapter->q_vector[i]->napi);
            napi_disable(&adapter->q_vector[i]->napi);
        }
    }
#endif

#ifdef __APPLE__
    adapter->netdev->setTimers(FALSE);
#else
    del_timer_sync(&adapter->watchdog_timer);
    del_timer_sync(&adapter->phy_info_timer);
#endif
    /* record the stats before reset*/
    //spin_lock(&adapter->stats64_lock);
    igc_update_stats(adapter);
    //spin_unlock(&adapter->stats64_lock);

    adapter->link_speed = 0;
    adapter->link_duplex = 0;

#ifdef HAVE_PCI_ERS
    if (!pci_channel_offline(adapter->pdev))
        igc_reset(adapter);
#else
    igc_reset(adapter);
#endif
    /* clear VLAN promisc flag so VFTA will be updated if necessary */
    adapter->flags &= ~IGC_FLAG_VLAN_PROMISC;

    igc_clean_all_tx_rings(adapter);
    igc_clean_all_rx_rings(adapter);
}

void igc_reinit_locked(struct igc_adapter *adapter)
{
    while (test_and_set_bit(__IGC_RESETTING, &adapter->state))
        usleep_range(1000, 2000);
    igc_down(adapter);
    igc_up(adapter);
    clear_bit(__IGC_RESETTING, &adapter->state);
}

#ifndef __APPLE__
static void igc_reset_task(struct work_struct *work)
{
    struct igc_adapter *adapter;

    adapter = container_of(work, struct igc_adapter, reset_task);

    rtnl_lock();
    /* If we're already down or resetting, just bail */
    if (test_bit(__IGC_DOWN, &adapter->state) ||
        test_bit(__IGC_RESETTING, &adapter->state)) {
        rtnl_unlock();
        return;
    }

    igc_rings_dump(adapter);
    igc_regs_dump(adapter);
    netdev_err(adapter->netdev, "Reset adapter\n");
    igc_reinit_locked(adapter);
    rtnl_unlock();
}
#endif

/**
 * igc_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int igc_change_mtu(IOEthernetController *netdev, int new_mtu)
{
    int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN;
    struct igc_adapter *adapter = netdev_priv(netdev);

#if 0
    if (igc_xdp_is_enabled(adapter) && new_mtu > ETH_DATA_LEN) {
        netdev_dbg(netdev, "Jumbo frames not supported with XDP");
        return -EINVAL;
    }
#endif

    /* adjust max frame to be at least the size of a standard frame */
    if (max_frame < (ETH_FRAME_LEN + ETH_FCS_LEN))
        max_frame = ETH_FRAME_LEN + ETH_FCS_LEN;

    while (test_and_set_bit(__IGC_RESETTING, &adapter->state))
        usleep_range(1000, 2000);

    /* igc_down has a dependency on max_frame_size */
    adapter->max_frame_size = max_frame;

    if (netif_running(netdev))
        igc_down(adapter);
    
#if 0
    netdev->mtu = new_mtu;
#endif

    if (netif_running(netdev))
        igc_up(adapter);
    else
        igc_reset(adapter);

    clear_bit(__IGC_RESETTING, &adapter->state);

    return 0;
}

static netdev_features_t igc_fix_features(struct net_device *netdev,
                      netdev_features_t features)
{
    /* Since there is no support for separate Rx/Tx vlan accel
     * enable/disable make sure Tx flag is always in same state as Rx.
     */
#ifdef NETIF_F_HW_VLAN_CTAG_RX
    if (features & NETIF_F_HW_VLAN_CTAG_RX)
        features |= NETIF_F_HW_VLAN_CTAG_TX;
    else
        features &= ~NETIF_F_HW_VLAN_CTAG_TX;
#else
    if (features & NETIF_F_HW_VLAN_RX)
        features |= NETIF_F_HW_VLAN_TX;
    else
        features &= ~NETIF_F_HW_VLAN_TX;
#endif

    return features;
}
#ifdef HAVE_NDO_SET_FEATURES
static int igc_set_features(AppleIGC *netdev,
                netdev_features_t features)
{
    netdev_features_t changed = netdev->features() ^ features;
    struct igc_adapter *adapter = netdev_priv(netdev);

#ifdef NETIF_F_HW_VLAN_CTAG_RX
    if (changed & NETIF_F_HW_VLAN_CTAG_RX)
        igc_vlan_mode(netdev, features);
#else
    if (changed & NETIF_F_HW_VLAN_RX)
        igc_vlan_mode(netdev, adapter->vlgrp);
#endif

    /* Add VLAN support */
    if (!(changed & (NETIF_F_RXALL | NETIF_F_NTUPLE)))
        return 0;

    if (!(features & NETIF_F_NTUPLE))
        igc_flush_nfc_rules(adapter);

    netdev->features = features;

    if (netif_running(netdev))
        igc_reinit_locked(adapter);
    else
        igc_reset(adapter);

    return 1;
}
#endif /* HAVE_NDO_SET_FEATURES */

#ifdef HAVE_NDO_FEATURES_CHECK
#define IGB_MAX_TUNNEL_HDR_LEN 80
#ifdef NETIF_F_GSO_PARTIAL
#define IGB_MAX_MAC_HDR_LEN    127
#define IGB_MAX_NETWORK_HDR_LEN    511

static netdev_features_t
igc_features_check(struct sk_buff *skb, struct net_device *dev,
           netdev_features_t features)
{
    unsigned int network_hdr_len, mac_hdr_len;

    /* Make certain the headers can be described by a context descriptor */
    mac_hdr_len = skb_network_header(skb) - skb->data;
    if (unlikely(mac_hdr_len > IGC_MAX_MAC_HDR_LEN))
        return features & ~(NETIF_F_HW_CSUM |
                    NETIF_F_SCTP_CRC |
                    NETIF_F_HW_VLAN_CTAG_TX |
                    NETIF_F_TSO |
                    NETIF_F_TSO6);

    network_hdr_len = skb_checksum_start(skb) - skb_network_header(skb);
    if (unlikely(network_hdr_len >  IGC_MAX_NETWORK_HDR_LEN))
        return features & ~(NETIF_F_HW_CSUM |
                    NETIF_F_SCTP_CRC |
                    NETIF_F_TSO |
                    NETIF_F_TSO6);

    /* We can only support IPv4 TSO in tunnels if we can mangle the
     * inner IP ID field, so strip TSO if MANGLEID is not supported.
     */
    if (skb->encapsulation && !(features & NETIF_F_TSO_MANGLEID))
        features &= ~NETIF_F_TSO;

    return features;
}
#else /* NETIF_F_GSO_PARTIAL */
static netdev_features_t
igc_features_check(struct sk_buff *skb, struct net_device *dev,
           netdev_features_t features)
{
    if (!skb->encapsulation)
        return features;

    if (unlikely(skb_inner_mac_header(skb) - skb_transport_header(skb) >
                IGB_MAX_TUNNEL_HDR_LEN))
        return features & ~NETIF_F_CSUM_MASK;

    return features;
}
#endif /* NETIF_F_GSO_PARTIAL */
#endif /* HAVE_NDO_FEATURES_CHECK */

/**
 * igc_msix_other - msix other interrupt handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
#ifndef __APPLE__
static irqreturn_t igc_msix_other(int irq, void *data)
{
    struct igc_adapter *adapter = data;
    struct igc_hw *hw = &adapter->hw;
    u32 icr = rd32(IGC_ICR);

    /* reading ICR causes bit 31 of EICR to be cleared */
    if (icr & IGC_ICR_DRSTA)
        schedule_work(&adapter->reset_task);

    if (icr & IGC_ICR_DOUTSYNC) {
        /* HW is reporting DMA is out of sync */
        adapter->stats.doosync++;
    }

    if (icr & IGC_ICR_LSC) {
        hw->mac.get_link_status = true;
        /* guard against interrupt when we're going down */
        if (!test_bit(__IGC_DOWN, &adapter->state))
            mod_timer(&adapter->watchdog_timer, jiffies + 1);
    }

    if (icr & IGC_ICR_TS)
        igc_tsync_interrupt(adapter);

    wr32(IGC_EIMS, adapter->eims_other);

    return IRQ_HANDLED;
}
#endif

static void igc_write_itr(struct igc_q_vector *q_vector)
{
    u32 itr_val = q_vector->itr_val & IGC_QVECTOR_MASK;

    if (!q_vector->set_itr)
        return;

    if (!itr_val)
        itr_val = IGC_ITR_VAL_MASK;

    itr_val |= IGC_EITR_CNT_IGNR;

    writel(itr_val, q_vector->itr_register);
    q_vector->set_itr = 0;
}

#ifndef __APPLE__
static irqreturn_t igc_msix_ring(int irq, void *data)
{
    struct igc_q_vector *q_vector = data;

    /* Write the ITR value calculated from the previous interrupt. */
    igc_write_itr(q_vector);

    napi_schedule(&q_vector->napi);

    return IRQ_HANDLED;
}
#endif

/**
 * igc_request_msix - Initialize MSI-X interrupts
 * @adapter: Pointer to adapter structure
 *
 * igc_request_msix allocates MSI-X vectors and requests interrupts from the
 * kernel.
 */
static int igc_request_msix(struct igc_adapter *adapter)
{
#ifdef __APPLE__
    return -1;
#else
    unsigned int num_q_vectors = adapter->num_q_vectors;
    int i = 0, err = 0, vector = 0, free_vector = 0;
    struct net_device *netdev = adapter->netdev;

    err = request_irq(adapter->msix_entries[vector].vector,
              &igc_msix_other, 0, netdev->name, adapter);
    if (err)
        goto err_out;

    if (num_q_vectors > MAX_Q_VECTORS) {
        num_q_vectors = MAX_Q_VECTORS;
        dev_warn(&adapter->pdev->dev,
             "The number of queue vectors (%d) is higher than max allowed (%d)\n",
             adapter->num_q_vectors, MAX_Q_VECTORS);
    }
    for (i = 0; i < num_q_vectors; i++) {
        struct igc_q_vector *q_vector = adapter->q_vector[i];

        vector++;

        q_vector->itr_register = adapter->io_addr + IGC_EITR(vector);

        if (q_vector->rx.ring && q_vector->tx.ring)
            sprintf(q_vector->name, "%s-TxRx-%u", netdev->name,
                q_vector->rx.ring->queue_index);
        else if (q_vector->tx.ring)
            sprintf(q_vector->name, "%s-tx-%u", netdev->name,
                q_vector->tx.ring->queue_index);
        else if (q_vector->rx.ring)
            sprintf(q_vector->name, "%s-rx-%u", netdev->name,
                q_vector->rx.ring->queue_index);
        else
            sprintf(q_vector->name, "%s-unused", netdev->name);

        err = request_irq(adapter->msix_entries[vector].vector,
                  igc_msix_ring, 0, q_vector->name,
                  q_vector);
        if (err)
            goto err_free;
    }

    igc_configure_msix(adapter);
    return 0;

err_free:
    /* free already assigned IRQs */
    free_irq(adapter->msix_entries[free_vector++].vector, adapter);

    vector--;
    for (i = 0; i < vector; i++) {
        free_irq(adapter->msix_entries[free_vector++].vector,
             adapter->q_vector[i]);
    }
err_out:
    return err;
#endif
}

/**
 * igc_clear_interrupt_scheme - reset the device to a state of no interrupts
 * @adapter: Pointer to adapter structure
 *
 * This function resets the device so that it has 0 rx queues, tx queues, and
 * MSI-X interrupts allocated.
 */
static void igc_clear_interrupt_scheme(struct igc_adapter *adapter)
{
    igc_free_q_vectors(adapter);
    igc_reset_interrupt_capability(adapter);
}

/* Need to wait a few seconds after link up to get diagnostic information from
 * the phy
 */
#ifndef __APPLE__
static void igc_update_phy_info(struct timer_list *t)
{
    struct igc_adapter *adapter = from_timer(adapter, t, phy_info_timer);

    igc_get_phy_info(&adapter->hw);
}
#endif

/**
 * igc_has_link - check shared code for link and determine up/down
 * @adapter: pointer to driver private info
 */
bool igc_has_link(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    bool link_active = false;

    /* get_link_status is set on LSC (link status) interrupt or
     * rx sequence error interrupt.  get_link_status will stay
     * false until the igc_check_for_link establishes link
     * for copper adapters ONLY
     */
    if (!hw->mac.get_link_status)
        return true;
    hw->mac.ops.check_for_link(hw);
    link_active = !hw->mac.get_link_status;

    if (hw->mac.type == igc_i225) {
        if (!netif_carrier_ok(adapter->netdev)) {
            adapter->flags &= ~IGC_FLAG_NEED_LINK_UPDATE;
        } else if (!(adapter->flags & IGC_FLAG_NEED_LINK_UPDATE)) {
            adapter->flags |= IGC_FLAG_NEED_LINK_UPDATE;
            adapter->link_check_timeout = jiffies;
        }
    }

    return link_active;
}

/**
 * igc_intr_msi - Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 */
static irqreturn_t igc_intr_msi(int irq, void *data)
{
#ifndef __APPLE__
    struct igc_adapter *adapter = (struct igc_adapter *)data;
    struct igc_q_vector *q_vector = adapter->q_vector[0];
    struct igc_hw *hw = &adapter->hw;
    /* read ICR disables interrupts using IAM */
    u32 icr = rd32(IGC_ICR);

    igc_write_itr(q_vector);

    if (icr & IGC_ICR_DRSTA)
        schedule_work(&adapter->reset_task);

    if (icr & IGC_ICR_DOUTSYNC) {
        /* HW is reporting DMA is out of sync */
        adapter->stats.doosync++;
    }

    if (icr & (IGC_ICR_RXSEQ | IGC_ICR_LSC)) {
        hw->mac.get_link_status = true;
        if (!test_bit(__IGC_DOWN, &adapter->state))
            mod_timer(&adapter->watchdog_timer, jiffies + 1);
    }

    if (icr & IGC_ICR_TS)
        igc_tsync_interrupt(adapter);

    napi_schedule(&q_vector->napi);
#endif
    return IRQ_HANDLED;
}

/**
 * igc_intr - Legacy Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 */
static irqreturn_t igc_intr(int irq, void *data)
{
/* All logic implemented in AppleIGC::interruptOccurred */
#ifndef __APPLE__
    struct igc_adapter *adapter = data;
    struct igc_q_vector *q_vector = adapter->q_vector[0];
    struct igc_hw *hw = &adapter->hw;
    /* Interrupt Auto-Mask...upon reading ICR, interrupts are masked.  No
     * need for the IMC write
     */
    u32 icr = rd32(IGC_ICR);

    /* IMS will not auto-mask if INT_ASSERTED is not set, and if it is
     * not set, then the adapter didn't send an interrupt
     */
    if (!(icr & IGC_ICR_INT_ASSERTED))
        return IRQ_NONE;

    igc_write_itr(q_vector);

    if (icr & IGC_ICR_DRSTA)
        schedule_work(&adapter->reset_task);

    if (icr & IGC_ICR_DOUTSYNC) {
        /* HW is reporting DMA is out of sync */
        adapter->stats.doosync++;
    }

    if (icr & (IGC_ICR_RXSEQ | IGC_ICR_LSC)) {
        hw->mac.get_link_status = true;
        /* guard against interrupt when we're going down */
        if (!test_bit(__IGC_DOWN, &adapter->state))
            mod_timer(&adapter->watchdog_timer, jiffies + 1);
    }

    if (icr & IGC_ICR_TS)
        igc_tsync_interrupt(adapter);

    napi_schedule(&q_vector->napi);
#endif
    return IRQ_HANDLED;
}

static void igc_free_irq(struct igc_adapter *adapter)
{
#ifndef __APPLE__
    if (adapter->msix_entries) {
        int vector = 0, i;

        free_irq(adapter->msix_entries[vector++].vector, adapter);

        for (i = 0; i < adapter->num_q_vectors; i++)
            free_irq(adapter->msix_entries[vector++].vector,
                 adapter->q_vector[i]);
    } else {
        free_irq(adapter->pdev->irq, adapter);
    }
#endif
}

/**
 * igc_request_irq - initialize interrupts
 * @adapter: Pointer to adapter structure
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 */
static int igc_request_irq(struct igc_adapter *adapter)
{
    int err = 0;

    if (adapter->flags & IGC_FLAG_HAS_MSIX) {
        err = igc_request_msix(adapter);
        if (!err)
            goto request_done;
        /* fall back to MSI */
        igc_free_all_tx_resources(adapter);
        igc_free_all_rx_resources(adapter);

        igc_clear_interrupt_scheme(adapter);
        err = igc_init_interrupt_scheme(adapter, false);
        if (err)
            goto request_done;
        igc_setup_all_tx_resources(adapter);
        igc_setup_all_rx_resources(adapter);
        igc_configure(adapter);
    }

    igc_assign_vector(adapter->q_vector[0], 0);

#ifndef __APPLE__
    if (adapter->flags & IGC_FLAG_HAS_MSI) {
        err = request_irq(pdev->irq, &igc_intr_msi, 0,
                  netdev->name, adapter);
        if (!err)
            goto request_done;

        /* fall back to legacy interrupts */
        igc_reset_interrupt_capability(adapter);
        adapter->flags &= ~IGC_FLAG_HAS_MSI;
    }

    err = request_irq(pdev->irq, &igc_intr, IRQF_SHARED,
              netdev->name, adapter);
#endif
    if (err)
        netdev_err(netdev, "Error %d getting interrupt\n", err);

request_done:
    return err;
}

/**
 * __igc_open - Called when a network interface is made active
 * @netdev: network interface device structure
 * @resuming: boolean indicating if the device is resuming
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 */
static int __igc_open(IOEthernetController *netdev, bool resuming)
{
    struct igc_adapter *adapter = netdev_priv(netdev);
#if 0
    struct pci_dev *pdev = adapter->pdev;
#endif
    struct igc_hw *hw = &adapter->hw;
    int err = 0;

    /* disallow open during test */

    if (test_bit(__IGC_TESTING, &adapter->state)) {
        WARN_ON(resuming);
        return -EBUSY;
    }

#if 0
    if (!resuming)
        pm_runtime_get_sync(&pdev->dev);
#endif

    netif_carrier_off(netdev);

    /* allocate transmit descriptors */
    err = igc_setup_all_tx_resources(adapter);
    if (err)
        goto err_setup_tx;

    /* allocate receive descriptors */
    err = igc_setup_all_rx_resources(adapter);
    if (err)
        goto err_setup_rx;

    igc_power_up_link(adapter);

    igc_configure(adapter);

    err = igc_request_irq(adapter);
    if (err)
        goto err_req_irq;

#ifndef __APPLE__
    /* Notify the stack of the actual queue counts. */
    err = netif_set_real_num_tx_queues(netdev, adapter->num_tx_queues);
    if (err)
        goto err_set_queues;

    err = netif_set_real_num_rx_queues(netdev, adapter->num_rx_queues);
    if (err)
        goto err_set_queues;
#endif

    clear_bit(__IGC_DOWN, &adapter->state);

#ifndef __APPLE__
    for (i = 0; i < adapter->num_q_vectors; i++)
        napi_enable(&adapter->q_vector[i]->napi);
#endif

    /* Clear any pending interrupts. */
    rd32(IGC_ICR);
    igc_irq_enable(adapter);
#ifndef __APPLE__
    if (!resuming)
        pm_runtime_put(&pdev->dev);
#endif

    netif_tx_start_all_queues(netdev);

    /* start the watchdog. */
    hw->mac.get_link_status = true;
    schedule_work(&adapter->watchdog_task);

    return IGC_SUCCESS;
#ifndef __APPLE__
err_set_queues:
    igc_free_irq(adapter);
#endif
err_req_irq:
    igc_release_hw_control(adapter);
    igc_power_down_phy_copper_base(&adapter->hw);
    igc_free_all_rx_resources(adapter);
err_setup_rx:
    igc_free_all_tx_resources(adapter);
err_setup_tx:
    igc_reset(adapter);
#if 0
    if (!resuming)
        pm_runtime_put(&pdev->dev);
#endif

    return err;
}

int igc_open(IOEthernetController *netdev)
{
    return __igc_open(netdev, false);
}

/**
 * __igc_close - Disables a network interface
 * @netdev: network interface device structure
 * @suspending: boolean indicating the device is suspending
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the driver's control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 */
static int __igc_close(IOEthernetController *netdev, bool suspending)
{
    struct igc_adapter *adapter = netdev_priv(netdev);
#if 0
    struct pci_dev *pdev = adapter->pdev;
#endif
    WARN_ON(test_bit(__IGC_RESETTING, &adapter->state));

#if 0
    if (!suspending)
        pm_runtime_get_sync(&pdev->dev);
#endif
    igc_down(adapter);

    igc_release_hw_control(adapter);

    igc_free_irq(adapter);

    igc_free_all_tx_resources(adapter);
    igc_free_all_rx_resources(adapter);
#if 0
    if (!suspending)
        pm_runtime_put_sync(&pdev->dev);
#endif
    return 0;
}

int igc_close(IOEthernetController *netdev)
{
    //if (netif_device_present(netdev) || netdev->dismantle)
        return __igc_close(netdev, false);
    //return 0;
}

/**
 * igc_ioctl - Access the hwtstamp interface
 * @netdev: network interface device structure
 * @ifr: interface request data
 * @cmd: ioctl command
 **/
static int igc_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
    switch (cmd) {
#ifdef SIOCGHWTSTAMP
    case SIOCGHWTSTAMP:
        return igc_ptp_get_ts_config(netdev, ifr);
#endif
#ifdef SIOCSHWTSTAMP
    case SIOCSHWTSTAMP:
        return igc_ptp_set_ts_config(netdev, ifr);
#endif
    default:
        return -EOPNOTSUPP;
    }
}

static int igc_save_launchtime_params(struct igc_adapter *adapter, int queue,
                      bool enable)
{
    struct igc_ring *ring;

    if (queue < 0 || queue >= adapter->num_tx_queues)
        return -EINVAL;

    ring = adapter->tx_ring[queue];
    ring->launchtime_enable = enable;

    return 0;
}
#if 0
static bool is_base_time_past(ktime_t base_time, const struct timespec64 *now)
{
    struct timespec64 b;

    b = ktime_to_timespec64(base_time);

    return timespec64_compare(now, &b) > 0;
}
#endif

static int igc_save_cbs_params(struct igc_adapter *adapter, int queue,
                   bool enable, int idleslope, int sendslope,
                   int hicredit, int locredit)
{
    bool cbs_status[IGC_MAX_SR_QUEUES] = { false };
    struct igc_ring *ring;
    int i;
    
    /* i225 has two sets of credit-based shaper logic.
     * Supporting it only on the top two priority queues
     */
    if (queue < 0 || queue > 1)
        return -EINVAL;
    
    ring = adapter->tx_ring[queue];
    
    for (i = 0; i < IGC_MAX_SR_QUEUES; i++)
        if (adapter->tx_ring[i])
            cbs_status[i] = adapter->tx_ring[i]->cbs_enable;
    
    /* CBS should be enabled on the highest priority queue first in order
     * for the CBS algorithm to operate as intended.
     */
    if (enable) {
        if (queue == 1 && !cbs_status[0]) {
            netdev_err(netdev,
                       "Enabling CBS on queue1 before queue0\n");
            return -EINVAL;
        }
    } else {
        if (queue == 0 && cbs_status[1]) {
            netdev_err(netdev,
                       "Disabling CBS on queue0 before queue1\n");
            return -EINVAL;
        }
    }
    
    ring->cbs_enable = enable;
    ring->idleslope = idleslope;
    ring->sendslope = sendslope;
    ring->hicredit = hicredit;
    ring->locredit = locredit;
    
    return 0;
}

static void igc_trigger_rxtxq_interrupt(struct igc_adapter *adapter,
                    struct igc_q_vector *q_vector)
{
    struct igc_hw *hw = &adapter->hw;
    u32 eics = 0;

    eics |= q_vector->eims_value;
    wr32(IGC_EICS, eics);
}

/* PCIe configuration access */
void igc_read_pci_cfg(struct igc_hw *hw, u32 reg, u16 *value)
{
    struct igc_adapter *adapter = (igc_adapter *)hw->back;
    
    *value = adapter->pdev->configRead16(reg);
}

void igc_write_pci_cfg(struct igc_hw *hw, u32 reg, u16 *value)
{
    struct igc_adapter *adapter = (igc_adapter *)hw->back;

    adapter->pdev->configWrite16(reg, *value);
}

s32 igc_read_pcie_cap_reg(struct igc_hw *hw, u32 reg, u16 *value)
{
    struct igc_adapter *adapter = (igc_adapter *)hw->back;
    u8 cap_offset;

    if (0 == adapter->pdev->findPCICapability(kIOPCIPCIExpressCapability, &cap_offset))
        return -IGC_ERR_CONFIG;

    *value = adapter->pdev->configRead16(cap_offset + reg);
#if 0
    if (!pci_is_pcie(adapter->pdev))
        return -IGC_ERR_CONFIG;

    pcie_capability_read_word(adapter->pdev, reg, value);
#endif
    return IGC_SUCCESS;
}

s32 igc_write_pcie_cap_reg(struct igc_hw *hw, u32 reg, u16 *value)
{
    struct igc_adapter *adapter = (igc_adapter *)hw->back;
    u8 cap_offset;

    if (0 == adapter->pdev->findPCICapability(kIOPCIPCIExpressCapability, &cap_offset))
        return -IGC_ERR_CONFIG;
    
    adapter->pdev->configWrite16(cap_offset + reg, *value);
#if 0
    if (!pci_is_pcie(adapter->pdev))
        return -IGC_ERR_CONFIG;

    pcie_capability_write_word(adapter->pdev, reg, *value);
#endif
    return IGC_SUCCESS;
}

u32 igc_rd32(struct igc_hw *hw, u32 reg)
{
    //struct igc_adapter *igc = container_of(hw, struct igc_adapter, hw);
    u8 __iomem *hw_addr = READ_ONCE(hw->hw_addr);
    u32 value = 0;

    if (IGC_REMOVED(hw_addr))
        return ~value;

    value = readl(&hw_addr[reg]);

    /* reads should not return all F's */
    if (!(~value) && (!reg || !(~readl(hw_addr)))) {
        netdev_err(netdev, "PCIe link lost, device now detached\n");
    }

    return value;
}

#ifndef    __APPLE__
static int __igc_shutdown(struct pci_dev *pdev, bool *enable_wake,
              bool runtime)
{
    struct net_device *netdev = pci_get_drvdata(pdev);
    struct igc_adapter *adapter = netdev_priv(netdev);
    u32 wufc = runtime ? IGC_WUFC_LNKC : adapter->wol;
    struct igc_hw *hw = &adapter->hw;
    u32 ctrl, rctl, status;
    bool wake;

    rtnl_lock();
    netif_device_detach(netdev);

    if (netif_running(netdev))
        __igc_close(netdev, true);

    igc_ptp_suspend(adapter);

    igc_clear_interrupt_scheme(adapter);
    rtnl_unlock();

    status = rd32(IGC_STATUS);
    if (status & IGC_STATUS_LU)
        wufc &= ~IGC_WUFC_LNKC;

    if (wufc) {
        igc_setup_rctl(adapter);
        igc_set_rx_mode(netdev);

        /* turn on all-multi mode if wake on multicast is enabled */
        if (wufc & IGC_WUFC_MC) {
            rctl = rd32(IGC_RCTL);
            rctl |= IGC_RCTL_MPE;
            wr32(IGC_RCTL, rctl);
        }

        ctrl = rd32(IGC_CTRL);
        ctrl |= IGC_CTRL_ADVD3WUC;
        wr32(IGC_CTRL, ctrl);

        /* Allow time for pending master requests to run */
        igc_disable_pcie_master(hw);

        wr32(IGC_WUC, IGC_WUC_PME_EN);
        wr32(IGC_WUFC, wufc);
    } else {
        wr32(IGC_WUC, 0);
        wr32(IGC_WUFC, 0);
    }

    wake = wufc || adapter->en_mng_pt;
    if (!wake)
        igc_power_down_phy_copper_base(&adapter->hw);
    else
        igc_power_up_link(adapter);

    if (enable_wake)
        *enable_wake = wake;

    /* Release control of h/w to f/w.  If f/w is AMT enabled, this
     * would have already happened in close and is redundant.
     */
    igc_release_hw_control(adapter);

    pci_disable_device(pdev);

    return 0;
}
#endif

#ifdef CONFIG_PM
static int __maybe_unused igc_runtime_suspend(struct device *dev)
{
    return __igc_shutdown(to_pci_dev(dev), NULL, 1);
}

static void igc_deliver_wake_packet(struct net_device *netdev)
{
    struct igc_adapter *adapter = netdev_priv(netdev);
    struct igc_hw *hw = &adapter->hw;
    struct sk_buff *skb;
    u32 wupl;

    wupl = rd32(IGC_WUPL) & IGC_WUPL_MASK;

    /* WUPM stores only the first 128 bytes of the wake packet.
     * Read the packet only if we have the whole thing.
     */
    if (wupl == 0 || wupl > IGC_WUPM_BYTES)
        return;

    skb = netdev_alloc_skb_ip_align(netdev, IGC_WUPM_BYTES);
    if (!skb)
        return;

    skb_put(skb, wupl);

    /* Ensure reads are 32-bit aligned */
    wupl = roundup(wupl, 4);

    memcpy_fromio(skb->data, hw->hw_addr + IGC_WUPM_REG(0), wupl);

    skb->protocol = eth_type_trans(skb, netdev);
    netif_rx(skb);
}

static int __maybe_unused igc_resume(struct device *dev)
{
    struct pci_dev *pdev = to_pci_dev(dev);
    struct net_device *netdev = pci_get_drvdata(pdev);
    struct igc_adapter *adapter = netdev_priv(netdev);
    struct igc_hw *hw = &adapter->hw;
    u32 err, val;

    pci_set_power_state(pdev, PCI_D0);
    pci_restore_state(pdev);
    pci_save_state(pdev);

    if (!pci_device_is_present(pdev))
        return -ENODEV;
    err = pci_enable_device_mem(pdev);
    if (err) {
        netdev_err(netdev, "Cannot enable PCI device from suspend\n");
        return err;
    }
    pci_set_master(pdev);

    pci_enable_wake(pdev, PCI_D3hot, 0);
    pci_enable_wake(pdev, PCI_D3cold, 0);

    if (igc_init_interrupt_scheme(adapter, true)) {
        netdev_err(netdev, "Unable to allocate memory for queues\n");
        return -ENOMEM;
    }

    igc_reset(adapter);

    /* let the f/w know that the h/w is now under the control of the
     * driver.
     */
    igc_get_hw_control(adapter);

    val = rd32(IGC_WUS);
    if (val & WAKE_PKT_WUS)
        igc_deliver_wake_packet(netdev);

    wr32(IGC_WUS, ~0);

    rtnl_lock();
    if (!err && netif_running(netdev))
        err = __igc_open(netdev, true);

    if (!err)
        netif_device_attach(netdev);
    rtnl_unlock();

    return err;
}

static int __maybe_unused igc_runtime_resume(struct device *dev)
{
    return igc_resume(dev);
}

static int __maybe_unused igc_suspend(struct device *dev)
{
    return __igc_shutdown(to_pci_dev(dev), NULL, 0);
}

static int __maybe_unused igc_runtime_idle(struct device *dev)
{
    struct net_device *netdev = dev_get_drvdata(dev);
    struct igc_adapter *adapter = netdev_priv(netdev);

    if (!igc_has_link(adapter))
        pm_schedule_suspend(dev, MSEC_PER_SEC * 5);

    return -EBUSY;
}
#endif /* CONFIG_PM */
#ifndef __APPLE__
static void igc_shutdown(struct pci_dev *pdev)
{
    bool wake;

    __igc_shutdown(pdev, &wake, 0);

    if (system_state == SYSTEM_POWER_OFF) {
        pci_wake_from_d3(pdev, wake);
        pci_set_power_state(pdev, PCI_D3hot);
    }
}
#endif

/**
 * igc_reinit_queues - return error
 * @adapter: pointer to adapter structure
 */
int igc_reinit_queues(struct igc_adapter *adapter)
{
    struct IOEthernetController *netdev = adapter->netdev;
    int err = 0;

    if (netif_running(netdev))
        igc_close(netdev);

    igc_reset_interrupt_capability(adapter);

    if (igc_init_interrupt_scheme(adapter, true)) {
        netdev_err(netdev, "Unable to allocate memory for queues\n");
        return -ENOMEM;
    }

    if (netif_running(netdev))
        err = igc_open(netdev);

    return err;
}

static void igc_disable_rx_ring_hw(struct igc_ring *ring)
{
    struct igc_hw *hw = &ring->q_vector->adapter->hw;
    u8 idx = ring->reg_idx;
    u32 rxdctl;

    rxdctl = rd32(IGC_RXDCTL(idx));
    rxdctl &= ~IGC_RXDCTL_QUEUE_ENABLE;
    rxdctl |= IGC_RXDCTL_SWFLUSH;
    wr32(IGC_RXDCTL(idx), rxdctl);
}

void igc_disable_rx_ring(struct igc_ring *ring)
{
    igc_disable_rx_ring_hw(ring);
    igc_clean_rx_ring(ring);
}

void igc_enable_rx_ring(struct igc_ring *ring)
{
    struct igc_adapter *adapter = ring->q_vector->adapter;

    igc_configure_rx_ring(adapter, ring);

    //if (ring->xsk_pool)
    //    igc_alloc_rx_buffers_zc(ring, igc_desc_unused(ring));
    //else
        igc_alloc_rx_buffers(ring, igc_desc_unused(ring));
}

static void igc_disable_tx_ring_hw(struct igc_ring *ring)
{
    struct igc_hw *hw = &ring->q_vector->adapter->hw;
    u8 idx = ring->reg_idx;
    u32 txdctl;

    txdctl = rd32(IGC_TXDCTL(idx));
    txdctl &= ~IGC_TXDCTL_QUEUE_ENABLE;
    txdctl |= IGC_TXDCTL_SWFLUSH;
    wr32(IGC_TXDCTL(idx), txdctl);
}

void igc_disable_tx_ring(struct igc_ring *ring)
{
    igc_disable_tx_ring_hw(ring);
    igc_clean_tx_ring(ring);
}

void igc_enable_tx_ring(struct igc_ring *ring)
{
    struct igc_adapter *adapter = ring->q_vector->adapter;

    igc_configure_tx_ring(adapter, ring);
}

static IOMediumType mediumTypeArray[MEDIUM_INDEX_COUNT] = {
    kIOMediumEthernetAuto,
    (kIOMediumEthernet10BaseT | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet10BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionHalfDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl),
    (kIOMediumEthernet2500BaseT | kIOMediumOptionFullDuplex),
    (kIOMediumEthernet2500BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionEEE),
    (kIOMediumEthernet1000BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionEEE),
    (kIOMediumEthernet100BaseTX | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE),
    (kIOMediumEthernet2500BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionEEE),
    (kIOMediumEthernet2500BaseT | kIOMediumOptionFullDuplex | kIOMediumOptionFlowControl | kIOMediumOptionEEE)
};

static UInt32 mediumSpeedArray[MEDIUM_INDEX_COUNT] = {
    0,
    10 * MBit,
    10 * MBit,
    100 * MBit,
    100 * MBit,
    100 * MBit,
    1000 * MBit,
    1000 * MBit,
    2500u * MBit,
    2500u * MBit,
    1000 * MBit,
    1000 * MBit,
    100 * MBit,
    100 * MBit,
    2500u * MBit,
    2500u * MBit,
};

static const struct  {
        UInt16 id;
        const char* name;
} deviceModelNames[] =
{
    { IGC_DEV_ID_I226_V, "I226-V"},
    { IGC_DEV_ID_I226_LM, "I226-LM"},
    { IGC_DEV_ID_I226_IT, "I226-IT"},
    { IGC_DEV_ID_I226_K, "I226-K"},
    { IGC_DEV_ID_I225_V, "I225-V"},
    { IGC_DEV_ID_I225_LM, "I225-LM"},
    { IGC_DEV_ID_I225_I, "I225-I"},
    { IGC_DEV_ID_I225_IT, "I225-IT"},
};

OSDefineMetaClassAndStructors(AppleIGC, IOEthernetController);

bool AppleIGC::init(OSDictionary *properties) {
#ifdef APPLE_OS_LOG
    igc_logger = os_log_create("com.sxx.AppleIGC", "Drivers");
#endif
    if (super::init(properties) == false)
        return false;
    enabledForNetif = false;
    workLoop = NULL;

    pdev = NULL;
    mediumDict = NULL;
    csrPCIAddress = NULL;
    interruptSource = NULL;
    watchdogSource = NULL;
    resetSource = NULL;
    dmaErrSource = NULL;
    
    multicastListCount = 0;

    netif = NULL;
#ifndef __PRIVATE_SPI__
    transmitQueue = NULL;
    stalled = FALSE;
#endif
    preLinkStatus = 0;
    txMbufCursor = NULL;
    bSuspended = FALSE;

    linkUp = FALSE;

    eeeMode = 0;

    _mtu = 1500;
    
    return true;
}

#ifdef APPLE_OS_LOG
os_log_t igc_logger = OS_LOG_DEFAULT;
#endif

void AppleIGC::igc_remove() {
    struct igc_adapter *adapter = &priv_adapter;
    set_bit(__IGC_DOWN, &adapter->state);
    
    igc_release_hw_control(adapter);
    igc_clear_interrupt_scheme(adapter);
    RELEASE(csrPCIAddress);
}

void AppleIGC::free() {
    RELEASE(mediumDict);
    
    super::free();
#ifdef APPLE_OS_LOG
    os_release(igc_logger);
#endif
}

void AppleIGC::stop(IOService *provider) {
    detachInterface(netif);
    RELEASE(netif);
    
    if (workLoop) {
        if (watchdogSource) {
            workLoop->removeEventSource(watchdogSource);
            RELEASE(watchdogSource);
        }
        if (resetSource) {
            workLoop->removeEventSource(resetSource);
            RELEASE(resetSource);
        }
        if (dmaErrSource) {
            workLoop->removeEventSource(dmaErrSource);
            RELEASE(dmaErrSource);
        }
        
        if (interruptSource) {
            workLoop->removeEventSource(interruptSource);
            RELEASE(interruptSource);
        }
        RELEASE(workLoop);
    }
    igc_remove();
    
    RELEASE(pdev);
    enabledForNetif = false;
    super::stop(provider);
}

bool AppleIGC::igc_probe() {
    bool success = false;
    struct igc_adapter *adapter = &priv_adapter;
    struct igc_hw *hw = &adapter->hw;
    const struct igc_info *ei = igc_info_tbl[board_base];
    
    int err;
    
    csrPCIAddress = pdev->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
    if (csrPCIAddress == NULL) {
        return false;
    }
    {
        UInt16    reg16;
        reg16    = pdev->configRead16( kIOPCIConfigCommand );
        reg16  &= ~kIOPCICommandIOSpace;
        reg16    |= ( kIOPCICommandBusMaster
                    |    kIOPCICommandMemorySpace);
        
        pdev->configWrite16( kIOPCIConfigCommand, reg16 );
        
        // pdev->setMemoryEnable(true);
    }
    
    adapter->netdev = this;
    adapter->pdev = pdev;
    
    hw->back = adapter;
    adapter->port_num = hw->bus.func;
    
    adapter->io_addr = (u8*)(csrPCIAddress->getVirtualAddress());
    /* hw->hw_addr can be zeroed, so use adapter->io_addr for unmap */
    hw->hw_addr = adapter->io_addr;

    /* Copy the default MAC and PHY function pointers */
    memcpy(&hw->mac.ops, ei->mac_ops, sizeof(hw->mac.ops));
    memcpy(&hw->phy.ops, ei->phy_ops, sizeof(hw->phy.ops));
    
    hw->vendor_id = pdev->configRead16(kIOPCIConfigVendorID);
    hw->device_id = pdev->configRead16(kIOPCIConfigDeviceID);
    
    hw->subsystem_vendor_id = pdev->configRead16(kIOPCIConfigSubSystemVendorID);
    hw->subsystem_device_id = pdev->configRead16(kIOPCIConfigSubSystemID);

    hw->revision_id = pdev->configRead8(kIOPCIConfigRevisionID);

    hw->bus.pci_cmd_word = pdev->configRead16(kIOPCIConfigCommand);
    
    err = ei->get_invariants(hw);
    if (err) {
        pr_err("failed to get invariants\n");
        goto err_sw_init;
    }
    
    //adapter->bd_number = OSIncrementAtomic8(&cards_found);
    
    _features |= NETIF_F_SG |
    NETIF_F_IP_CSUM |
#ifdef NETIF_F_IPV6_CSUM
    NETIF_F_IPV6_CSUM |
#endif
#ifdef NETIF_F_RXHASH
    NETIF_F_RXHASH |
#endif
#ifdef HAVE_NDO_SET_FEATURES
    NETIF_F_RXCSUM |
#endif
#ifdef NETIF_F_HW_VLAN_CTAG_RX
    NETIF_F_HW_VLAN_CTAG_RX |
    NETIF_F_HW_VLAN_CTAG_TX;
#else
    NETIF_F_HW_VLAN_RX |
    NETIF_F_HW_VLAN_TX;
#endif
    
    _features |= NETIF_F_SCTP_CSUM;
    
#ifdef HAVE_NDO_SET_FEATURES
    /* copy netdev features into list of user selectable features */
    netdev->hw_features |= _features;
#else
#ifdef NETIF_F_GRO
    
    /* this is only needed on kernels prior to 2.6.39 */
    _features |= NETIF_F_GRO;
#endif
#endif
    /* set this bit last since it cannot be part of hw_features */
#ifdef NETIF_F_HW_VLAN_CTAG_FILTER
    _features |= NETIF_F_HW_VLAN_CTAG_FILTER;
#else
    _features |= NETIF_F_HW_VLAN_FILTER;
#endif
    /* setup the private structure */
    err = igc_sw_init(adapter);
    if (err) {
        pr_err("failed to sw init\n");
        goto err_sw_init;
    }
    
    if (igc_check_reset_block(hw))
        pr_err("PHY reset is blocked due to SOL/IDER session.\n");
    adapter->en_mng_pt = igc_enable_mng_pass_thru(hw);
    
    /* before reading the NVM, reset the controller to put the device in a
     * known good starting state
     */
    hw->mac.ops.reset_hw(hw);
    
    if (igc_get_flash_presence_i225(hw)) {
        if (hw->nvm.ops.validate(hw) < 0) {
            //dev_err(&pdev->dev, "The NVM Checksum Is Not Valid\n");
            pr_err("The NVM Checksum Is Not Valid\n");
            err = -EIO;
            goto err_eeprom;
        }
    }
    
    if (igc_read_mac_addr(hw))
        pr_err("NVM Read Error\n");
    
    if (!is_valid_ether_addr(hw->mac.addr)) {
        pr_err("Invalid MAC Address\n");
        err = -EIO;
        goto err_eeprom;
    }
    
    //memcpy(mac_table, hw->mac.addr, ETH_ALEN);
    igc_rar_set(hw, hw->mac.addr, 0);
    
    /* configure RXPBSIZE and TXPBSIZE */
    wr32(IGC_RXPBS, I225_RXPBSIZE_DEFAULT);
    wr32(IGC_TXPBS, I225_TXPBSIZE_DEFAULT);

    adapter->watchdog_task = watchdogSource;
    adapter->dma_err_task = dmaErrSource;
    adapter->reset_task = resetSource;
    
    /* Initialize link properties that are user-changeable */
    adapter->fc_autoneg = true;
    hw->mac.autoneg = true;
    hw->phy.autoneg_advertised = 0xaf;
    
    hw->fc.requested_mode = igc_fc_default;
    hw->fc.current_mode = igc_fc_default;

    /* By default, support wake on port A */
    adapter->flags |= IGC_FLAG_WOL_SUPPORTED;

    /* initialize the wol settings based on the eeprom settings */
    if (adapter->flags & IGC_FLAG_WOL_SUPPORTED)
        adapter->wol |= IGC_WUFC_MAG;

    //device_set_wakeup_enable(&adapter->pdev->dev,
    //             adapter->flags & IGC_FLAG_WOL_SUPPORTED);
    igc_reset(adapter);
    igc_get_hw_control(adapter);
    
    /* carrier off reporting is important to ethtool even BEFORE open */
    netif_carrier_off(this);
    /* Check if Media Autosense is enabled */
    adapter->ei = *ei;
    
    hw->dev_spec._base.eee_enable = false;
    adapter->flags &= ~IGC_FLAG_EEE;
    igc_set_eee_i225(hw, false, false, false);
    return true;
err_eeprom:
    if (!igc_check_reset_block(hw))
        igc_reset_phy(hw);
err_sw_init:
    //kfree(adapter->shadow_vfta,sizeof(u32) * E1000_VFTA_ENTRIES);
    igc_clear_interrupt_scheme(adapter);
    RELEASE(csrPCIAddress);    // iounmap(hw->io_addr);
    
    return success;
}

bool AppleIGC::getBoolOption(const char *name, bool defVal)
{
    OSBoolean* rc = OSDynamicCast( OSBoolean, getProperty(name));
    if( rc != NULL ){
        return (rc == kOSBooleanTrue );
    }
    return defVal;
}
    
int AppleIGC::getIntOption(const char *name, int defVal, int maxVal, int minVal )
{
    int val = defVal;
    OSNumber* numObj = OSDynamicCast( OSNumber, getProperty(name) );
    if ( numObj != NULL ){
        val = (int)numObj->unsigned32BitValue();
        if( val < minVal )
            val = minVal;
        else if(val > maxVal )
            val = maxVal;
    }
    return val;
}

bool AppleIGC::start(IOService *provider) {
    u32 i;

//    #ifdef APPLE_OS_LOG
//    igc_logger = os_log_create("com.sxx.AppleIGC", "Drivers");
//    #endif

    pr_err("start()\n");
    
    if (super::start(provider) == false) {
        return false;
    }

    pdev = OSDynamicCast(IOPCIDevice, provider);
    if (pdev == NULL)
        return false;
    
    pdev->retain();
    if (pdev->open(this) == false)
        return false;

#ifdef NETIF_F_TSO
    useTSO = getBoolOption("NETIF_F_TSO", TRUE);
#else
    useTSO = FALSE;
#endif

    /** igc_probe requires watchdog to be intialized*/
    if(!initEventSources(provider)) {
        pr_err("Failed to initEventSources()\n");
        return false;
    }

    if(!igc_probe()) {
        pr_err("Failed to igc_probe()\n");
        return false;
    }

    if (!setupMediumDict()) {
        pr_err("Failed to setupMediumDict\n");
        return false;
    }

    chip_idx = 0;
    for( i = 0; i < sizeof(deviceModelNames)/sizeof(deviceModelNames[0]); i++){
        if(priv_adapter.hw.device_id == deviceModelNames[i].id )
            chip_idx = i;
    }

    // Close our provider, it will be re-opened on demand when
    // our enable() is called by a client.
    pdev->close(this);
    
    // Allocate and attach an IOEthernetInterface instance.
    if (attachInterface((IONetworkInterface**)&netif) == false) {
        pr_err("attachInterface() failed \n");
        return false;
    }
    
    netif->registerService();

    return true;
}

IOReturn AppleIGC::enable(IONetworkInterface *netif) {
    const IONetworkMedium *selectedMedium;
    struct igc_hw *hw = &priv_adapter.hw;
    int ret_val;
    
    if (!enabledForNetif) {
        pdev->open(this);
        
        selectedMedium = getSelectedMedium();
        
        if (!selectedMedium) {
            selectedMedium = mediumTable[MEDIUM_INDEX_AUTO];
            setSelectedMedium(selectedMedium);
        }
        
        setCarrier(false);

        intelSetupAdvForMedium(selectedMedium);

        ret_val = igc_open(this);
        if (ret_val) {
            pr_err("igc_open failed %d\n", ret_val);
            return kIOReturnIOError;
        }

/*
        // hack to accept any VLAN
        for(u16 k = 1; k < 4096; k++){
            igc_vlan_rx_add_vid(this,k);
        }
 */

        interruptSource->enable();
        setTimers(true);
#ifndef __PRIVATE_SPI__
        if (!transmitQueue->setCapacity(IGC_DEFAULT_TXD)) {
            pr_err("Failed to set tx queue capacity %u\n", IGC_DEFAULT_TXD);
        }
#endif


        if (!carrier()) {
            setCarrier(intelCheckLink(&priv_adapter)); // setValidLinkStatus(Active)
        }
#ifndef __PRIVATE_SPI__
        stalled = FALSE;
#endif
        eeeMode = 0;
        hw->mac.get_link_status = true;
        enabledForNetif = true;
    } else {
        pr_err("enable() on not disabled interface\n");
    }
    
    return kIOReturnSuccess;
}

IOReturn AppleIGC::disable(IONetworkInterface *netif) {
    if (enabledForNetif) {
        enabledForNetif = false;
#ifndef __PRIVATE_SPI__
        stopTxQueue();
        transmitQueue->setCapacity(0);
#else
        stopTxQueue();
        RELEASE(txMbufCursor);
#endif
        watchdogSource->cancelTimeout();
        interruptSource->disable();
        setTimers(false);

        igc_close(this);

        igc_irq_disable(&priv_adapter);

        eeeMode = 0;
#ifndef __PRIVATE_SPI__
        stalled = FALSE;
#endif

        if (carrier()) {
            setCarrier(false);
            pr_debug("Link down on en%u\n", netif->getUnitNumber());
        }

        if (pdev && pdev->isOpen())
            pdev->close(this);
    } else {
        pr_err("disable() on not enabled interface\n");
    }

    pr_debug("disable() <===\n");
    
    return kIOReturnSuccess;
}

static const char *speed25GName = "2.5-Gigabit";
static const char *speed1GName = "1-Gigabit";
static const char *speed100MName = "100-Megabit";
static const char *speed10MName = "10-Megabit";
static const char *duplexFullName = "Full-duplex";
static const char *duplexHalfName = "Half-duplex";


static const char *flowControlNames[kFlowControlTypeCount] = {
    "No flow-control",
    "Rx flow-control",
    "Tx flow-control",
    "Rx/Tx flow-control",
};

static const char* eeeNames[kEEETypeCount] = {
    "",
    ", energy-efficient-ethernet"
};

int AppleIGC::currentMediumIndex() {
    UInt32 fcIndex;
    
    struct igc_adapter *adapter = &priv_adapter;
    struct igc_hw *hw = &adapter->hw;
    
    UInt32 ctrl = igc_rd32(hw, IGC_CTRL) & (IGC_CTRL_RFCE | IGC_CTRL_TFCE);

    switch (ctrl) {
        case (IGC_CTRL_RFCE | IGC_CTRL_TFCE):
            fcIndex = kFlowControlTypeRxTx;
            break;
        case IGC_CTRL_RFCE:
            fcIndex = kFlowControlTypeRx;
            break;
        case IGC_CTRL_TFCE:
            fcIndex = kFlowControlTypeTx;
            break;
        default:
            fcIndex = kFlowControlTypeNone;
            break;
    }
    
    if (priv_adapter.link_speed == SPEED_2500) {
        if (fcIndex == kFlowControlTypeNone) {
            if (eeeMode) {
                return MEDIUM_INDEX_2500FDEEE;
            } else {
                return MEDIUM_INDEX_2500FD;
            }
        } else {
            if (eeeMode) {
                return MEDIUM_INDEX_2500FDFCEEE;
            } else {
                return MEDIUM_INDEX_2500FDFC;
            }
        }
    } else if (priv_adapter.link_speed == SPEED_1000) {
        if (fcIndex == kFlowControlTypeNone) {
            if (eeeMode) {
                return MEDIUM_INDEX_1000FDEEE;
            } else {
                return MEDIUM_INDEX_1000FD;
            }
        } else {
            if (eeeMode) {
                return MEDIUM_INDEX_1000FDFCEEE;
            } else {
                return MEDIUM_INDEX_1000FDFC;
            }
        }

    } else if (priv_adapter.link_speed == SPEED_100) {
       if (priv_adapter.link_duplex != DUPLEX_FULL) {
           if (fcIndex == kFlowControlTypeNone) {
               if (eeeMode) {
                   return MEDIUM_INDEX_100FDEEE;
               } else {
                   return MEDIUM_INDEX_100FD;
               }
           } else {
               if (eeeMode) {
                   return MEDIUM_INDEX_100FDFCEEE;
               } else {
                   return MEDIUM_INDEX_100FDFC;
               }
           }
       } else {
            return MEDIUM_INDEX_100HD;
       }
    } else if (priv_adapter.link_speed == SPEED_10) {
        if (priv_adapter.link_duplex != DUPLEX_FULL) {
            return MEDIUM_INDEX_10FD;
        } else {
            return MEDIUM_INDEX_10HD;
        }
    } else {
        return MEDIUM_INDEX_AUTO;
   }
}


void AppleIGC::setLinkUp() {
    struct igc_hw *hw = &priv_adapter.hw;
    struct igc_phy_info *phy = &hw->phy;
    struct igc_adapter *adapter = &priv_adapter;
    const char *flowName;
    const char *speedName;
    const char *duplexName;
    const char *eeeName;
    UInt64 mediumSpeed;
    UInt32 mediumIndex = MEDIUM_INDEX_AUTO;
    UInt32 fcIndex;
    UInt32 ctrl;

    pr_debug("setLinkUp() ===>\n");

    eeeMode = 0;
    eeeName = eeeNames[kEEETypeNo];

    igc_get_phy_info(hw);

    igc_check_downshift(hw);
    if (phy->speed_downgraded)
        pr_debug("Link Speed was downgraded by SmartSpeed\n");

    hw->mac.ops.get_speed_and_duplex(hw, &adapter->link_speed, &adapter->link_duplex);

    /* Get link speed, duplex and flow-control mode. */
    ctrl = igc_rd32(hw, IGC_CTRL) & (IGC_CTRL_RFCE | IGC_CTRL_TFCE);

    switch (ctrl) {
        case (IGC_CTRL_RFCE | IGC_CTRL_TFCE):
            fcIndex = kFlowControlTypeRxTx;
            break;
        case IGC_CTRL_RFCE:
            fcIndex = kFlowControlTypeRx;
            break;
        case IGC_CTRL_TFCE:
            fcIndex = kFlowControlTypeTx;
            break;
        default:
            fcIndex = kFlowControlTypeNone;
            break;
    }

    flowName = flowControlNames[fcIndex];

    if (priv_adapter.link_speed == SPEED_2500) {
        mediumSpeed = kSpeed2500MBit;
        speedName = speed25GName;
        duplexName = duplexFullName;

        eeeMode = intelSupportsEEE(adapter);

        if (fcIndex == kFlowControlTypeNone) {
            if (eeeMode) {
                mediumIndex = MEDIUM_INDEX_2500FDEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_2500FD;
            }
        } else {
            if (eeeMode) {
                mediumIndex = MEDIUM_INDEX_2500FDFCEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_2500FDFC;
            }
        }
    } else if (priv_adapter.link_speed == SPEED_1000) {
        mediumSpeed = kSpeed1000MBit;
        speedName = speed1GName;
        duplexName = duplexFullName;

        eeeMode = intelSupportsEEE(adapter);

        if (fcIndex == kFlowControlTypeNone) {
            if (eeeMode) {
                mediumIndex = MEDIUM_INDEX_1000FDEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_1000FD;
            }
        } else {
            if (eeeMode) {
                mediumIndex = MEDIUM_INDEX_1000FDFCEEE;
                eeeName = eeeNames[kEEETypeYes];
            } else {
                mediumIndex = MEDIUM_INDEX_1000FDFC;
            }
        }

    } else if (priv_adapter.link_speed == SPEED_100) {
       mediumSpeed = kSpeed100MBit;
       speedName = speed100MName;

       if (priv_adapter.link_duplex != DUPLEX_FULL) {
           duplexName = duplexFullName;

           eeeMode = intelSupportsEEE(adapter);

           if (fcIndex == kFlowControlTypeNone) {
               if (eeeMode) {
                   mediumIndex = MEDIUM_INDEX_100FDEEE;
                   eeeName = eeeNames[kEEETypeYes];
               } else {
                   mediumIndex = MEDIUM_INDEX_100FD;
               }
           } else {
               if (eeeMode) {
                   mediumIndex = MEDIUM_INDEX_100FDFCEEE;
                   eeeName = eeeNames[kEEETypeYes];
               } else {
                   mediumIndex = MEDIUM_INDEX_100FDFC;
               }
           }
       } else {
                mediumIndex = MEDIUM_INDEX_100HD;
                duplexName = duplexHalfName;
       }
   } else {
       mediumSpeed = kSpeed10MBit;
       speedName = speed10MName;

       if (priv_adapter.link_duplex != DUPLEX_FULL) {
           mediumIndex = MEDIUM_INDEX_10FD;
           duplexName = duplexFullName;
       } else {
           mediumIndex = MEDIUM_INDEX_10HD;
           duplexName = duplexHalfName;
       }
   }

    /* adjust timeout factor according to speed/duplex */
    adapter->tx_timeout_factor = 1;
    switch (adapter->link_speed) {
    case SPEED_10:
        adapter->tx_timeout_factor = 14;
        break;
    case SPEED_100:
        /* maybe add some timeout factor ? */
        break;
    default:
        break;
    }

    while (test_and_set_bit(__IGC_RESETTING, &adapter->state))
        usleep_range(1000, 2000);

    if (!carrier()) {
        setCarrier(true);
    }

    igc_up(adapter);

    clear_bit(__IGC_RESETTING, &adapter->state);

    linkUp = true;
    
#ifndef __PRIVATE_SPI__
    if (stalled) {
        transmitQueue->service();
        stalled = false;
        pr_debug("Restart stalled queue!\n");
    }
#else
    netif->startOutputThread();
#endif

    interruptSource->enable();
    setTimers(true);

    pr_debug("[LU]: Link Up on en%u (%s), %s, %s, %s%s (igc driver ver %08x)\n",
             netif->getUnitNumber(), deviceModelNames[chip_idx].name,
             speedName, duplexName, flowName, eeeName, 0);
    pr_debug("setLinkUp() <===\n");
}

void AppleIGC::systemWillShutdown(IOOptionBits specifier)
{
    pr_debug("systemWillShutdown() ===>\n");

    if ((kIOMessageSystemWillPowerOff | kIOMessageSystemWillRestart) & specifier) {
        disable(netif);

        /* Restore the original MAC address. */
        priv_adapter.hw.mac.ops.rar_set(&priv_adapter.hw, priv_adapter.hw.mac.perm_addr, 0);

                /*
                 * Let the firmware know that the network interface is now closed
                 */
        igc_release_hw_control(&priv_adapter);
    }

    pr_debug("systemWillShutdown() <===\n");

    /* Must call super on shutdown or system will stall. */
    super::systemWillShutdown(specifier);
}

/** This method doesn't completely shutdown NIC. It intentionally keeps eventSources
 * and enables interruptes back
 */
void AppleIGC::setLinkDown()
{
    struct igc_hw *hw = &priv_adapter.hw;
    struct igc_adapter *adapter = &priv_adapter;

    pr_debug("setLinkDown() ===>\n");
    
    netif->stopOutputThread();
    netif->flushOutputQueue();

    linkUp = false;
    /** igb_down also performs setLinkStatus(Valid) via netif_carrier_off */
    igc_down(adapter);

    clear_bit(__IGC_DOWN, &adapter->state);

    /* Clear any pending interrupts. */
    igc_rd32(hw, IGC_ICR);
    igc_irq_enable(adapter);

    pr_debug("Link down on en%u\n", netif->getUnitNumber());
    pr_debug("setLinkDown() <===\n");
}

#ifdef __PRIVATE_SPI__
IOReturn AppleIGC::outputStart(IONetworkInterface *interface, IOOptionBits options)
{
    struct igc_adapter *adapter = &priv_adapter;
    struct igc_ring *tx_ring = igc_tx_queue_mapping(adapter, skb);
    mbuf_t skb = NULL;
    while ((txNumFreeDesc = igc_desc_unused(tx_ring)) >= (MAX_SKB_FRAGS + 3) && kIOReturnSuccess == interface->dequeueOutputPackets(1, &skb, NULL, NULL, NULL)) {
        int tso = 0;
        u32 tx_flags = 0;
        u8 hdr_len = 0;
        
        struct IOPhysicalSegment vec[MAX_SKB_FRAGS];
        UInt32 frags = txMbufCursor->getPhysicalSegmentsWithCoalesce(skb, vec, MAX_SKB_FRAGS);
        if(frags == 0) {
            pr_debug("No frags by getPhysicalSegmentsWithCoalesce()\n");
            break;
        }
        
        UInt32 count = 0;
        for (UInt32 k = 0; k < frags; k++){
            count += (vec[k].length + (IGC_MAX_DATA_PER_TXD-1))/IGC_MAX_DATA_PER_TXD;
        }
        
        u16 next_to_use = tx_ring->next_to_use;
        struct igc_tx_buffer *first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
        first->skb = skb;
        first->bytecount = (u32)mbuf_pkthdr_len(skb);
        first->gso_segs = 1;
        
        UInt32 vlan;
        if(getVlanTagDemand(skb, &vlan)){
            pr_debug("vlan(out) = %d\n",(int)vlan);
            tx_flags |= IGC_TX_FLAGS_VLAN;
            tx_flags |= (vlan << IGC_TX_FLAGS_VLAN_SHIFT);
        }
        
        /* record initial flags and protocol */
        first->tx_flags = tx_flags;

        if(useTSO) {
            tso = igc_tso(tx_ring, first, 0, false, &hdr_len);
        }
        if (unlikely(tso < 0)){
            pr_debug("tso failed, impossible\n");
            igc_unmap_and_free_tx_resource(tx_ring, first);
            break;
        } else if (!tso) {
            if (useTSO) {
                tx_ring->next_to_use = next_to_use;
            }
            igc_tx_csum(tx_ring, first, 0, false);
        }
        if(!igc_tx_map(tx_ring, first, hdr_len, vec, frags)){
            netStats->outputErrors += 1;
            pr_debug("output: igb_tx_map failed (%u)\n", netStats->outputErrors);
            first->skb = NULL;
            break;
        }
    }
    if ((txNumFreeDesc = igc_desc_unused(tx_ring)) >= (MAX_SKB_FRAGS + 3)) {
        return kIOReturnSuccess;
    } else {
        return kIOReturnNoResources;
    }
}
#endif

#ifndef __PRIVATE_SPI__
// corresponds to igc_xmit_frame
UInt32 AppleIGC::outputPacket(mbuf_t skb, void * param)
{
    struct igc_adapter *adapter = &priv_adapter;
    UInt32 result = kIOReturnOutputDropped;
    if (unlikely(!(enabledForNetif && linkUp) || !txMbufCursor
            || test_bit(__IGC_DOWN, &adapter->state))) {
        pr_debug("output: Dropping packet on disabled device\n");
        goto error;
    }
    /*
     * The minimum packet size with TCTL.PSP set is 17 so pad the skb
     * in order to meet this minimum size requirement.
     */
    // not applied to Mac OS X
    // igb_xmit_frame_ring is inlined here
    do {
        struct igc_ring *tx_ring = igc_tx_queue_mapping(adapter, skb);
        struct igc_tx_buffer *first;
        int tso = 0;
        u32 tx_flags = 0;
        u8 hdr_len = 0;
        
        struct IOPhysicalSegment vec[MAX_SKB_FRAGS];
        UInt32 frags = tx_ring->netdev->txCursor()->getPhysicalSegmentsWithCoalesce(skb, vec, MAX_SKB_FRAGS);
        if(frags == 0) {
            pr_debug("No frags by getPhysicalSegmentsWithCoalesce()\n");
            goto error;
        }
        
        UInt32 count = 0;
        for (UInt32 k = 0; k < frags; k++){
            count += (vec[k].length + (IGC_MAX_DATA_PER_TXD-1))/IGC_MAX_DATA_PER_TXD;
        }

        /* need: 1 descriptor per page,
         *       + 2 desc gap to keep tail from touching head,
         *       + 1 desc for skb->data,
         *       + 1 desc for context descriptor,
         * otherwise try next time */
        txNumFreeDesc = igc_desc_unused(tx_ring);

        if (txNumFreeDesc < count + 2 + 3 //igc_maybe_stop_tx
            || stalled) /** even if we have free desc we should exit in stalled mode as queue is enabled by threadsafe interrupts -> native igc code (see igb_poll) */
        {
            /* this is a hard error */
            netStats->outputErrors += 1;
#ifdef DEBUG
            if (netStats->outputErrors % 100 == 0)
                pr_debug("output: Dropping packets\n");
#endif
            result = kIOReturnOutputStall;
            stalled = true;
            goto done;
        }

        /* record the location of the first descriptor for this packet */
        u16 next_to_use = tx_ring->next_to_use;
        first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
        first->skb = skb;
        first->bytecount = (u32)mbuf_pkthdr_len(skb);
        first->gso_segs = 1;
        
        UInt32 vlan;
        if(getVlanTagDemand(skb,&vlan)){
            pr_debug("vlan(out) = %d\n",(int)vlan);
            tx_flags |= IGC_TX_FLAGS_VLAN;
            tx_flags |= (vlan << IGC_TX_FLAGS_VLAN_SHIFT);
        }
        
        /* record initial flags and protocol */
        first->tx_flags = tx_flags;

        if(useTSO) {
            tso = igc_tso(tx_ring, first, 0, false, &hdr_len);
        }
        if (unlikely(tso < 0)){
            pr_debug("tso failed, impossible\n");
            igc_unmap_and_free_tx_resource(tx_ring, first);
            break;
        } else if (!tso) {
            if (useTSO) {
                tx_ring->next_to_use = next_to_use;
            }
            igc_tx_csum(tx_ring, first, 0, false);
        }
        if(!igc_tx_map(tx_ring, first, hdr_len, vec, frags)){
            netStats->outputErrors += 1;
            pr_debug("output: igb_tx_map failed (%u)\n", netStats->outputErrors);
            first->skb = NULL;
            result = kIOReturnOutputDropped;
            goto error;
        }

        /* Make sure there is space in the ring for the next send. */
        //igc_maybe_stop_tx(tx_ring, MAX_SKB_FRAGS + 4);
    } while(false);

    result = kIOReturnOutputSuccess;

done:
    //pr_debug("[IntelMausi]: outputPacket() <=== %d\n", result);
    return result;

error:
    freePacket(skb);
    goto done;
}
#endif

void AppleIGC::getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const
{
    constraints->alignStart = kIOPacketBufferAlign2;
    constraints->alignLength = kIOPacketBufferAlign1;
    return;
}
#ifndef __PRIVATE_SPI__
IOOutputQueue * AppleIGC::createOutputQueue()
{
    return IOGatedOutputQueue::withTarget(this, getWorkLoop());
}
#endif

const OSString * AppleIGC::newVendorString() const
{
    return OSString::withCString("Intel");
}

const OSString * AppleIGC::newModelString() const
{
    if (chip_idx)
        return OSString::withCString(deviceModelNames[chip_idx].name);

    return OSString::withCString("Unknown");
}

/**
* intelSupportsEEE
*/
UInt16 AppleIGC::intelSupportsEEE(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;

    UInt16 result = 0;

    if (hw->phy.media_type != igc_media_type_copper)
        goto done;

    if (!hw->dev_spec._base.eee_enable)
        goto done;
    result |= IGC_IPCNFG_EEE_2_5G_AN | IGC_IPCNFG_EEE_1G_AN | IGC_IPCNFG_EEE_100M_AN;

    return result;

done:
    return result;
}

/**
* intelSetupAdvForMedium @IntelMausi
*/
void AppleIGC::intelSetupAdvForMedium(const IONetworkMedium *medium)
{
        struct igc_adapter *adapter = &priv_adapter;
        struct igc_hw *hw = &adapter->hw;

        pr_debug("intelSetupAdvForMedium(index %u, type %u) ===>\n", medium->getIndex(), type);

        hw->mac.autoneg = 0;

        if (intelSupportsEEE(adapter))
            hw->dev_spec._base.eee_enable = false;

        switch (medium->getIndex()) {
                /*
            case MEDIUM_INDEX_10HD:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_10FD:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_100HD:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_100FD:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_100FDFC:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_full;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_1000FD:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_1000FDFC:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_full;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_1000FDEEE:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = true;
                break;

            case MEDIUM_INDEX_1000FDFCEEE:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_full;
                hw->dev_spec._base.eee_enable = true;
                break;

            case MEDIUM_INDEX_100FDEEE:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = true;
                break;

            case MEDIUM_INDEX_100FDFCEEE:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_full;
                hw->dev_spec._base.eee_enable = true;
                break;
            case MEDIUM_INDEX_2500FD:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = false;
                break;
            case MEDIUM_INDEX_2500FDFC:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_full;
                hw->dev_spec._base.eee_enable = false;
                break;

            case MEDIUM_INDEX_2500FDEEE:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_none;
                hw->dev_spec._base.eee_enable = true;
                break;

            case MEDIUM_INDEX_2500FDFCEEE:
                hw->mac.autoneg = 0;
                hw->fc.requested_mode = igc_fc_full;
                hw->dev_spec._base.eee_enable = true;
                break;
                */
            default:
                pr_err("Force mode currently not supported\n");
            case MEDIUM_INDEX_AUTO:
                if (adapter->fc_autoneg)
                        hw->fc.requested_mode = igc_fc_default;

                if (intelSupportsEEE(adapter))
                    hw->dev_spec._base.eee_enable = true;

                hw->mac.autoneg = 1;
                break;
        }
        /* clear MDI, MDI(-X) override is only allowed when autoneg enabled */
        hw->phy.mdix = AUTO_ALL_MODES;

        pr_debug("intelSetupAdvForMedium() <===\n");
}

void AppleIGC::intelRestart() {
        struct igc_adapter *adapter = &priv_adapter;

        pr_debug("intelRestart ===> on en%u, linkUp=%u, carrier=%u\n",
                 netif->getUnitNumber(), linkUp, carrier());

        linkUp = false;
        eeeMode = 0;

        while (test_and_set_bit(__IGC_RESETTING, &adapter->state))
            usleep_range(1000, 2000);

        if (netif_running(this)) {
            /**
             * igb_down and igb_up do everything IntelMausi performs in its version:
             *  - netif_carrier_off = setLinkStatus(valid)
             *  - stop transmit queues
             *  - disable IRQ
             *  - reset HW
             *  - configure
             *  - enable IRQ
             *  - start transmit queues
             * So no obvious reason to avoid reusing as is.
             */
            pr_debug("igc_down...\n");
            igc_down(adapter);
            pr_debug("igc_up...\n");
            igc_up(adapter);
        } else {
            pr_debug("igc_reset...\n");
            igc_reset(adapter);
        }

        clear_bit(__IGC_RESETTING, &adapter->state);
        pr_debug("intelRestart <===\n");
}

IOReturn AppleIGC::selectMedium(const IONetworkMedium * medium)
{
    // force mode is not supported
    return kIOReturnUnsupported;
    pr_err("selectMedium()===>\n");

    if (medium) {
        intelSetupAdvForMedium(medium);
        setCurrentMedium(medium);

        igc_update_stats(&priv_adapter);

        intelRestart();
    } else {
        pr_err("Unexpected medium, ignoring.\n");
    }
    pr_err("<===selectMedium()\n");
    return kIOReturnSuccess;
}

bool AppleIGC::createWorkLoop()
{
    if ((vm_address_t) workLoop >> 1)
     return true;

    if (OSCompareAndSwap(0, 1, (UInt32 *) &workLoop)) {
        // Construct the workloop and set the cntrlSync variable
        // to whatever the result is and return
        workLoop = IOWorkLoop::workLoop();
    } else while ((IOWorkLoop *) workLoop == (IOWorkLoop *) 1)
        // Spin around the cntrlSync variable until the
        // initialization finishes.
        thread_block(0);
    return workLoop != NULL;
}

IOWorkLoop * AppleIGC::getWorkLoop() const
{
   return workLoop;
}


//-----------------------------------------------------------------------
// Methods inherited from IOEthernetController.
//-----------------------------------------------------------------------

IOReturn AppleIGC::getHardwareAddress(IOEthernetAddress * addr)
{
    memcpy(addr->bytes, priv_adapter.hw.mac.addr, kIOEthernetAddressSize);
    return kIOReturnSuccess;
}

// corresponds to igc_set_mac
IOReturn AppleIGC::setHardwareAddress(const IOEthernetAddress * addr)
{
    igc_adapter *adapter = &priv_adapter;
    struct igc_hw *hw = &adapter->hw;

    //igc_del_mac_filter(adapter, hw->mac.addr,
    //                   adapter->vfs_allocated_count);
    memcpy(hw->mac.addr, addr->bytes, kIOEthernetAddressSize);
    
    /* set the correct pool for the new PF MAC address in entry 0 */
    //igc_add_mac_filter(adapter, hw->mac.addr,
    //                          adapter->vfs_allocated_count);
    
    return kIOReturnSuccess;
}

IOReturn AppleIGC::setPromiscuousMode(bool active)
{
    if(active)
        iff_flags |= IFF_PROMISC;
    else
        iff_flags &= ~IFF_PROMISC;

    igc_set_rx_mode(this);
    return kIOReturnSuccess;
}

IOReturn AppleIGC::setMulticastMode(bool active)
{
    if(active)
        iff_flags |= IFF_ALLMULTI;
    else
        iff_flags &= ~IFF_ALLMULTI;
    
    igc_set_rx_mode(this);
    return kIOReturnSuccess;
}

// corresponds to igc_write_mc_addr_list
IOReturn AppleIGC::setMulticastList(IOEthernetAddress * addrs, UInt32 count)
{
    igc_adapter *adapter = &priv_adapter;
    struct igc_hw *hw = &adapter->hw;

    if (!count) {
        this->multicastListCount = 0;
        igc_update_mc_addr_list(hw, NULL, 0);
        return 0;
    }
    
    this->multicastListCount = count;
    /* The shared function expects a packed array of only addresses. */
    igc_update_mc_addr_list(hw, (u8*)addrs, count);
    
    return kIOReturnSuccess;
}

IOReturn AppleIGC::getChecksumSupport(UInt32 *checksumMask, UInt32 checksumFamily, bool isOutput)
{
    *checksumMask = 0;
    if( checksumFamily != kChecksumFamilyTCPIP ) {
        pr_err("AppleIGC: Operating system wants information for unknown checksum family.\n");
        return kIOReturnUnsupported;
    }
    if( !isOutput ) {
        *checksumMask = kChecksumTCP | kChecksumUDP | kChecksumIP | CSUM_TCPIPv6 | CSUM_UDPIPv6;
    } else {
#if USE_HW_UDPCSUM
        *checksumMask = kChecksumTCP | kChecksumUDP | CSUM_TCPIPv6 | CSUM_UDPIPv6;
#else
        *checksumMask = kChecksumTCP | CSUM_TCPIPv6;
#endif
    }
    return kIOReturnSuccess;
}

/**
* intelCheckLink
* It's not exact copy of igc_has_link, additional check for E1000_STATUS_LU (Link up)
* is performed
* Reference: igc_has_link
*/
bool AppleIGC::intelCheckLink(struct igc_adapter *adapter)
{
    struct igc_hw *hw = &adapter->hw;
    bool link_active = FALSE;
    
    if (!hw->mac.get_link_status)
        return true;
    hw->mac.ops.check_for_link(hw);
    link_active = !hw->mac.get_link_status;

    if (hw->mac.type == igc_i225) {
        if (!netif_carrier_ok(adapter->netdev)) {
            adapter->flags &= ~IGC_FLAG_NEED_LINK_UPDATE;
        } else if (!(adapter->flags & IGC_FLAG_NEED_LINK_UPDATE)) {
            adapter->flags |= IGC_FLAG_NEED_LINK_UPDATE;
            adapter->link_check_timeout = jiffies;
        }
    }

    return link_active;
}

/**
  this is called by interrupt
    @see igc_watchdog_task
 */
void AppleIGC::checkLinkStatus()
{
    struct igc_adapter *adapter = &priv_adapter;
    struct igc_hw *hw = &priv_adapter.hw;

    u32 link;

    hw->mac.get_link_status = true;

    /* Now check the link state. */
    link = intelCheckLink(adapter);

    pr_debug("checkLinkStatus() ===> link=%u, carrier=%u, linkUp=%u\n",
             link, carrier(), linkUp);

    if (adapter->flags & IGC_FLAG_NEED_LINK_UPDATE) {
        if (time_after(jiffies, (adapter->link_check_timeout + HZ)))
            adapter->flags &= ~IGC_FLAG_NEED_LINK_UPDATE;
        else {
            pr_debug("Force link down due to IGC_FLAG_NEED_LINK_UPDATE\n");
            link = FALSE;
        }
    }

    if (linkUp) {
        if (link) {
            /* The link partner must have changed some setting. Initiate renegotiation
             * of the link parameters to make sure that the MAC is programmed correctly.
             */
            watchdogSource->cancelTimeout();
            igc_update_stats(&priv_adapter);
            intelRestart();
        } else {
            /* Stop watchdog and statistics updates. */
            watchdogSource->cancelTimeout();
            setLinkDown();
        }
    } else {
        if (link) {
            /* Start rx/tx and inform upper layers that the link is up now. */
            setLinkUp();
            /* Perform live checks periodically. */
            watchdogSource->setTimeoutMS(200);
       }
    }
    pr_debug("checkLinkStatus() <===\n");
}

// corresponds to igc_intr
void AppleIGC::interruptOccurred(IOInterruptEventSource * src, int count)
{
    struct igc_adapter *adapter = &priv_adapter;
    struct igc_q_vector *q_vector = adapter->q_vector[0];
    struct igc_hw *hw = &adapter->hw;

    /* Interrupt Auto-Mask...upon reading ICR, interrupts are masked.  No
         * need for the IMC write */
    u32 icr = igc_rd32(hw, IGC_ICR);

    if(!enabledForNetif) {
        pr_err("Interrupt 0x%08x on disabled device\n", icr);
        return;
    }

    /* IMS will not auto-mask if INT_ASSERTED is not set, and if it is
     * not set, then the adapter didn't send an interrupt */
    if (!(icr & IGC_ICR_INT_ASSERTED)) {
        return;
    }
    igc_write_itr(q_vector);
    if (icr & IGC_ICR_DRSTA) {
        resetSource->setTimeoutMS(1);
    }

    if (icr & IGC_ICR_DOUTSYNC) {
        /* HW is reporting DMA is out of sync */
        adapter->stats.doosync++;
    }
    if (unlikely(icr & (IGC_ICR_RXSEQ | IGC_ICR_LSC))) {
        checkLinkStatus();
//
//        /* guard against interrupt when we're going down */
//        if (!test_bit(__IGB_DOWN, &adapter->state))
//            watchdogSource->setTimeoutMS(1);
    } else {
        igc_poll(q_vector, 64);
    }
    
    wr32(IGC_EIMS, adapter->eims_other);
}

void AppleIGC::interruptHandler(OSObject * target, IOInterruptEventSource * src, int count)
{
    AppleIGC * me = (AppleIGC *) target;
    me->interruptOccurred(src, count);
}


// corresponds to igb_watchdog_task
void AppleIGC::watchdogTask()
{
    struct igc_adapter *adapter = &priv_adapter;
    struct igc_hw *hw = &adapter->hw;
    int i;

    igc_update_stats(adapter);

    for (i = 0; i < adapter->num_tx_queues; i++) {
        struct igc_ring *tx_ring = adapter->tx_ring[i];

        /* Force detection of hung controller every watchdog period */
        set_bit(IGC_RING_FLAG_TX_DETECT_HANG, &tx_ring->flags);
    }

    /* Cause software interrupt to ensure rx ring is cleaned */
    /*if (adapter->msix_entries) {
        u32 eics = 0;

        for (i = 0; i < adapter->num_q_vectors; i++)
            eics |= adapter->q_vector[i]->eims_value;
        wr32(IGC_EICS, eics);
    } else {*/
        wr32(IGC_ICS, IGC_ICS_RXDMT0);
    //}

    /* Reset the timer */
    if (!test_bit(__IGC_DOWN, &adapter->state)){
        if (adapter->flags & IGC_FLAG_NEED_LINK_UPDATE) {
            pr_debug("watchdogTask(): adapter has IGB_FLAG_NEED_LINK_UPDATE, forcing restart.\n");
            intelRestart();
        }
    }

    watchdogSource->setTimeoutMS(200);
}
    
void AppleIGC::watchdogHandler(OSObject * target, IOTimerEventSource * src)
{
    AppleIGC* me = (AppleIGC*) target;
    me->watchdogTask();
    me->watchdogSource->setTimeoutMS(1000);
}
    
void AppleIGC::resetHandler(OSObject * target, IOTimerEventSource * src)
{
    AppleIGC* me = (AppleIGC*) target;
    if(src == me->resetSource) {
        pr_debug("resetHandler: resetSource\n");
        igc_reinit_locked(&me->priv_adapter);
    }
    else if(src == me->dmaErrSource) {
        pr_debug("resetHandler: dmaErrSource\n");
        //igc_dma_err_task(&me->priv_adapter,src);
    }
}


IOReturn AppleIGC::registerWithPolicyMaker ( IOService * policyMaker )
{
    static IOPMPowerState powerStateArray[ 2 ] = {
        { 1,0,0,0,0,0,0,0,0,0,0,0 },
        { 1,kIOPMDeviceUsable,kIOPMPowerOn,kIOPMPowerOn,0,0,0,0,0,0,0,0 }
    };
    powerState = 1;
    return policyMaker->registerPowerDriver( this, powerStateArray, 2 );
}

IOReturn AppleIGC::setPowerState( unsigned long powerStateOrdinal,
                                IOService *policyMaker )
{
    pr_err("setPowerState(%d)\n",(int)powerStateOrdinal);
    if (powerState == powerStateOrdinal)
        return IOPMAckImplied;
    powerState = powerStateOrdinal;

    if(powerStateOrdinal == 0){ // SUSPEND/SHUTDOWN
        pr_err("suspend start.\n");
        
        pr_err("suspend end.\n");
        bSuspended = TRUE;
    } else if(bSuspended) { // WAKE
        pr_err("resume start.\n");
        
        pr_err("resume end.\n");
        bSuspended = FALSE;
    }
    /* acknowledge the completion of our power state change */
    return IOPMAckImplied;
}

IOReturn AppleIGC::getMaxPacketSize (UInt32 *maxSize) const {
    if (maxSize)
        *maxSize = MAX_STD_JUMBO_FRAME_SIZE;

    return kIOReturnSuccess;
}

IOReturn AppleIGC::getMinPacketSize (UInt32 *minSize) const {
    if(minSize)
        *minSize = ETH_ZLEN + ETH_FCS_LEN + VLAN_HLEN;
    
    return kIOReturnSuccess;
}


IOReturn AppleIGC::setMaxPacketSize (UInt32 maxSize){
    UInt32 newMtu = maxSize  - (ETH_HLEN + ETH_FCS_LEN);
    if(newMtu != _mtu){
        _mtu = newMtu;
        igc_change_mtu(this,_mtu);
    }
    return kIOReturnSuccess;
}

IOReturn AppleIGC::setWakeOnMagicPacket(bool active)
{
    igc_adapter *adapter = &priv_adapter;
    if(active){
       if ((adapter->flags & IGC_FLAG_WOL_SUPPORTED) == 0)
           return kIOReturnUnsupported;
        adapter->wol = 1;
    } else {
        adapter->wol = 0;
    }
    return kIOReturnSuccess;
}

IOReturn AppleIGC::getPacketFilters(const OSSymbol * group, UInt32 * filters) const {
    if(group == gIOEthernetWakeOnLANFilterGroup){
        *filters = kIOEthernetWakeOnMagicPacket;
        return kIOReturnSuccess;
    }
#if defined(MAC_OS_X_VERSION_10_6)
    if(group == gIOEthernetDisabledWakeOnLANFilterGroup){
        *filters = 0;
        return kIOReturnSuccess;
    }
#endif
    return super::getPacketFilters(group, filters);
}

UInt32 AppleIGC::getFeatures() const {
    UInt32 f = kIONetworkFeatureMultiPages | kIONetworkFeatureHardwareVlan;
    if(useTSO) {
#ifdef NETIF_F_TSO6
        f |= kIONetworkFeatureTSOIPv4 | kIONetworkFeatureTSOIPv6;
#else
        f |= kIONetworkFeatureTSOIPv4;
#endif
    }
    return f;
}

/**
 * Linux porting helpers
 **/


void AppleIGC::startTxQueue()
{
#ifndef __PRIVATE_SPI__
    pr_debug("AppleIGC::startTxQueue\n");
    if (likely(stalled && txMbufCursor && transmitQueue)) {
        pr_debug("Assuming wake queue called.\n");
        transmitQueue->service(IOBasicOutputQueue::kServiceAsync);
    } else {
        txMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(_mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN, MAX_SKB_FRAGS);
        if(txMbufCursor && transmitQueue) {
            transmitQueue->start();
        }
        if (stalled && transmitQueue) {
            transmitQueue->service(IOBasicOutputQueue::kServiceAsync);
        }
    }
    stalled = false;
#else
    if (txMbufCursor == NULL) {
        txMbufCursor = IOMbufNaturalMemoryCursor::withSpecification(0x4000, MAX_SKB_FRAGS);
    }
    netif->signalOutputThread();
#endif
}

void AppleIGC::stopTxQueue()
{
    pr_debug("AppleIGC::stopTxQueue()\n");
#ifndef __PRIVATE_SPI__
    transmitQueue->stop();
    transmitQueue->flush();
#endif
    netif->stopOutputThread();
    netif->flushOutputQueue();
}

void AppleIGC::rxChecksumOK( mbuf_t skb, UInt32 flag )
{
    setChecksumResult(skb, kChecksumFamilyTCPIP, flag, flag );
}
    
bool AppleIGC::carrier()
{
    return (preLinkStatus & kIONetworkLinkActive) != 0;

}
    
void AppleIGC::setCarrier(bool stat)
{
    pr_debug("setCarrier(%d) ===>\n", stat);
    if(stat){
        preLinkStatus = kIONetworkLinkValid | kIONetworkLinkActive;
        
        int index = currentMediumIndex();
        if (!setLinkStatus(preLinkStatus, mediumTable[index])) {
            pr_err("setLinkStatus: Some properties were not updated successullly with current medium(%u)\n",
                   preLinkStatus);
        }
    } else {
        preLinkStatus = kIONetworkLinkValid;
        if (!setLinkStatus(preLinkStatus)) {
            pr_err("setLinkStatus(kIONetworkLinkValid): Some properties were not updated\n");
        }
    }

    pr_debug("setCarrier() <===\n");
}
    
void AppleIGC::receive(mbuf_t skb)
{
    if (!(mbuf_flags(skb) & M_PKTHDR)) {
        this->freePacket(skb);
        skb = NULL;
        return;
    }
    netif->inputPacket(skb, (UInt32)mbuf_pkthdr_len(skb), IONetworkInterface::kInputOptionQueuePacket);
    //netif->inputPacket(skb, 0, IONetworkInterface::kInputOptionQueuePacket);
}

void AppleIGC::flushInputQueue() {
    netif->flushInputQueue();
}

void AppleIGC::setVid(mbuf_t skb, UInt16 vid)
{
    setVlanTag(skb, vid);
}

void AppleIGC::setTimers(bool enable)
{
    if(enable){
        if(watchdogSource)
            watchdogSource->enable();
        if(resetSource)
            resetSource->enable();
        if(dmaErrSource)
            dmaErrSource->enable();
    } else {
        if(watchdogSource)
            watchdogSource->disable();
        if(resetSource)
            resetSource->disable();
        if(dmaErrSource)
            dmaErrSource->disable();
    }
}
   
bool AppleIGC::setupMediumDict()
{
        IONetworkMedium *medium;
        UInt32 count;
        UInt32 i;
        bool result = false;

        pr_debug("setupMediumDict() ===>\n");

        if (intelSupportsEEE(&priv_adapter)) {
            count = MEDIUM_INDEX_COUNT;
        } else {
            count = MEDIUM_INDEX_COUNT - 6;
        }

        mediumDict = OSDictionary::withCapacity(count + 1);

        if (mediumDict) {
            for (i = MEDIUM_INDEX_AUTO; i < count; i++) {
                medium = IONetworkMedium::medium(mediumTypeArray[i], mediumSpeedArray[i], 0, i);

                if (!medium)
                    goto error1;
                result = IONetworkMedium::addMedium(mediumDict, medium);
                medium->release();

                if (!result)
                    goto error1;

                mediumTable[i] = medium;
            }
        }
        result = publishMediumDictionary(mediumDict);

        if (!result)
            goto error1;

    done:
        pr_debug("setupMediumDict() <===\n");
        return result;

    error1:
        pr_err("Error creating medium dictionary.\n");
        mediumDict->release();

        for (i = MEDIUM_INDEX_AUTO; i < MEDIUM_INDEX_COUNT; i++)
            mediumTable[i] = NULL;

        goto done;
}

bool AppleIGC::initEventSources( IOService* provider )
{
    bool result = false;

    pr_debug("initEventSources() ===>\n");

    // Get a handle to our superclass' workloop.
    //
    IOWorkLoop* myWorkLoop = getWorkLoop();
    if (myWorkLoop == NULL) {
        if (!createWorkLoop()) {
            pr_err("No workloop and failed to create one\n");
            return false;
        }
        myWorkLoop = getWorkLoop();
        if (myWorkLoop == NULL) {
            return false;
        }
    }
#ifndef __PRIVATE_SPI__
    transmitQueue = getOutputQueue();
    if (transmitQueue == NULL) {
        pr_err("Unexpected transmitQueue\n");
        return false;
    }
    transmitQueue->retain();
#endif
    interruptSource = IOInterruptEventSource::interruptEventSource(this,&AppleIGC::interruptHandler,provider);
    if (!interruptSource) {
        pr_err("MSI interrupt could not be enabled.\n");
        goto error1;
    }
    myWorkLoop->addEventSource(interruptSource);

    watchdogSource = IOTimerEventSource::timerEventSource(this, &AppleIGC::watchdogHandler );
    if (!watchdogSource) {
        pr_err("Failed to create IOTimerEventSource.\n");
        goto error2;
    }
    myWorkLoop->addEventSource(watchdogSource);

    resetSource = IOTimerEventSource::timerEventSource(this, &AppleIGC::resetHandler );
    myWorkLoop->addEventSource(resetSource);

    dmaErrSource = IOTimerEventSource::timerEventSource(this, &AppleIGC::resetHandler );
    myWorkLoop->addEventSource(dmaErrSource);

    pr_debug("initEventSources() <===\n");
    return true;
done:
    return result;

error2:
    workLoop->removeEventSource(interruptSource);
    RELEASE(interruptSource);

error1:
    pr_err("Error initializing event sources.\n");
#ifndef __PRIVATE_SPI__
    transmitQueue->release();
    transmitQueue = NULL;
#endif
    goto done;
}

#define kNameLength 60
bool AppleIGC::configureInterface(IONetworkInterface *interface) {
    char modelName[kNameLength];
    IONetworkData * data = NULL;
    
    if (super::configureInterface(interface) == false) {
        pr_err("IOEthernetController::confiugureInterface failed.\n");
        return false;
    }
    
    // Get the generic network statistics structure.
    data = interface->getParameter(kIONetworkStatsKey);
    if (!data || !(netStats = (IONetworkStats *) data->getBuffer())) {
        pr_err("netif getParameter NetworkStatsKey failed.\n");
        return false;
    }
    
    // Get the Ethernet statistics structure.
    data = interface->getParameter(kIOEthernetStatsKey);
    if (!data || !(etherStats = (IOEthernetStats *) data->getBuffer())) {
        pr_err("netif getParameter kIOEthernetStatsKey failed.\n");
        return false;
    }
#ifdef __PRIVATE_SPI__
    IOReturn error = interface->configureOutputPullModel(IGC_MIN_TXD, 0, 0, IOEthernetInterface::kOutputPacketSchedulingModelNormal, 0);
    if (error != kIOReturnSuccess) {
        IOLog("configureOutputPullModel() failed\n.");
        return false;
    }
#endif
    snprintf(modelName, kNameLength, "Intel(R) Ethernet Controller %s (IGC)", deviceModelNames[chip_idx].name);
    
    this->setProperty("Model", modelName);
    this->setProperty("IOModel", modelName);

    return true;
}

#pragma clang diagnostic pop
