/* lwipopts.h — lwIP 2.1.x config for the Orientrise CCS2 adapter app (NO_SYS=1 raw API).
 * Byte-exact match to the recovered C013 TCP/IPv6/ND6 config (REPORT §5.9, Agent K/N,
 * analyze97/98): TCP_MSS 1460, TCP_WND 11680, TCP_SND_BUF 14600 (10*MSS), SND_QUEUELEN 40,
 * SYNMAXRTX 3 / MAXRTX 4, tcp_backoff {1,2,3,4,5,6,7,7,...} + persist {3,6,12,24,48,96,120}
 * (lwIP defaults), MSL 60s (TIME_WAIT 240 ticks), fasttmr 250ms / slowtmr 500ms.
 * IPv6 link-local EUI-64 + ND6 (the recovered nd6_input/nd6_tmr/netif_create_ip6_linklocal
 * addresses ARE lwIP symbols). IPv6 frag/reass ON (V2GTP EXI frames up to 8509 > MTU).
 * IPv4 / sockets / netconn / stats / debug OFF. Freestanding: arch/cc.h + libc shim. */
#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* ---- system: bare-metal, raw API, no OS ---- */
#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0      /* single-threaded raw API; RX ISR only queues frames */
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0
#define LWIP_NETIF_API              0
#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_LINK_CALLBACK    1
#define LWIP_NETIF_HOSTNAME         0
#define LWIP_NETIF_HWADDRHINT       1
#define LWIP_HAVE_LOOPIF            0
#define LWIP_LOOPBACK_MAX_PBUFS     0
#define LWIP_SINGLE_NETIF           1
#define LWIP_TIMEVAL_PRIVATE        0
#define LWIP_PROVIDE_ERRNO          0      /* shim supplies errno */

/* ---- protocols: IPv6 only, TCP + UDP + ICMPv6 + ND6 ---- */
#define LWIP_IPV4                   0
#define LWIP_IPV6                   1
#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define LWIP_UDPLITE                0
#define LWIP_ICMP                   0
#define LWIP_ICMP6                  1
#define LWIP_RAW                    0
#define LWIP_IGMP                   0
#define LWIP_IPV6_MLD               0      /* ff02::1 all-nodes is implicit; no MLD needed */
#define LWIP_IPV6_AUTOCONFIG        0      /* static link-local, no SLAAC */
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_IPV6_FORWARD           0
#define LWIP_IPV6_FRAG              1      /* EXI frames > 1500 MTU */
#define LWIP_IPV6_REASS             1
#define LWIP_IPV6_DHCP6             0
#define LWIP_DNS                    0
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_PPP                    0
#define LWIP_ARP                    0
#define LWIP_ETHERNET               1      /* ethernet_input/ethip6_output even with ARP off */

/* ---- TCP: recovered byte-exact constants ---- */
#define TCP_MSS                     1460   /* 0x5b4 */
#define TCP_WND                     11680  /* 0x2da0 */
#define TCP_SND_BUF                 14600  /* 0x3908 = 10*MSS */
#define TCP_SND_QUEUELEN            40     /* 0x28 */
#define TCP_SYNMAXRTX               3
#define TCP_MAXRTX                  4
#define TCP_LISTEN_BACKLOG          0
#define TCP_QUEUE_OOSEQ             1
#define LWIP_TCP_TIMESTAMPS         0
#define LWIP_TCP_SACK_OUT           0
#define LWIP_TCP_KEEPALIVE          0
#define LWIP_WND_SCALE              0      /* window 11680 fits 16-bit, no scaling */
#define TCP_CALCULATE_EFF_SEND_MSS  1      /* recovered tcp_eff_send_mss */
#define TCP_TMR_INTERVAL            250    /* fasttmr 250ms; slowtmr every other = 500ms */
#define TCP_MSL                     60000  /* TIME_WAIT 2*MSL = 120s = 240 slow ticks */
#define LWIP_TCP_RTO_TIME           3000
/* tcp_backoff / tcp_persist_backoff use lwIP defaults (match recovered tables) */

/* ---- ND6 (recovered cache/state machine; lwIP defaults match) ---- */
#define LWIP_ND6_NUM_NEIGHBORS      8
#define LWIP_ND6_NUM_DESTINATIONS   8
#define LWIP_ND6_NUM_PREFIXES       4
#define LWIP_ND6_NUM_ROUTERS        4
#define LWIP_ND6_QUEUEING           1
#define LWIP_ND6_NUM_QUEUED_PACKETS 4
#define LWIP_ND6_MAX_MULTICAST_SOLICIT 3
#define LWIP_ND6_MAX_UNICAST_SOLICIT   3
#define LWIP_ND6_REACHABLE_TIME     30000
#define LWIP_ND6_RETRANS_TIMER      1000
#define LWIP_ND6_DELAY_FIRST_PROBE_TIME 5000

/* ---- memory: static pools (no libc malloc); sized for one TLS-over-TCP V2G session ---- */
#define MEM_LIBC_MALLOC             0
#define MEM_SIZE                    24576  /* lwIP ram_heap (PBUF_RAM / tcp seg data) */
#define MEMP_MEM_MALLOC             0
#define MEMP_NUM_PBUF               16
#define MEMP_NUM_UDP_PCB            2
#define MEMP_NUM_TCP_PCB            4
#define MEMP_NUM_TCP_PCB_LISTEN     1
#define MEMP_NUM_TCP_SEG            48     /* >= TCP_SND_QUEUELEN + OOSEQ headroom */
#define MEMP_NUM_NETBUF             0
#define MEMP_NUM_NETCONN            0
#define MEMP_NUM_SYS_TIMEOUT        8
#define MEMP_NUM_ND6_QUEUE          4
#define MEMP_NUM_REASSDATA          4
#define MEMP_NUM_FRAG_PBUF          8
#define PBUF_POOL_SIZE              16
#define PBUF_POOL_BUFSIZE           1524   /* ETH(14)+IPv6(40)+TCP(20)+MSS(1460) rounded */
#define PBUF_LINK_HLEN              14
#define PBUF_LINK_ENCAPSULATION_HLEN 0
#define LWIP_SUPPORT_CUSTOM_PBUF    1      /* IPv6 frag/reass uses pbuf_alloced_custom */
#define LWIP_NETIF_TX_SINGLE_PBUF   0
#define MEM_ALIGNMENT               4

/* ---- checksums: QCA7005 has no HW offload -> all SW ---- */
#define CHECKSUM_GEN_IP             0
#define CHECKSUM_GEN_UDP            1
#define CHECKSUM_GEN_TCP            1
#define CHECKSUM_GEN_ICMP           0
#define CHECKSUM_GEN_ICMP6          1
#define CHECKSUM_CHECK_IP           0
#define CHECKSUM_CHECK_UDP          1
#define CHECKSUM_CHECK_TCP          1
#define CHECKSUM_CHECK_ICMP         0
#define CHECKSUM_CHECK_ICMP6        1
#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#define LWIP_CHECKSUM_ON_COPY       0

/* ---- size: no stats / debug / asserts ---- */
#define LWIP_STATS                  0
#define LWIP_STATS_DISPLAY          0
#define MEMP_STATS                  0
#define MEM_STATS                   0
#define LINK_STATS                  0
#define LWIP_DEBUG                  0
#define LWIP_NOASSERT               1

#endif /* LWIPOPTS_H */
