#define LOG6LBR_MODULE "6LBR"

#include "contiki.h"
#include "contiki-net.h"

#include "log-6lbr.h"
#include "6lbr-network.h"
#include "nvm-config.h"

#include "ip64.h"
#include "ip64-ipv4-dhcp.h"
#include "ip64-dhcpc.h"
#include "ip64-eth.h"
#include "ip64-addr.h"
#include "6lbr-ip64.h"  // Include your modified header file

#if CONTIKI_TARGET_NATIVE
extern void cetic_6lbr_save_ip(void);
#endif

uip_ip4addr_t eth_ip64_addr;
uip_ip4addr_t eth_ip64_netmask;
uip_ip4addr_t eth_ip64_gateway;

// Define the variable in this file
const struct ip64_dhcpc_state *cetic_6lbr_ip64_dhcp_state;

/---------------------------------------------------------------------------/
void
cetic_6lbr_ip64_dhcpc_configured(const struct ip64_dhcpc_state *s)
{
  cetic_6lbr_ip64_dhcp_state = s;
  LOG6LBR_4ADDR(INFO, &s->ipaddr, "Set IPv4 address : ");
#if CONTIKI_TARGET_NATIVE
  cetic_6lbr_save_ip();
#endif
}
/---------------------------------------------------------------------------/
void
cetic_6lbr_ip64_init(void)
{
  if((nvm_data.global_flags & CETIC_GLOBAL_IP64) != 0) {
    LOG6LBR_INFO("Starting IP64\n");
    ip64_eth_addr_set((struct ip64_eth_addr *)&eth_mac_addr);
    if((nvm_data.eth_ip64_flags & CETIC_6LBR_IP64_RFC6052_PREFIX) != 0) {
      uip_ip6addr_t ip64_prefix = {{ 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
      ip64_addr_set_prefix(&ip64_prefix, 96);
    }
    ip64_init();
    if((nvm_data.eth_ip64_flags & CETIC_6LBR_IP64_DHCP) == 0) {
      memcpy(&eth_ip64_addr, nvm_data.eth_ip64_addr, sizeof(nvm_data.eth_ip64_addr));
      memcpy(&eth_ip64_netmask, nvm_data.eth_ip64_netmask, sizeof(nvm_data.eth_ip64_netmask));
      memcpy(&eth_ip64_gateway, nvm_data.eth_ip64_gateway, sizeof(nvm_data.eth_ip64_gateway));
      ip64_set_ipv4_address(&eth_ip64_addr, &eth_ip64_netmask);
      ip64_set_draddr(&eth_ip64_gateway);
      LOG6LBR_4ADDR(INFO, &eth_ip64_addr, "IPv4 address : ");
    } else {
      ip64_ipv4_dhcp_init();
    }
  }
}
/---------------------------------------------------------------------------/
// Other functions and implementation specific to 6lbr-ip64.c
