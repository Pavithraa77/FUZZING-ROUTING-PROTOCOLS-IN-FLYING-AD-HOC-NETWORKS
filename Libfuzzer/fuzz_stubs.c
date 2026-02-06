#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

#include "batman.h"
#include "os.h"

/* ---------- Time ---------- */
uint32_t get_time_msec(void) { return 1; }
uint64_t get_time_msec64(void) { return 1; }

/* ---------- Debug ---------- */
void debug_output(int8_t debug_prio, const char *format, ...) {}

/* ---------- Address helpers ---------- */
void addr_to_string(uint32_t addr, char *str, int32_t len)
{
    snprintf(str, len, "0.0.0.0");
}

/* ---------- Routing ---------- */
void add_del_route(uint32_t dest, uint8_t netmask, uint32_t router,
                   uint32_t src_ip, int32_t ifi, const char *dev,
                   uint8_t rt_table, int8_t route_type, int8_t del) {}

void del_default_route(void) {}
void add_default_route(void) {}

void add_del_rule(uint32_t network, uint8_t netmask, int8_t rt_table,
                  uint32_t prio, const char *iif, int8_t dst_rule,
                  int8_t del) {}

int add_del_interface_rules(int8_t del) { return 0; }

void hna_local_update_nat(uint32_t hna_ip, uint8_t netmask,
                          int8_t route_action) {}

/* ---------- Daemon / interface ---------- */
int8_t is_aborted(void) { return 1; }

void deactivate_interface(struct batman_if *batman_if) {}
void check_inactive_interfaces(void) {}

void restore_and_exit(uint8_t is_sigsegv)
{
    exit(0);
}

/* ---------- UDP / Networking ---------- */
int8_t send_udp_packet(unsigned char *packet_buff, int packet_buff_len,
                       struct sockaddr_in *broad, int send_sock,
                       struct batman_if *batman_if)
{
    return 0;
}

int8_t receive_packet(unsigned char *packet_buff, int32_t packet_buff_len,
                      int16_t *packet_len, uint32_t *neigh,
                      uint32_t timeout, struct batman_if **if_incoming)
{
    return -1;
}

/* ---------- System settings ---------- */
int get_rp_filter(const char *iface) { return 0; }
int get_send_redirects(const char *iface) { return 0; }

void set_rp_filter(int val, const char *iface) {}
void set_send_redirects(int val, const char *iface) {}

int get_forwarding(void) { return 0; }
void set_forwarding(int val) {}

/* ---------- Random ---------- */
int rand_num(int max) { return 0; }

/* ---------- Stop flag ---------- */
int8_t stop = 0;
