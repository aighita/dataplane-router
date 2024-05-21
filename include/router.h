#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>

#define ETHERTYPE_IP		    0x0800	/* IPv4 protocol */
#define ETHERTYPE_ARP           0x0806  /* ARP protocol */

struct pack_cell {
    char buff[MAX_PACKET_LEN];
    size_t len;
};

int comparePrefix(const void *a, const void *b);
void print_rtable(const char *path, struct route_table_entry *rtable, size_t rtable_len);
struct route_table_entry *get_best_route(uint32_t ip_dest);
struct arp_table_entry *get_arp_table_entry(uint32_t given_ip);
void add_to_arp_table(struct arp_table_entry *arp_table, uint32_t ip, uint8_t mac[6]);
