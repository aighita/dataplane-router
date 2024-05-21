#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "router.h"

/* R TABLE */
struct route_table_entry *rtable;
size_t rtable_len;

/* ARP TABLE */
struct arp_table_entry *arp_table;
size_t arptable_len;

int main(int argc, char *argv[])
{
	char rtable_path[20];
	char buf[MAX_PACKET_LEN];

	uint8_t router_mac[6];
	uint8_t broadcast_mac[6];
	memset(broadcast_mac, 0xff, 6);

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Get rtable path
	char *p;
	p = strtok(argv[1], " ");
	strcpy(rtable_path, &p[0]);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable memory");

	arp_table = calloc(10, sizeof(struct arp_table_entry));
	DIE(arp_table == NULL, "arp_table memory");
	arptable_len = 10;

	rtable_len = read_rtable(rtable_path, rtable);
	print_rtable("rtable_out.txt", rtable, rtable_len);

	// qsort(rtable, rtable_len, sizeof(struct route_table_entry), comparePrefix);
	// print_rtable("rtable_out_sorted.txt", rtable, rtable_len);
	// arptable_len = parse_arp_table("arp_table_static.txt", arp_table);

	queue q = queue_create();
	queue aux_q = queue_create();

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		char *interface_ip = get_interface_ip(interface);
		uint32_t router_ip = inet_addr(interface_ip);

		get_interface_mac(interface, router_mac);

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if ((memcmp(eth_hdr->ether_dhost, router_mac, 6) != 0) && (memcmp(eth_hdr->ether_dhost, broadcast_mac, 6) != 0)) {
			continue;
		}

		if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
			// Process ARP packet
			struct arp_header *recv_arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

			// if (recv_arp_hdr->tpa == router_ip);

			if (recv_arp_hdr->op == htons(1)) {
				char buf_response[MAX_PACKET_LEN];
				size_t buf_response_len = sizeof(struct ether_header) + sizeof(struct arp_header);
				
				struct ether_header *r_ether_header = (struct ether_header *) buf_response;
				struct arp_header *r_arp_header = (struct arp_header *) (buf_response + sizeof(struct ether_header));

				r_arp_header->htype = htons(0x1);
				r_arp_header->ptype = htons(ETHERTYPE_IP);
				r_arp_header->hlen = 6;
				r_arp_header->plen = 4;
				r_arp_header->op = htons(2);
				r_arp_header->spa = recv_arp_hdr->tpa;
				r_arp_header->tpa = recv_arp_hdr->spa;
				memcpy(r_arp_header->sha, router_mac, 6);
				memcpy(r_arp_header->tha, eth_hdr->ether_shost, 6);

				memcpy(r_ether_header->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(r_ether_header->ether_shost, router_mac, 6);
				r_ether_header->ether_type = htons(ETHERTYPE_ARP);

				send_to_link(interface, buf_response, buf_response_len);
				continue;
			}
			
			if (recv_arp_hdr->op == htons(2)) {
				// add_to_arp_table(arp_table, recv_arp_hdr->spa, recv_arp_hdr->sha);
				// struct route_table_entry *entry = get_best_route(recv_arp_hdr->spa);
				// if (entry == NULL) continue;
				// int alrd = 0;
				// for (int i = 0; i < arptable_len; i++) {
				// 	if (memcmp(arp_table[i].mac, recv_arp_hdr->sha, 6) == 0) {
				// 		alrd = 1;
				// 		break;
				// 	}
				// }
				// if (!alrd) add_to_arp_table(arp_table, pack->entry, recv_arp_hdr->sha);
				while (queue_empty(q)) {
					struct pack_cell *pack = (struct pack_cell *) queue_deq(q);
					struct iphdr *pack_ip_hdr = (struct iphdr *) (pack->buff + sizeof(struct ether_header));
					if (pack_ip_hdr->daddr == recv_arp_hdr->spa) {
						struct ether_header *p_eth_header = (struct ether_header *) pack->buff;
						memcpy(p_eth_header->ether_shost, router_mac, 6);
						memcpy(p_eth_header->ether_dhost, recv_arp_hdr->sha, 6);
						send_to_link(interface, pack->buff, pack->len);
						add_to_arp_table(arp_table, recv_arp_hdr->spa, recv_arp_hdr->sha);
					} else {
						queue_enq(aux_q, pack);
					}
				}
				while(queue_empty(aux_q)) {
					struct pack_cell *aux_pack = (struct pack_cell *) queue_deq(aux_q);
					queue_enq(q, aux_pack);
				}
				continue;
			}
		} else if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			// Process IPv4 packet
			struct iphdr *recv_ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

			// IP Header checksum verification
			uint16_t recv_ip_hdr_checksum = recv_ip_hdr->check;
			recv_ip_hdr->check = 0;
			uint16_t iphdr_checksum = 0;
			iphdr_checksum = checksum((uint16_t *) recv_ip_hdr, sizeof(struct iphdr));

			if (htons(iphdr_checksum) != recv_ip_hdr_checksum) {
				/* Corrupted packet */
				continue;
			}

			if ((recv_ip_hdr->daddr == router_ip) && (recv_ip_hdr->protocol == 1)) {
				/* Send back ICMP type "echo-reply" */
				struct icmphdr *recv_icmp_header = (struct icmphdr *) ((char *) recv_ip_hdr + sizeof(struct iphdr));
				if (recv_icmp_header->type != 8) {
					continue;
				}

				char buf_response[MAX_PACKET_LEN];
				size_t buf_response_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

				struct ether_header *r_eth_header = (struct ether_header *) buf_response;
				struct iphdr *r_ip_header = (struct iphdr *) (buf_response + sizeof(struct ether_header));
				struct icmphdr *r_icmp_header = (struct icmphdr *) (buf_response + (sizeof(struct ether_header) + sizeof(struct iphdr)));

				r_icmp_header->type = 0;
				r_icmp_header->code = 0;
				r_icmp_header->checksum = 0;
				r_icmp_header->checksum = htons(checksum((uint16_t *) r_icmp_header, sizeof(struct icmphdr)));

				r_ip_header->ihl = 5;
				r_ip_header->version = 4;
				r_ip_header->tos = 0;
				r_ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				r_ip_header->id = htons(1);
				r_ip_header->frag_off = 0;
				r_ip_header->ttl = 21;
				r_ip_header->protocol = 1;
				r_ip_header->check = 0;
				r_ip_header->saddr = recv_ip_hdr->daddr;
				r_ip_header->daddr = recv_ip_hdr->saddr;

				memcpy(r_eth_header->ether_shost, eth_hdr->ether_dhost, 6);
				memcpy(r_eth_header->ether_dhost, eth_hdr->ether_shost, 6);
				r_eth_header->ether_type = htons(ETHERTYPE_IP);

				r_icmp_header->checksum = htons(checksum((uint16_t *) r_ip_header, buf_response_len -  sizeof(struct ether_header)));

				send_to_link(interface, buf_response, buf_response_len);
				continue;
			}

			if (recv_ip_hdr->ttl < 2) {					/* Send back ICMP packet "Time exceeded" */
				char buf_response[MAX_PACKET_LEN];
				size_t buf_response_len = sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8;

				struct ether_header *r_eth_header = (struct ether_header *) buf_response;
				struct iphdr *r_ip_header = (struct iphdr *) (buf_response + sizeof(struct ether_header));
				struct icmphdr *r_icmp_header = (struct icmphdr *) (buf_response + (sizeof(struct ether_header) + sizeof(struct iphdr)));
				struct iphdr *old_ip_hdr = (struct iphdr *) (buf_response + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
				char *old_data = buf_response + (sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr));

				memcpy(old_data, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

				memcpy(old_ip_hdr, buf + sizeof(struct ether_header), sizeof(struct iphdr));

				r_icmp_header->type = 11;
				r_icmp_header->code = 0;
				r_icmp_header->checksum = 0;
				r_icmp_header->checksum = htons(checksum((uint16_t *) r_icmp_header, sizeof(struct icmphdr)));

				r_ip_header->ihl = 5;
				r_ip_header->version = 4;
				r_ip_header->tos = 0;
				r_ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
				r_ip_header->id = htons(1);
				r_ip_header->frag_off = 0;
				r_ip_header->ttl = 21;
				r_ip_header->protocol = 1;
				r_ip_header->check = 0;
				r_ip_header->saddr = recv_ip_hdr->daddr;
				r_ip_header->daddr = recv_ip_hdr->saddr;

				memcpy(r_eth_header->ether_shost, eth_hdr->ether_dhost, 6);
				memcpy(r_eth_header->ether_dhost, eth_hdr->ether_shost, 6);
				r_eth_header->ether_type = htons(ETHERTYPE_IP);

				send_to_link(interface, buf_response, buf_response_len);
				continue;
			}

			// Update TTL & checksum
			recv_ip_hdr->ttl -= 1;
			recv_ip_hdr->check = 0;
			recv_ip_hdr->check = ~(~recv_ip_hdr_checksum + ~((uint16_t)(recv_ip_hdr->ttl + 1)) + (uint16_t)recv_ip_hdr->ttl) - 1;

			struct route_table_entry *entry = get_best_route(recv_ip_hdr->daddr);
			if (entry == NULL) {							/* Send back ICMP packet "Destination unreachable" */
				char buf_response[MAX_PACKET_LEN];
				size_t buf_response_len = sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8;

				struct ether_header *r_eth_header = (struct ether_header *) buf_response;
				struct iphdr *r_ip_header = (struct iphdr *) (buf_response + sizeof(struct ether_header));
				struct icmphdr *r_icmp_header = (struct icmphdr *) (buf_response + (sizeof(struct ether_header) + sizeof(struct iphdr)));
				struct iphdr *old_ip_hdr = (struct iphdr *) (buf_response + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
				char *old_data = buf_response + (sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr));

				memcpy(old_data, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);

				memcpy(old_ip_hdr, buf + sizeof(struct ether_header), sizeof(struct iphdr));

				r_icmp_header->type = 3;
				r_icmp_header->code = 0;
				r_icmp_header->checksum = 0;
				r_icmp_header->checksum = htons(checksum((uint16_t *) r_icmp_header, sizeof(struct icmphdr)));

				r_ip_header->ihl = 5;
				r_ip_header->version = 4;
				r_ip_header->tos = 0;
				r_ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
				r_ip_header->id = htons(1);
				r_ip_header->frag_off = 0;
				r_ip_header->ttl = 21;
				r_ip_header->protocol = 1;
				r_ip_header->check = 0;
				r_ip_header->saddr = recv_ip_hdr->daddr;
				r_ip_header->daddr = recv_ip_hdr->saddr;

				memcpy(r_eth_header->ether_shost, eth_hdr->ether_dhost, 6);
				memcpy(r_eth_header->ether_dhost, eth_hdr->ether_shost, 6);
				r_eth_header->ether_type = htons(ETHERTYPE_IP);

				send_to_link(interface, buf_response, buf_response_len);
				continue;
			}

			struct arp_table_entry *dest = get_arp_table_entry(entry->next_hop);
			fprintf(stdout, "next_hop: %d\n", entry->next_hop);
			if (dest == NULL) {
				/* Send ARP request */
				fprintf(stdout, "Sending ARP request for: %d\n", entry->next_hop);
				struct pack_cell *pack = (struct pack_cell *) malloc(sizeof(struct pack_cell));

				memcpy(pack->buff, buf, len);
				pack->len = len;

				fprintf(stdout, "buf: %s\n", buf);
				fprintf(stdout, "pack->buf: %s\n", pack->buff);
				queue_enq(q, pack);
				
				char buf_response[MAX_PACKET_LEN];
				size_t buf_response_len = sizeof(struct ether_header) + sizeof(struct arp_header);

				struct ether_header *r_eth_header = (struct ether_header *) buf_response;
				struct arp_header *r_arp_header = (struct arp_header *) (buf_response + sizeof(struct ether_header));

				r_arp_header->htype = htons(0x1);
				r_arp_header->ptype = htons(ETHERTYPE_IP);
				r_arp_header->hlen = 6;
				r_arp_header->plen = 4;
				r_arp_header->op = htons(1);
				r_arp_header->spa = router_ip;
				r_arp_header->tpa = recv_ip_hdr->daddr;
				memcpy(r_arp_header->sha, router_mac, 6);
				memcpy(r_arp_header->tha, "\x00", 6);

				memcpy(r_eth_header->ether_dhost, broadcast_mac, 6);
				memcpy(r_eth_header->ether_shost, router_mac, 6);
				r_eth_header->ether_type = htons(ETHERTYPE_ARP);

				send_to_link(entry->interface, buf_response, buf_response_len);
				continue;
			}

			memcpy(eth_hdr->ether_shost, router_mac, 6);
			memcpy(eth_hdr->ether_dhost, dest->mac, 6);
			
			send_to_link(entry->interface, buf, len);
			continue;
		}
	}

	free(rtable);
	free(arp_table);
	free(q);
	free(aux_q);
	return 0;
}

void add_to_arp_table(struct arp_table_entry *arp_table, uint32_t ip, uint8_t mac[6]) {
	for (int i = 0; i < arptable_len; i++) {
		if (arp_table[i].ip == 0) {
			arp_table[i].ip = ip;
			memcpy(arp_table[i].mac, mac, 6);
			fprintf(stdout, "%d %s added to arp table\n", arp_table[i].ip, arp_table[i].mac);
			break;
		}
	}
}

void print_rtable(const char *path, struct route_table_entry *rtable, size_t rtable_len) {
	FILE *fp = fopen(path, "w");
	
    for (int i = 0; i < rtable_len; ++i) {
        fprintf(fp, "%u.%u.%u.%u   %u.%u.%u.%u   %u.%u.%u.%u   %u\n",
            rtable[i].prefix & 0xFF, (rtable[i].prefix >> 8) & 0xFF,
            (rtable[i].prefix >> 16) & 0xFF, (rtable[i].prefix >> 24) & 0xFF,
            rtable[i].next_hop & 0xFF, (rtable[i].next_hop >> 8) & 0xFF,
            (rtable[i].next_hop >> 16) & 0xFF, (rtable[i].next_hop >> 24) & 0xFF,
            rtable[i].mask & 0xFF, (rtable[i].mask >> 16) & 0xFF,
            (rtable[i].mask >> 8) & 0xFF, (rtable[i].mask >> 24) & 0xFF,
            rtable[i].interface);
    }
}

int comparePrefix(const void *a, const void *b) {
    struct route_table_entry *entryA = (struct route_table_entry *)a;
    struct route_table_entry *entryB = (struct route_table_entry *)b;
    
    if (entryA->prefix != entryB->prefix) {
        return entryB->prefix - entryA->prefix;
    }
    
    return entryB->mask - entryA->mask;
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	for (int i = 0; i < rtable_len; i++) {
		if ((rtable[i].mask & ip_dest) == rtable[i].prefix) {
			return &rtable[i];
		}
	}
	return NULL;
}

struct arp_table_entry *get_arp_table_entry(uint32_t given_ip) {
	for (int i = 0; i < arptable_len; i++) {
		fprintf(stdout, "%s is in arp_table\n", arp_table[i].mac);
		if (arp_table[i].ip == given_ip) {
			
			return &arp_table[i];
		}
	}
	return NULL;
}
