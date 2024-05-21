void test_router_mac_and_broadcast_mac() {
    fprintf(stdout, "BROADCAST_MAC: \n");
    for (int i = 0; i < 6; i++) {
        fprintf(stdout, "%d", broadcast_mac[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "ETHER_DHOST: \n");
    for (int i = 0; i < 6; i++) {
        fprintf(stdout, "%d", eth_hdr->ether_dhost[i]);
    }
    fprintf(stdout, "\n");
    fprintf(stdout, "ROUTER_MAC: \n");
    for (int i = 0; i < 6; i++) {
        fprintf(stdout, "%d", router_mac[i]);
    }
    fprintf(stdout, "\n");
}