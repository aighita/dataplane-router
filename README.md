# Router Program

This repository contains a simple router implementation in C. The program handles basic routing and ARP requests and replies, and is designed for educational purposes. 

## Files

- `router.c`: The main file containing the router implementation.
- `queue.h`, `lib.h`, `protocols.h`, `router.h`: Header files required for the router's functionality.
- `rtable_out.txt`, `arp_table_static.txt`: Example files for routing and ARP tables.

## Functionality

The router performs the following key tasks:

1. **Initialization**: Initializes routing and ARP tables, reads routing table from file, and prints it.
2. **Packet Reception**: Listens for incoming packets on all interfaces.
3. **Packet Processing**: Handles ARP and IP packets:
   - ARP requests and replies.
   - IP packet forwarding, ICMP echo requests and replies, and ICMP error messages.
4. **Routing Table Management**: Finds the best route for an IP packet.
5. **ARP Table Management**: Manages ARP table entries.

## Structure

### Main Function

The `main` function initializes the router, reads the routing table, creates queues, and enters an infinite loop to process incoming packets.

### ARP Handling

- **ARP Requests**: Generates and sends ARP replies.
- **ARP Replies**: Updates the ARP table and processes queued packets waiting for the ARP reply.

### IP Packet Handling

- **ICMP Echo Requests**: Replies with ICMP Echo Replies.
- **ICMP Errors**: Sends ICMP Time Exceeded or Destination Unreachable messages.
- **IP Forwarding**: Forwards IP packets to the next hop based on the routing table.

### Helper Functions

- `add_to_arp_table`: Adds an entry to the ARP table.
- `print_rtable`: Prints the routing table to a file.
- `comparePrefix`: Compares two routing table entries by prefix and mask.
- `get_best_route`: Finds the best route for a given IP address.
- `get_arp_table_entry`: Finds an ARP table entry for a given IP address.

## Compilation

Compile the router program using the following command:
```sh
gcc -o router router.c
