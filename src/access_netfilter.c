#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
/* types for the internet address family */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/table.h>
#include <libnftnl/expr.h>

/* functions to operate on structs (e.g., struct sockaddr_in) */
#include <time.h>
#include <errno.h>

#include "access_netfilter.h"
#include "access_control.h"

/*
	reference:
	https://github.com/greearb/libnftnl-ct/tree/master/examples

	Based on libnftnl and libmnl to set rules for nftables;
	libmnl: c lib for working with Netlink
	libnftnl: bridge between user program and nf_tables

  * nftables does not have default tables. Need to create tables 
	for address family before setting rules.
		ip, ip6, inet, netdev, ... (family name) see the manual of nft

  	create ipv4_addr set, install the rule
  	ip saddr @blocklist_set drop
  	at runtime, add/remote elements to/from the set
  	using netlink

	from CLI, use nft tool:
	% nft --debug=netlink list ruleset # check ruleset + low-level rule expressions
	% nft delete table inet blocklist_table # to delete the table in inet family
	% nft add element inet blocklist_table blocklist_set { 192.168.0.1 }
	% nft delete element inet blocklist_table blocklist_set { 192.168.0.1 }
	% nft flush ruleset  # delete all
*/

/* Add or delete a single IPv4 address in an existing nftables set.
 * family: NFPROTO_INET (matches `table inet`)
 * add: 1 to insert, 0 to remove
 * Returns 0 on success, -1 on error. */

/* default for now */
static char *table_name = "blocklist_table";
static char *set_name = "blocklist_set";
static char *chain_name = "blocklist_chain";

static int send_to_netfilter(struct mnl_nlmsg_batch *batch) {
	int ret = 0;
	struct mnl_socket *socket = NULL;
	uint32_t portid;

	char recv_buf[MNL_SOCKET_BUFFER_SIZE];

	/* open netfilter socket */
	socket = mnl_socket_open(NETLINK_NETFILTER);
	if (!socket) {
		fprintf(stderr, "Failed to open netfilter socket\n");
		ret = -1;
		goto out;
	}

	/* bind socket: MNL_SOCKET_AUTOPID for automatic port ID selection */
	ret = mnl_socket_bind(socket, 0, MNL_SOCKET_AUTOPID);
	if (ret < 0) {
		perror("Failed to bind socket:");
		ret = -1;
		goto out;
	}
	portid = mnl_socket_get_portid(socket);

	/* send through socket */
	ret = mnl_socket_sendto(socket, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch));
	if (ret < 0) {
		perror("Failed to send:");
		ret = -1;
		goto out;
	}

	/* receive the ACK response from netfilter */
	ssize_t size = 0;
	while ((size = mnl_socket_recvfrom(socket, recv_buf, sizeof recv_buf)) > 0) {
		/* callback runqueue for netlink messages
	
		int mnl_cb_run (const void * buf, size_t numbytes, unsigned int seq,
						unsigned int portid, mnl_cb_t cb_data, void * data);
		seq: sequence number that we expect to receive
		portid: netlink port ID that we expect to receive
		cb_data: callback handler for data messages
		data: pointer to data that will be passed to cb_data

		if seq is 0, sequence number validation is skipped; 
		portid validation works the same way.
		Since each message in a batch has its own seq, it's awkward to validate
		message by message with a single mnl_cb_run() call, we only validate
		portid so foreign messages are rejected.
		*/
		ret = mnl_cb_run(recv_buf, size, 0, portid, NULL, NULL);
		/* 	MNL_CB_OK (>= 1): no problems occured
			MNL_CB_STOP (0): stop callback runqueue
		   MNL_CB_ERROR (<=-1): error occured */
		if (ret <= 0) break;
	}

	if (ret < 0) perror("mnl_cb_run error:");
	else ret = 0;

out:
	/* close the socket */
	mnl_socket_close(socket);
	return ret;
}

/*
	Logic:
	alloc a set object -> specify table & set name -> alloc element objects ->
	configure element keys -> add the elements to the set object -> build batch

	netlink message header:
	NFT_MSG_NEWSETELEM: add the element
	NFT_MSG_DELSETELEM: delete the element
	-> send to kernel thorough netlink

	idempotent block and unblock.

    TODO: validation on the number of elements passing to netfilter;
	Zabbix manualinput has length limit (in our case: 2048 including the symbols in JSON);
*/
static int netfilter_element_op(const char *table_name, const char *set_name,
					struct ip_batch *arr, int num)
{
	int ret = 0, i;
	struct nlmsghdr *header = NULL;
	struct nftnl_set *block_set = NULL;
	struct nftnl_set *unblock_set = NULL;
	struct mnl_nlmsg_batch *batch = NULL;

	int num_blocks = 0, num_unblocks = 0;
	uint16_t family = NFPROTO_INET;

    char *buf = NULL;
	size_t buf_size = 1024 + num * 64;

	if (!arr || !num) {
		/* emtpy input do nothing */
		goto out;
	}
 
	buf = malloc(buf_size);
	if (!buf) {
		fprintf(stderr, "Failed to allocate buf\n");
		ret = -1;
		goto out;
	}

	/* initialize sets */
    block_set = nftnl_set_alloc();
	if (!block_set) {
		perror("nftnl_set_alloc error:");
		ret = -1;
		goto out;
	}
    nftnl_set_set_str(block_set, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(block_set, NFTNL_SET_NAME, set_name);

    unblock_set = nftnl_set_alloc();
	if (!unblock_set) {
		perror("nftnl_set_alloc error:");
		ret = -1;
		goto out;
	}
    nftnl_set_set_str(unblock_set, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(unblock_set, NFTNL_SET_NAME, set_name);

	uint32_t seq = time(NULL);
    batch = mnl_nlmsg_batch_start(buf, buf_size);

	/* envelop begin */
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

	/* FIXME: IPv4 only for now */
	for (i = 0; i < num; i++) {
		uint32_t saddr = 0;
		struct in_addr addr;
		struct ip_batch *cur = &arr[i];
		int op = cur->op;
		char *ip = cur->ip_addr;
		struct nftnl_set *set = NULL;

		/* convert ip address to network byte order */
		if (inet_pton(AF_INET, ip, &addr) != 1) {
			perror("inet_pton() failed:");
			ret = -1;
			goto out;
		}
		saddr = addr.s_addr;

		if (op == OP_BLOCK) {
			set = block_set;
			num_blocks++;
		}
		else {
			set = unblock_set;
			num_unblocks++;
		}

		/* initiate an element */
	    struct nftnl_set_elem *element = nftnl_set_elem_alloc();
	    if (!element) {
			perror("nftnl_set_element_alloc error:");
			ret = -1;
			goto out;
	    }
	    nftnl_set_elem_set(element, NFTNL_SET_ELEM_KEY, &saddr, sizeof(saddr));
	    nftnl_set_elem_add(set, element);
	}

	/* add in the batch only if op is not empty;
		NFT_MSG_NEWSETELEM is idempotent if NLM_F_EXCL is not set */
	if (num_blocks) {
		header = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_NEWSETELEM, family,
					NLM_F_CREATE | NLM_F_ACK, seq++);
		nftnl_set_elems_nlmsg_build_payload(header, block_set);
		mnl_nlmsg_batch_next(batch);
	}

	/* use destroy instead of delete if idempotent delete (success even if nonexist) */
	#ifndef NFT_MSG_DESTROYSETELEM
	#define NFT_MSG_DESTROYSETELEM 30
	#endif
	if (num_unblocks) {
		header = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					NFT_MSG_DESTROYSETELEM, family, NLM_F_ACK, seq++);
		nftnl_set_elems_nlmsg_build_payload(header, unblock_set);
		mnl_nlmsg_batch_next(batch);
	}

	/* envelop end */
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

	/* send the batch to netfilter */
	ret = send_to_netfilter(batch);
	if (ret) {
		fprintf(stderr, "%s: send_to_netfilter failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	if (buf) free(buf);
	nftnl_set_free(block_set);
	nftnl_set_free(unblock_set);
    mnl_nlmsg_batch_stop(batch);
    return ret;
}

/* add element */
int netfilter_op(struct ip_batch *op_arr, int num)
{
// FIXME: EVAL 
//	return 0;
	return netfilter_element_op(table_name, set_name, op_arr, num);
}

/*
	create table, set, base chain, rule;
	creating tables is idempotent;
	rule is not: if called twice then two handles are allocated with two
		identical rules; (e.g., multiple @nh,96,32 @blocklist_set drop)
*/
int netfilter_init(void) {
	int ret = 0;
	uint32_t family = NFPROTO_INET;
	uint32_t seq;
	uint16_t flags = NLM_F_CREATE | NLM_F_ACK;

	struct nlmsghdr *header = NULL;
	struct mnl_nlmsg_batch *batch = NULL;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	/* netfilter structure variables */
	struct nftnl_table *table = NULL;
	struct nftnl_set *set = NULL;
	struct nftnl_chain *chain = NULL;
	struct nftnl_rule *rule = NULL, *del_rule = NULL;
	struct nftnl_expr *expr_payload = NULL,
					  *expr_lookup = NULL,
					  *expr_immediate = NULL;

	/*	build table */
	table = nftnl_table_alloc();
	if (!table) {
		perror("nftnl_table_alloc error:");
		ret = -1;
		goto out;
	}
	nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, family);
	nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

	/* build set to compare against */
	set = nftnl_set_alloc();
	if (!set) {
		perror("nftnl_set_alloc error:");
		ret = -1;
		goto out;
	}
	nftnl_set_set_str(set, NFTNL_SET_TABLE, table_name);
	nftnl_set_set_str(set, NFTNL_SET_NAME, set_name);
	nftnl_set_set_u32(set, NFTNL_SET_FAMILY, family);
	nftnl_set_set_u32(set, NFTNL_SET_KEY_LEN, sizeof(uint32_t));
	/* nftables/include/datatypes.h: TYPE_IPADDR for blocklist */
	nftnl_set_set_u32(set, NFTNL_SET_KEY_TYPE, 7);
	nftnl_set_set_u32(set, NFTNL_SET_ID, 1);

	/* build chain */
	chain = nftnl_chain_alloc();
	if (!chain) {
		perror("nftnl_chain_alloc error:");
		ret = -1;
		goto out;
	}
	nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, table_name);
	nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name);
	nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
	/* hook to input: incoming network packets to the node */
	nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);
	/* priority: lower number higher prio */
	nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 0);
	/* default type: filter (filter packets), other types are nat & route */
	nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "filter");
	/* default verdict applied to packets: defines the policy when a packet
	pass through all rules in a chain without triggering a match, then the 
	policy below determines if accept or drop; default policy is accept */
	nftnl_chain_set_u32(chain, NFTNL_CHAIN_POLICY, NF_ACCEPT);

	/* build rule to delete if exists */
	del_rule = nftnl_rule_alloc();
	if (!del_rule) {
		perror("nftnl_rule_alloc error:");
		ret = -1;
		goto out;
	}
	nftnl_rule_set_str(del_rule, NFTNL_RULE_TABLE, table_name);
	nftnl_rule_set_str(del_rule, NFTNL_RULE_CHAIN, chain_name);
	nftnl_rule_set_u32(del_rule, NFTNL_RULE_FAMILY, family);

	/* build rule */
	rule = nftnl_rule_alloc();
	if (!rule) {
		perror("nftnl_rule_alloc error:");
		ret = -1;
		goto out;
	}
	nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name);
	nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);
	nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, family);
	/* 
	nf_tables subsystem is implementing a virtual machine of low-level
	expressions that operates on network packets

	Table: namespace for chains
	Chains: a container for rules, may attach to a netfilter hook in kernel (base chain)
	Rule: a container for expressions
	Expressions: nftables VM code instruction	

	basic logic from documentation:
	for each rule in a chain:
		for each low level expression in the rule:
			evaluate the packet against the expression
		evaluate the expression return code (break, continue, drop, accept, etc)

	Think on these low level expressions as assembly-like instructions:
		nft_immediate: loads an immediate value into a register;
		nft_cmp: compare a given data with data from a given register;
		nft_payload: set/get arbitrary data from packet headers
		nft_bitwise: perform bitwise math operations over data in a given register
		nft_byteorder: perform byte order operations over data in a given register
		nft_counter: a basic counter for packet/bytes that gets incremented everything
				is evaluated for a packet
		nft_meta: set/get packet metadata, such as related interfaces, timestamps, etc
		nft_lookup: search for data from a given register (key) into a dataset.
				if the set is a map/vmap, returns the valuefor that key.

	blocklist expressions logic:
		1. payload: load the source address from IP header into register 1
		2. lookup: check register 1 against the blocklist_set; if not a member, stop; if a member, continue;
		3. immediate: issue the drop verdict
	*/
	
	/* add payload expr to the rule */
	expr_payload = nftnl_expr_alloc("payload");
	if (!expr_payload) {
		perror("nftnl_expr_alloc(payload) error:");
		ret = -1;
		goto out;
	}
	/* starting protocol layer, LL, NETWORK, TRANSPORT */
	nftnl_expr_set_u32(expr_payload, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
	/* retrieve packet data and put into destination register 1 */
	nftnl_expr_set_u32(expr_payload, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
	/* byte offset of a payload data inside a network packet header */
	nftnl_expr_set_u32(expr_payload, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, saddr));
	/* length of the packet data being extracted */
	nftnl_expr_set_u32(expr_payload, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
	nftnl_rule_add_expr(rule, expr_payload);
	
	/* add lookup expr to the rule */
	expr_lookup = nftnl_expr_alloc("lookup");
	if (!expr_lookup) {
		perror("nftnl_expr_alloc(lookup) error:");
		ret = -1;
		goto out;
	}
	/* set the name of the set to check against */
	nftnl_expr_set_str(expr_lookup, NFTNL_EXPR_LOOKUP_SET, set_name);
	/* match NFTNL_SET_ID */
	nftnl_expr_set_u32(expr_lookup, NFTNL_EXPR_LOOKUP_SET_ID, 1);
	/* specify the source register: the register that contains the search key
		being passed to a named set */
	nftnl_expr_set_u32(expr_lookup, NFTNL_EXPR_LOOKUP_SREG, NFT_REG_1);
	nftnl_rule_add_expr(rule, expr_lookup);
	
	/* add immediate expr to the rule: 
	store constant data into a register or trigger an immediate
	action on a packet: accept or drop */
	expr_immediate = nftnl_expr_alloc("immediate");
	nftnl_expr_set_u32(expr_immediate, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(expr_immediate, NFTNL_EXPR_IMM_VERDICT, NF_DROP);
	nftnl_rule_add_expr(rule, expr_immediate);
	

	/* Now build a batch of netlink messages and send to netfilter kernel module

	   Starting value, time(NULL) is better than 0
	   bcz seq 0 sometimes treated as "no sequence / unsolicited message" 

	   In a batch of netlink messages, each message carries an incrementing seq number,
	   including both the envelop markers and the payloads.
	*/
	seq = time(NULL);

	/* start a batch: batch several messages into one single datagram */
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

	/* envelop marker begin */
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	/* build table header and payload */
	header = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE,
				family, flags, seq++);
	nftnl_table_nlmsg_build_payload(header, table);
	mnl_nlmsg_batch_next(batch);

	/* build set header and payload */
	header = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWSET,
				family, flags, seq++);
	nftnl_set_nlmsg_build_payload(header, set);
	mnl_nlmsg_batch_next(batch);

	/* build chain header and payload */
	header = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWCHAIN,
				family,	flags, seq++);
	nftnl_chain_nlmsg_build_payload(header, chain);
	mnl_nlmsg_batch_next(batch);

	/* build rule header and payload */
	header = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_DELRULE,
				family,	NLM_F_ACK, seq++);
	nftnl_rule_nlmsg_build_payload(header, del_rule);
	mnl_nlmsg_batch_next(batch);

	/* build rule header and payload */
	header = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE,
				family,	flags, seq++);
	nftnl_rule_nlmsg_build_payload(header, rule);
	mnl_nlmsg_batch_next(batch);

	/* envelop marker end */
	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	/* send the batch to netfilter */
	ret = send_to_netfilter(batch);
	if (ret) {
		fprintf(stderr, "send_to_netfilter failed\n");
		goto out;
	}

out:
	/* release the batch */
	mnl_nlmsg_batch_stop(batch);

	nftnl_table_free(table);
	nftnl_set_free(set);
	nftnl_chain_free(chain);
	/* apparently it also frees all the exprs attached to the rule */
	nftnl_rule_free(rule);
	nftnl_rule_free(del_rule);

	return ret;
}

/*
int main(int argc, char **argv) {
	int ret = 0;

	netfilter_init();

	char *ips[] = { "1.2.3.4", "5.6.7.8", "2.3.4.5", "6.7.8.9" };
	struct ip_batch ops[4] = { 0 };

	int i;
	for (i = 0; i < 4; i++) {
//		ops[i].op = (i % 2)? OP_BLOCK : OP_UNBLOCK;
//		ops[i].op = OP_UNBLOCK;
//		ops[i].op = OP_BLOCK;
//		strcpy(ops[i].ip_addr, ips[i]);
	}

	netfilter_op(ops, 4);
	return 0;
}
*/
