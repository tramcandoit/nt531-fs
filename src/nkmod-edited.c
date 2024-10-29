#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

static struct nf_hook_ops *nf_hook_ex_ops = NULL;

static unsigned int nf_hook_ex(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *ip_hdr_ptr;
	struct tcphdr *tcp_hdr_ptr;
	struct udphdr *udp_hdr_ptr;
	//const char *blocked_ip = "10.0.145.242";
    const char *allowed_ip = "118.69.123.140"; //uit.edu.vn
	char source_ip[16];
	char destination_ip[16];

	if (!skb)
        return NF_ACCEPT;

	ip_hdr_ptr = ip_hdr(skb);
    
	// Convert source IP to string format
	snprintf(source_ip, sizeof(source_ip), "%pI4", &ip_hdr_ptr->saddr);

	// Convert destination IP to string format
    snprintf(destination_ip, sizeof(destination_ip), "%pI4", &ip_hdr_ptr->daddr);
	
    // if (strcmp(destination_ip, allowed_ip) == 0 || strcmp(source_ip, allowed_ip) == 0 || strcmp(destination_ip, "127.0.0.53") == 0){
    //     printk(KERN_INFO "Accept packet\n");
	//     return NF_ACCEPT;
    // } else{
    //     printk(KERN_INFO "Drop packet\n");
    //     return NF_DROP;
    // }

	//printk(KERN_INFO "Source IP: %s \n", source_ip);
	//printk(KERN_INFO "Destination IP: %s \n", destination_ip);

	// Compare the source IP with the blocked IP
	/*if (strcmp(source_ip, blocked_ip) != 0) {
        	printk(KERN_INFO "Packet from %s not dropped\n", source_ip);
	} else {
        	printk(KERN_INFO "Packet from %s dropped\n", source_ip);
        	return NF_DROP;  // Drop the packet if it matches the blocked IP
    	}*/

	// if (ip_hdr_ptr->protocol == 17){
	// 	udp_hdr_ptr = udp_hdr(skb);
	// 	if (ntohs(udp_hdr_ptr->dest) == 80)
	// 	{
	// 		printk(KERN_INFO "DROP UDP 80\n");
	// 		return NF_DROP;
	// 	}
	// 	else{
	// 		printk(KERN_INFO "Packet UDP not dropped\n");
	// 		return NF_ACCEPT;
	// 	}
	// } else if (ip_hdr_ptr->protocol == 6){
    //             tcp_hdr_ptr = tcp_hdr(skb);
    //             if (ntohs(tcp_hdr_ptr->dest) == 80)
    //             {
	// 		printk(KERN_INFO "DROP TCP 80\n");
    //                     return NF_DROP;
    //             }
    //             else{
	// 		printk(KERN_INFO "Packet TCP not dropped\n");
    //                     return NF_ACCEPT;
    //             }
	// } else {
	// 	printk(KERN_INFO "Packet not dropped\n");
	// 	return NF_ACCEPT;  // Accept all other packets
	// }
    	//return NF_ACCEPT;  // Accept all other packets
}

/* Được gọi khi sử dụng lệnh 'insmod' */
static int __init kmod_init(void) {
	nf_hook_ex_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_hook_ex_ops != NULL) {

		/* đây là hàm callback `nf_hook_ex` kiểu nf_hookfn - định nghĩa trong include/linux/netfilter.h, line 47
				- các tham số của hook mà người dùng định nghĩa phải khớp với kiểu nf_hookfn */ 
		nf_hook_ex_ops->hook = (nf_hookfn*)nf_hook_ex;
		
		/* Sự kiện mà hook này đăng ký  */
		//nf_hook_ex_ops->hooknum = NF_INET_PRE_ROUTING; 
        	nf_hook_ex_ops->hooknum = NF_INET_LOCAL_OUT;

		/* Chỉ xử lý các Internet (IPv4
) packet  */
		nf_hook_ex_ops->pf = NFPROTO_IPV4;

		/* Cài đặt độ ưu tiên của hook này ở mức độ cao nhất*/
		nf_hook_ex_ops->priority = NF_IP_PRI_FIRST;
		
		nf_register_net_hook(&init_net, nf_hook_ex_ops);
	}
	return 0;
}


static void __exit kmod_exit(void) {
	if(nf_hook_ex_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_hook_ex_ops);
		kfree(nf_hook_ex_ops);
	}
	printk(KERN_INFO "Exit");
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_LICENSE("GPL");