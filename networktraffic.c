#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#define MAX_LEN       1000

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Network Traffic Module");
MODULE_AUTHOR("HoangDieu6789");

int time_interval = 1000;
void simple_timer_function(struct timer_list *);
struct timer_list simple_timer;


typedef struct monitor {
	unsigned int total_packet;
	unsigned int old_packet;
	unsigned int baud_width;
}Monitor;

Monitor Receiving = {};
Monitor Sending   = {};
/*******implement proc*************/
static ssize_t read_proc (struct file *filp, char __user * buf, size_t count, loff_t * offp)
{
	char info[MAX_LEN];
	int len=0;
	if(*offp > 0 || count < MAX_LEN)
		return 0;
	printk(KERN_INFO "Baud in proc: %d", Receiving.baud_width);
	len += sprintf( info, "Receiving baud %d byte/s\n", Receiving.baud_width);
	len += sprintf( info + len, "Total Received  %d byte\n", Receiving.total_packet);
	len += sprintf( info + len, "Sending baud %d byte/s\n", Sending.baud_width);
	len += sprintf( info + len, "Total Sent  %d byte\n", Sending.total_packet);
	if(copy_to_user(buf, info, len))
		return -EFAULT;
	*offp = len;

    return count;
}

/* static ssize_t write_proc (struct file *filp, const char __user * buf, size_t count, loff_t * offp)
{

    return count;
} */

static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = read_proc,
/*     .write = write_proc, */
};

void create_new_proc_entry (void)
{
    proc_create ("monitor_network", 0444, NULL, &proc_fops);

}

/***************netfilter***************************/
unsigned int hook_func_in(void *priv,
              struct sk_buff *skb,
              const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	if(0 == skb){
        return NF_ACCEPT;
	}
	 if (!ip_header) {
        return NF_ACCEPT;
    }
	Receiving.total_packet = Receiving.total_packet + skb->len;
	/* printk (KERN_INFO "total receive %d  sizeof packet currrent : %d\n", total_packet, skb->len); */
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_in = {
    .hook          = hook_func_in,
    .hooknum    = NF_INET_LOCAL_IN,
    .pf              = PF_INET,
    .priority       = NF_IP_PRI_FIRST,
};

unsigned int hook_func_out(void *priv,
              struct sk_buff *skb,
              const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	if(0 == skb){
        return NF_ACCEPT;
	}
	 if (!ip_header) {
        return NF_ACCEPT;
    }
	Sending.total_packet = Sending.total_packet + skb->len;
	/* printk (KERN_INFO "total sending %d  sizeof packet currrent : %d\n", Sending.total_packet, skb->len); */
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_out = {
    .hook          = hook_func_out,
    .hooknum    = NF_INET_LOCAL_OUT,
    .pf              = PF_INET,
    .priority       = NF_IP_PRI_FIRST,
};

/*************using timer*********************************/
void simple_timer_function(struct timer_list *timer)
{
	mod_timer (&simple_timer, jiffies + ( msecs_to_jiffies(time_interval)));
	/* Calculator packet Receiving*/
	Receiving.baud_width = Receiving.total_packet - Receiving.old_packet;
	Receiving.old_packet = Receiving.total_packet;
	if (1024 <= Receiving.baud_width)
	{
		printk(KERN_INFO "Receiving baud %d kb/s\n", (Receiving.baud_width / 1024));
		if (1024*1024 <= Receiving.total_packet)
		{
			printk(KERN_INFO "Total Received %d Mb\n", (Receiving.total_packet/(1024*1024)));
		} else if (1024 <= Receiving.total_packet)
		{
			printk(KERN_INFO "Total Received %d Kb\n", (Receiving.total_packet/1024));
		} else
		{
			printk(KERN_INFO "Total Received %d Byte\n", Receiving.total_packet);
		}
	} else
	{
		printk(KERN_INFO "Receiving baud %d byte/s\n", Receiving.baud_width);
		if (1024*1024 <= Receiving.total_packet)
		{
			printk(KERN_INFO "Total Received %d Mb\n", (Receiving.total_packet/(1024*1024)));
		} else if (1024 <= Receiving.total_packet)
		{
			printk(KERN_INFO "Total Received %d Kb\n", (Receiving.total_packet/1024));
		} else
		{
			printk(KERN_INFO "Total Received %d Byte\n", Receiving.total_packet);
		}
	}
	/* Calculator packet Sending*/
	Sending.baud_width = Sending.total_packet - Sending.old_packet;
	Sending.old_packet = Sending.total_packet;
	if (1024 <= Sending.baud_width)
	{
		printk(KERN_INFO "Sending baud %d kb/s\n", (Sending.baud_width / 1024));
		if (1024*1024 <= Sending.total_packet)
		{
			printk(KERN_INFO "Total Sent %d Mb\n", (Sending.total_packet/(1024*1024)));
		} else if (1024 <= Sending.total_packet)
		{
			printk(KERN_INFO "Total Sent %d Kb\n", (Sending.total_packet/1024));
		} else
		{
			printk(KERN_INFO "Total Sent %d Byte\n", Sending.total_packet);
		}
	} else
	{
		printk(KERN_INFO "Sending baud %d byte/s\n", Sending.baud_width);
		if (1024*1024 <= Sending.total_packet)
		{
			printk(KERN_INFO "Total Sent %d Mb\n", (Sending.total_packet/(1024*1024)));
		} else if (1024 <= Sending.total_packet)
		{
			printk(KERN_INFO "Total Sent %d Kb\n", (Sending.total_packet/1024));
		} else
		{
			printk(KERN_INFO "Total Sent %d Byte\n", Sending.total_packet);
		}
	}
}

static int __init init_nf(void)
{
    printk(KERN_INFO "-------------------Register Kernel Module.-------------------------\n");

    nf_register_net_hook(&init_net, &nfho_in);
	nf_register_net_hook(&init_net, &nfho_out);

    create_new_proc_entry ();
	/*Starting the timer.*/	
	timer_setup(&simple_timer,simple_timer_function,0);
	mod_timer(&simple_timer, jiffies + msecs_to_jiffies(time_interval));
	
    return 0;
}

static void __exit exit_nf(void)
{
    printk(KERN_INFO "-------------------Unregister Kernel Module.-----------------------\n");
    nf_unregister_net_hook(&init_net, &nfho_in);
	nf_unregister_net_hook(&init_net, &nfho_out);
	del_timer(&simple_timer);
    remove_proc_entry ("monitor_network", NULL);
}

module_init(init_nf);
module_exit(exit_nf);
