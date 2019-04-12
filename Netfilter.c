#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/ip.h>             
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/netdevice.h>      
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <linux/skbuff.h> 



MODULE_LICENSE("Dual BSD/GPL");

#define MSG_SIZE 1000

static char *message;
static int message_length = 0;

static int* num_entries;

// modifiable maximum value for ip storage
int max_ip_blocks = 100;
int block_ait = 0;
int block_aot = 0;

// struct to store IP addresses and data on them
static struct ip_table
{
    char* address;
    int num_dropped;
};

static struct ip_table *table;


//Four hook option structs using two hooks

//two hooks are for filtering based on ip address
static struct nf_hook_ops incoming_IPHook_ops;
static struct nf_hook_ops outgoing_IPHook_ops;

//two hooks are for filtering indiscriminately
static struct nf_hook_ops incoming_absHook_ops; //"incoming and outgoing 'absolute hooks'
static struct nf_hook_ops outgoing_absHook_ops;
//an array of IP addresses represented as strings
char **blocked_addresses;

//a counter to help us keep track of blocked IP addresses
int counter_IP = 0;

//------------------------------------hook functions-------------------------------------

//absolute hook function
unsigned int absolute_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    return NF_DROP;								
}

//IP address hook function
unsigned int ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    int i;
    int ch = 1;
    int k;

    char source[16] = {'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0','\0', '\0', '\0', '\0', '\0', '\0'};
						
    //to access IP header
    struct iphdr* ip_header = (struct iphdr*)skb_network_header(skb);
		
    //convert to string
    snprintf(source, 16, "%pI4", &ip_header->saddr);

    //printk("SOURCE IS %s", source);

    //printk(KERN_WARNING "%s\n", "Got to 1");

    int length = strlen(table[i].address) - 1;

    for(i = 0; i < *num_entries; i++){
       ch = 1;
       for(k = 0; k < length; k++){

            if(source[k] != *(table[i].address + k)){
                  ch = 0;
                  break;
             }
       }
      if(ch != 0){
           table[i].num_dropped += 1;
           return NF_DROP;
      }
   }

  
    return NF_ACCEPT;
}

//-----traffic helper functions-----------

//register when user requests to block all traffic

static int block_all_incoming(void){
    //fill in hook ops
    incoming_absHook_ops.hook                   =       absolute_hook;
    incoming_absHook_ops.pf                     =       PF_INET;
    incoming_absHook_ops.hooknum                =       NF_INET_PRE_ROUTING;
    incoming_absHook_ops.priority               =       NF_IP_PRI_FIRST;

    //register hook	
    nf_register_net_hook(&init_net, &incoming_absHook_ops);
    return 0;
}

static int block_all_outgoing(void){
    //fill in hook ops
    outgoing_absHook_ops.hook                  =       absolute_hook;
    outgoing_absHook_ops.pf                    =       PF_INET;
    outgoing_absHook_ops.hooknum               =       NF_INET_POST_ROUTING;
    outgoing_absHook_ops.priority              =       NF_IP_PRI_FIRST;

    //register hook
    nf_register_net_hook(&init_net, &outgoing_absHook_ops);
    return 0;
}

//unregister when user requests to stop blocking traffic
static int stop_blocking_incoming(void){
    nf_unregister_net_hook(&init_net, &incoming_absHook_ops);
    return 0;
}

static int stop_blocking_outgoing(void){
    nf_unregister_net_hook(&init_net, &outgoing_absHook_ops);
    return 0;
}

//should be registered by default
static int register_ip_hook(void){
    //Fill in the hook ops for incoming traffic
    incoming_IPHook_ops.hook                   =       ip_hook;
    incoming_IPHook_ops.pf                     =       PF_INET;
    incoming_IPHook_ops.hooknum                =       NF_INET_PRE_ROUTING;
    incoming_IPHook_ops.priority               =       NF_IP_PRI_FIRST;

    //Fill in the hook ops for outgoing traffic
    outgoing_IPHook_ops.hook                   =       ip_hook;
    outgoing_IPHook_ops.pf                     =       PF_INET;
    outgoing_IPHook_ops.hooknum                =       NF_INET_POST_ROUTING;
    outgoing_IPHook_ops.priority               =       NF_IP_PRI_FIRST;

    //register hooks
    nf_register_net_hook(&init_net ,&outgoing_IPHook_ops);
    nf_register_net_hook(&init_net ,&incoming_IPHook_ops);
    return 0;
}




//---------------------------helper functions--------------------------------


// UNBLOCK IP: Method scans list of blocked IPs and removes ub_address from
//	       the list if it is found.
//             When items are removed from the array, the last ip address is
//             copied over to its spot to maintain unity, and num_entries is
//             decremented
static int unblock_ip_address(char* ub_address)
{
    int found = 0;
    int i = 0;
    while (i < max_ip_blocks) {
        if (strcmp(table[i].address, ub_address) == 0) {
	    found = 1;
	    if (*num_entries > 1) { // swap last with empty spot to maintain unity
	        strcpy(table[i].address, table[*num_entries - 1].address);
	        table[i].num_dropped = table[*num_entries - 1].num_dropped;
	    } 
	    strcpy(table[*num_entries - 1].address, ""); // delete ub_address's entry
	    table[*num_entries - 1].num_dropped = 0;
	}
	i++;
    } 
    if (found)
        *num_entries = (*num_entries) - 1;

    return 0;
}


// PARSE INPUT: Method is called whenever the proc file is written to.
// 		Scans the entry to the proc file to find which key command is
//		called. If the command allows for the blocking or unblocking
// 		of individual ip addresses, then the method either adds the 
// 		addresses to the table or removes them.
static int parse_input(char *message)
{
    char *block_ips = "bip";
    char *unblock_ips = "ubip";
    char *block_incoming = "bait";
    char *block_outgoing = "baot";
    char *unblock_incoming = "ubait";
    char *unblock_outgoing = "ubaot";
    char *param; 
 

    // Gets first command (should be one of listed above)
    char *first_cmd = strsep(&message, " ");

    if (strcmp(first_cmd, block_ips) == 0) { 
	// add all addresses to blocked list
        while ((param = strsep(&message, " ")) != NULL) {
            strcpy(table[*num_entries].address, param);
            (*num_entries)++;
        }
    } else if (strcmp(first_cmd, unblock_ips) == 0) {
	// call unblock_ip function on all addresses in command
	while ((param = strsep(&message, " ")) != NULL) {
            unblock_ip_address(param);
        }
    } else if (strcmp(first_cmd, block_incoming) == 0) {

        block_ait = 1;
	block_all_incoming();
    } else if (strcmp(first_cmd, block_outgoing) == 0) {

        block_aot = 1;
	block_all_outgoing();
    } else if (strcmp(first_cmd, unblock_incoming) == 0) {

        block_ait = 0;
	stop_blocking_incoming();
    } else if (strcmp(first_cmd, unblock_outgoing) == 0) {

        block_aot = 0;
 	stop_blocking_outgoing();
    } 
    
    return 0;
}



//---------------------------proc functions-----------------------------------


// READ_PROC: Method is called whenever the user calls cat /proc/netfilter_proc
// 	      and is the main way the program communicates with the user.
// 	      Displays the currently blocked ip addresses and how many packets 
// 	      were blocked. 
static ssize_t read_proc (struct file *filp,
			  char __user * buffer,
			  size_t length,
			  loff_t * off)
{

    int type_change_buff = 20; // for conversion

    strcpy(message, "List of currently blocked IP addresses:\n");
    int i = 0;
    while (i < *(num_entries)) { // concatenate all entries on
        message = strcat(message, table[i].address);
	message = strcat(message, ": ");

	// convert int to string for printing
   	int packets_int = table[i].num_dropped;
	char packets[type_change_buff];
	snprintf(packets, type_change_buff, "%d",packets_int);
        message = strcat(message, packets);
        message = strcat(message, " packets have been dropped.\n");
        i++;
    }
    message_length = strlen(message);
    return simple_read_from_buffer(buffer, length, off, message, message_length);
}

// Write Proc:  Callback function when user writes to proc_file
// 		The user supplies the message, which needs to be
// 		null terminated before it can be passed along to
// 		parse_input
static ssize_t write_proc (struct file *filp,
			   const char __user * buffer,
			   size_t length,
			   loff_t * off)
{
    message_length = simple_write_to_buffer(message, MSG_SIZE, off, buffer, length);
    message[message_length] = '\0';
    parse_input(message);
    
    return message_length;
}



static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = read_proc,
    .write = write_proc,
};

static int __init proc_init(void)
{
    printk(KERN_ALERT "Starting Netfilter Project");
    int i = 0;
    num_entries = kmalloc(sizeof(int), GFP_KERNEL);
    *num_entries = 0;

    table = kmalloc(max_ip_blocks * sizeof (struct ip_table), GFP_KERNEL);
    if (!table)
        return -ENOMEM;

    while (i < max_ip_blocks) {
        table[i].address = kmalloc(20 * sizeof(char), GFP_KERNEL);
        table[i].num_dropped = 0;
        strcpy(table[i].address, " ");
        i++;
    }

    //register ip hook
    register_ip_hook();

    proc_create ("netfilter_proc", 0666, NULL, &proc_fops);
    message = kmalloc (100 * sizeof (char), GFP_KERNEL);
    

    strcpy(message, "Initial content\n");
    message_length = strlen("Initial content\n");

    return 0;
}

static void __exit proc_exit(void)
{
    printk(KERN_ALERT "Stopping Netfilter Project\n");
    nf_unregister_net_hook(&init_net, &incoming_absHook_ops);
    nf_unregister_net_hook(&init_net ,&incoming_IPHook_ops);
    nf_unregister_net_hook(&init_net, &outgoing_absHook_ops);
    nf_unregister_net_hook(&init_net ,&outgoing_IPHook_ops);
    remove_proc_entry ("netfilter_proc", NULL);
    kfree(table);
}



module_init(proc_init);

module_exit(proc_exit);
