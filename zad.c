// Jarosław Kadecki 332771

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>

#include <pthread.h>
#include <time.h>

// DEFINES

#define MAX_UINT 0xFFFFFFFF
#define BUFFSIZE 30
#define TRANSFER_RECORD_SIZE 9
#define TRANSFER_IP_OFFSET 0
#define TRANSFER_CIDR_OFFSET 4
#define TRANSFER_DISTANCE_OFFSET 5
#define ROUND 2
#define TILL_UNREACHABLE 6
#define TILL_REMOVED ROUND*8 
#define INFINITE_DISTANCE 16
#define PRINTINFO if(0)
// STRUCTURES

struct VECTOR_RECORD 
{
    uint32_t ip_addr;
    uint8_t cidr;
    uint32_t distance;
    uint32_t via;
    time_t updated;
    struct VECTOR_RECORD* next;
};



// GLOBAL VARIABLES

static struct VECTOR_RECORD *routing_table = NULL;
static uint32_t table_size = 0;

static uint32_t my_addr_count = 0;
static char **my_addr = NULL;
static uint8_t* my_addr_cidr = NULL;
static uint32_t *neighbors_distance = NULL;
static uint32_t *neighbors_network = NULL;

static int sockfd_send;
static int sockfd_recieve;
pthread_mutex_t lock;

// USEFULL FUNCTIONS

int power(int a, int n)
{
    if(n == 0) return 1;
    return a*power(a, n-1);
}

uint32_t string_to_ip(char* buff, int len, int offset)
{
    int i = len-1;
    int exp = 0;
    int shift = 0;
    uint32_t res = 0;
    
    while(i >= offset)
    {
        if(buff[offset + i] != '\0')
        {
            while (buff[offset + i] != '.' && i >= offset)
            {
                res += ((uint32_t)(buff[offset + i]-48) * power(10, exp))<<shift;
                exp++;
                i--;
            }
        }
        // printf("i = %d res = %x\n", i, res);
        i--;
        if(buff[offset + i] != '\0') shift+=8;
        exp = 0;
    }
    return res;
}

uint32_t string_to_int(char* buff, int len, int offset)
{
    uint32_t res = 0;
    int exp = 0;
    int i = offset+len-1;
    while (i >= offset)
    {
        res += (int)(buff[i]-48)*power(10,exp);
        exp++;
        i--;
    }

    return res;
    
}


uint32_t get_mask(uint8_t cidr)
{
    uint32_t res = 0;
    uint32_t mark = 0x80000000;
    while (cidr > 0)
    {
        res |= mark;
        mark = mark>>1;
        cidr--;
    }
    return res;
}

uint32_t get_network(uint32_t ip)
{
    // printf("Getting network of: %x\n", ip);

    if(ip == 0)
    {
        return ip;
    }

    uint32_t temp;
    int one=0;
    for(int i=0 ;i< my_addr_count; i++)
    {
        temp = ip;
        temp ^= neighbors_network[i];
        one = 0;
        // printf("Comparing %x to %x\n", temp, neighbors_network[i]);
        while(temp > 0)
        {
            temp/=2;
            one++;
        }
        // printf("One is %d\n", one);
        if(32 - one >= my_addr_cidr[i]) 
        {   
            // printf("Returning %x\n", ip & get_mask(my_addr_cidr[i]));
            return ip & get_mask(my_addr_cidr[i]);
        }
    }

    return ip;
}

uint32_t network_index(uint32_t ip)
{
    for(uint32_t i=0; i<my_addr_count; i++)
    {
        if(neighbors_network[i] == ip) return i;
    }
    return my_addr_count;
}

uint32_t get_distance(uint32_t ip)
{
    if(ip == 0) return 0;
    int index = network_index(ip);
    if(index < my_addr_count)
    {
        return neighbors_distance[index];
    }

    return INFINITE_DISTANCE;
}

uint32_t in_my_addr(char *ip)
{
    struct VECTOR_RECORD *temp = routing_table;

    for(int i=0 ; i < my_addr_count; i++)
    {
        // printf("Checking if %s == %s\n", ip, my_addr[i]);
        if(strcmp(ip, my_addr[i]) == 0)
        {
            return 1;
        }
    }

    return 0;
}

uint32_t in_my_network(uint32_t ip)
{
    for(int i=0 ;i<my_addr_count; i++)
    {
        if(ip == neighbors_network[i])
        return 1;
    }

    return 0;
}

void add_record(uint32_t ip, uint8_t cidr, uint32_t distance, uint32_t via)
{
    time_t now;
    now = time(0);

    pthread_mutex_lock(&lock);

    if(routing_table == NULL)
    {
        routing_table = (struct VECTOR_RECORD*)malloc(sizeof(struct VECTOR_RECORD));
        routing_table->ip_addr = ip & get_mask(cidr);
        routing_table->cidr = cidr;
        routing_table->distance = distance;
        routing_table->via = via;
        routing_table->updated = now;
        routing_table->next = NULL;

        table_size = 1;
    }
    else
    {
        struct VECTOR_RECORD *temp = routing_table;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = (struct VECTOR_RECORD*)malloc(sizeof(struct VECTOR_RECORD));
        temp->next->ip_addr = ip & get_mask(cidr);
        temp->next->cidr = cidr;
        temp->next->distance = distance;
        temp->next->via = via;
        temp->next->updated = now;
        temp->next->next = NULL;

        table_size += 1;
    }

    pthread_mutex_unlock(&lock);

}

uint32_t is_neighbor(uint32_t ip)
{
    return network_index(ip) < my_addr_count;
}

uint32_t is_unreachable(uint32_t network)
{
    struct VECTOR_RECORD *temp = routing_table;
    while(temp != NULL)
    {
        if(temp->ip_addr == network)
        {
            if(temp->distance == INFINITE_DISTANCE)
            {
                return 1;
            }
        }
        temp = temp->next;
    }
    return 0;
}

void update_distance(uint32_t ip, uint8_t cidr, uint32_t distance, uint32_t via)
{
    pthread_mutex_lock(&lock);
    struct VECTOR_RECORD* temp = routing_table;
    int record_exists = 0; 

    PRINTINFO printf("Updating distance\n");

    while (temp != NULL)
    {


        if(temp->ip_addr == ip)
        {
            record_exists = 1;
            
            uint32_t sender_network = get_network(via);
            uint32_t sender_distance = get_distance(sender_network);
            PRINTINFO printf("From %x distance %ld\n", via, get_distance);
            PRINTINFO printf("Network %x ", temp->ip_addr);
            if(via == 0)
            {
                temp->updated = time(0);
                temp->distance = distance;
                PRINTINFO printf("IF0 forcing distance of %x to inf\n", ip);
            }
            if(ip == sender_network)
            {
                temp->updated = time(0);
                temp->distance = sender_distance;
                PRINTINFO printf("IF1 setting distance to %d\n", sender_distance);
                break;
            }
            else
            {
                if(temp->distance < sender_distance + distance)
                {
                    PRINTINFO printf("IF2a doing nothing %d < %d\n", temp->distance, sender_distance + distance);
                    break;
                }
                else if(temp->distance == sender_distance + distance)
                {
                    PRINTINFO printf("IF2aa updating time\n");
                    temp->updated = time(0);
                    break;
                }
                
                if (temp->distance > sender_distance + distance)
                {
                    PRINTINFO printf("IF2b setting distance to %d\n", sender_distance + distance);
                    temp->distance = sender_distance + distance;
                    temp->via = via;
                    temp->updated = time(0);
                    break;
                }
                
                if(distance == INFINITE_DISTANCE && temp->via == via)
                {
                    PRINTINFO printf("IF2c setting distance to %d\n", INFINITE_DISTANCE);
                    temp->distance = INFINITE_DISTANCE;
                    temp->updated = time(0);
                    break;
                }
                else if(temp->distance < sender_distance + distance && temp->via == via)
                {
                    PRINTINFO printf("IF2d setting distance to %d\n", sender_distance + distance);
                    temp->distance = sender_distance + distance;
                    temp->updated = time(0);
                    break;
                }
                
            }

        }
        temp = temp->next;
    }

    pthread_mutex_unlock(&lock);

    if(!record_exists && distance != INFINITE_DISTANCE)
    {
        PRINTINFO printf("Adding %x %d %d %x\n", ip, cidr, distance, via);
        add_record(ip, cidr, distance, via);
    }
    
}

//PRINTING

void print_table_record(struct VECTOR_RECORD *record)
{
    if(record != NULL)
    {
        printf("Time %ld ", time(0) - record->updated);
        printf("%d.%d.%d.%d/%d distance %d connected ", 
                                (record->ip_addr&0xFF000000)>>24,
                                (record->ip_addr&0xFF0000)>>16,
                                (record->ip_addr&0xFF00)>>8,
                                (record->ip_addr&0xFF),
                                record->cidr,
                                record->distance);
        if(record->via == 0)
        {
            printf("directly\n");
        }
        else
        {
            printf("via %d.%d.%d.%d\n",
                                (record->via&0xFF000000)>>24,
                                (record->via&0xFF0000)>>16,
                                (record->via&0xFF00)>>8,
                                (record->via&0xFF));
        }

    }
}

void print_table()
{
    struct VECTOR_RECORD *temp = routing_table;
    printf("\n");
    while (temp != NULL)
    {
        print_table_record(temp);
        temp = temp->next;
    }
    printf("\n");

    fflush(stdout);
    
}

// READING INPUT

void read_input()
{
    scanf("%d", &my_addr_count);
    my_addr = malloc(sizeof(char*) * my_addr_count);
    my_addr_cidr = malloc(sizeof(char) * my_addr_count);
    neighbors_network = malloc(sizeof(uint32_t) * my_addr_count);
    neighbors_distance = malloc(sizeof(uint32_t) * my_addr_count);


    char buff[BUFFSIZE];
    uint8_t ip_len;
    uint8_t cidr_len;
    uint8_t distance_len;

    fgets(buff, BUFFSIZE, stdin);

    for(int i=0; i<my_addr_count; i++)
    {
        fgets(buff, BUFFSIZE, stdin);
        ip_len = (uint8_t)(strchr(buff, '/') - buff);
        cidr_len = (uint8_t)(strchr(buff, ' ') - buff - ip_len - 1);
        distance_len = (uint8_t)(strchr(buff, '\n') - strchr(buff, 'e') - 2);

        my_addr[i] = malloc(sizeof(char) * (ip_len+1));
        strncpy(my_addr[i],buff, ip_len);
        //my_addr[i][ip_len] = '\n';
        my_addr_cidr[i] = (uint8_t)string_to_int(buff, cidr_len, ip_len+1);
        neighbors_network[i] = string_to_ip(buff, ip_len, 0) & get_mask(my_addr_cidr[i]);
        neighbors_distance[i] = string_to_int(buff, distance_len, (uint8_t)(strchr(buff, 'e')-buff) + 2);
        add_record(
            string_to_ip(buff, ip_len, 0),
            my_addr_cidr[i],
            neighbors_distance[i],
            0);
    }
}

// SENDING PACKAGE

ssize_t fill_message(char* message)
{
    struct VECTOR_RECORD* temp = routing_table;

    ssize_t i = 0;
    while(temp != NULL)
    {
        // printf("Adding to message %x %d %d\n", htonl(temp->ip_addr), temp->cidr, htonl(temp->distance));
        *(uint32_t*)(message + i + TRANSFER_IP_OFFSET) = htonl(temp->ip_addr);
        *(message + i + TRANSFER_CIDR_OFFSET) = (char)temp->cidr;
        *(uint32_t*)(message + i + TRANSFER_DISTANCE_OFFSET) = htonl(temp->distance);
        temp = temp->next;
        i += TRANSFER_RECORD_SIZE;
        
    }
    return i;
}

int send_table(int sockfd)
{
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}

	struct sockaddr_in dest_address;
    char* message = malloc(TRANSFER_RECORD_SIZE * table_size);
    char network_string[20];

    for(int i=0; i<my_addr_count; i++)
	{
        bzero (&dest_address, sizeof(dest_address));
        dest_address.sin_family      = AF_INET;
        dest_address.sin_port        = htons(54321);
        sprintf(network_string, "%d.%d.%d.%d",
                                (neighbors_network[i]&0xFF000000)>>24,
                                (neighbors_network[i]&0xFF0000)>>16,
                                (neighbors_network[i]&0xFF00)>>8,
                                (neighbors_network[i]&0xFF));
        inet_pton(AF_INET, network_string, &dest_address.sin_addr);
    
        ssize_t message_len = TRANSFER_RECORD_SIZE * table_size;
        ssize_t filled = fill_message(message);
        if(  filled != message_len)
        {
            printf("Fill message error, message_len is %d but filled %d.\n", message_len, filled);
        }

        static int error = 0;

        if (sendto(sockfd, message, message_len, 0, (struct sockaddr*) &dest_address, sizeof(dest_address)) != message_len) {
            if(error == 0)
            {
                update_distance(neighbors_network[i], my_addr_cidr[i], INFINITE_DISTANCE, 0);
                fprintf(stderr, "sendto error: %s\n", strerror(errno));
                error = 1;
                return EXIT_FAILURE;
            }	
        }
        else if(error)
        {
            error = 0;
            update_distance(neighbors_network[i], my_addr_cidr[i], neighbors_distance[i], 0);
        }
    }

    free(message);

	return EXIT_SUCCESS;
}

void* monitor_sending()
{

    while (1)
    {
        send_table(sockfd_send);
        sleep(ROUND);
    }

    
}

// monitoring unreachable networks

void look_for_unreachable()
{
    pthread_mutex_lock(&lock);
    struct VECTOR_RECORD* temp = routing_table;
    struct VECTOR_RECORD* prev = NULL;
    int changed = 0;
    time_t now = time(0);

    while(temp != NULL)
    {
        if(temp->distance > INFINITE_DISTANCE)
        {
            temp->distance = INFINITE_DISTANCE;     
        }

        if(temp->updated + TILL_UNREACHABLE < now && temp->distance != INFINITE_DISTANCE)
        {
            changed = 1;
            temp->distance = INFINITE_DISTANCE;
        }

        if(temp->distance == INFINITE_DISTANCE && in_my_network(temp->ip_addr) && temp->via != 0)
        {
            temp->via = 0;
        }

        if(temp->updated + TILL_REMOVED < now && !in_my_network(temp->ip_addr) && temp->distance == INFINITE_DISTANCE)
        {
            prev->next = temp->next;
            table_size -= 1;
        }
        prev = temp;
        temp = temp->next;
    }
    pthread_mutex_unlock(&lock);
    if(changed)
    {
        send_table(sockfd_send);
    }
}

void* monitor_unreachable()
{
    while(1)
    {
        sleep(ROUND);
        look_for_unreachable();
        print_table();
    }
}

// reacieving package
uint32_t sender_distance(char ip_string[20])
{
    uint32_t sender_network = get_network(string_to_ip(ip_string, strlen(ip_string), 0));
    uint32_t my_ip;
    for(int i=0; i<my_addr_count; i++)
    {
        my_ip = string_to_ip(my_addr[i], strlen(my_addr[i])-1, 0);
        if(neighbors_network[i] == sender_network)
        {
            return neighbors_distance[i];
        }
    }

    return INFINITE_DISTANCE;
}

void recieve_tables()
{
    struct sockaddr_in server_address;
	bzero (&server_address, sizeof(server_address));
	server_address.sin_family      = AF_INET;
	server_address.sin_port        = htons(54321);
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind (sockfd_recieve, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
		fprintf(stderr, "bind error: %s\n", strerror(errno)); 
	}

    struct sockaddr_in 	sender;	
	socklen_t 			sender_len = sizeof(sender);
	u_int8_t 			buffer[IP_MAXPACKET+1];

    fd_set descriptor_set;

    uint32_t curr_ip;
    uint8_t curr_cidr;
    uint32_t curr_dist;

	while (1)
    {
        memset(buffer, '\0', 20);
        FD_ZERO(&descriptor_set);
        FD_SET(sockfd_recieve, &descriptor_set);
        int ready = select(sockfd_recieve+1, &descriptor_set, NULL, NULL, NULL);
		
        if(ready != -1)
		{
            ssize_t datagram_len = recvfrom (sockfd_recieve, buffer, IP_MAXPACKET, 0, (struct sockaddr*)&sender, &sender_len);
            if (datagram_len < 0) {
                fprintf(stderr, "recvfrom error: %s\n", strerror(errno)); 
            }


            char sender_ip_str[20];
            
            inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
            for(ssize_t i=0; i<datagram_len; i += TRANSFER_RECORD_SIZE)
            {
                if(!in_my_addr(sender_ip_str))
                {
                    curr_ip = ntohl(*(uint32_t*)(buffer+i));
                    curr_cidr = *(buffer + i + TRANSFER_CIDR_OFFSET);
                    curr_dist =  ntohl(*(uint32_t*)(buffer + i + TRANSFER_DISTANCE_OFFSET));
                    update_distance(curr_ip, curr_cidr, curr_dist, string_to_ip(sender_ip_str,strlen(sender_ip_str),0));
                }
            }
        }
        else
        {
            printf("Select error\n");
        }
	}
}

int main()
{
    // reading initial data
    read_input();
    print_table();

    // setting up sender thread
    sockfd_send = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd_send < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
	}
    int broadcast_enable = 1;
    if(setsockopt(sockfd_send, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) == -1)
    {
        fprintf(stderr, "could not enable broadcast. Error: %s\n", strerror(errno));
    }
    pthread_t sender_thread;
    pthread_create(&sender_thread, NULL, &monitor_sending, NULL);

    // setting up monitoring thread
    pthread_t unreachable_monitor_thread;
    pthread_create(&unreachable_monitor_thread, NULL, &monitor_unreachable, NULL); 

    // recieving
    sockfd_recieve = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd_send < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
	}
    recieve_tables();

    pthread_join(sender_thread, NULL);
    pthread_join(unreachable_monitor_thread, NULL);

    return 0;
}
