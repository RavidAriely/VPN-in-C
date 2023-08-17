
#include <linux/if_tun.h> 	/* IFF_TUN, IFF_NO_PI  */
#include <linux/if.h>	  	/* struct ifreq ifr 	*/
#include <sys/ioctl.h>	  	/* ioctl 		*/
#include <fcntl.h>		/* open		*/
#include <sys/socket.h>	/* socket		*/
#include <arpa/inet.h>	  	/* inet_addr		*/
#include <openssl/ssl.h>  	/* open ssl		*/
#include <unistd.h>		/* close, read		*/
#include <sys/select.h> 	/* select 		*/
#include <string.h>		/* strcmp 		*/
#include <strings.h>		/* bzero		*/
#include <signal.h>		/* SIGINT handler	*/
#include <limits.h>		/* PATH_MAX		*/

/*********** COMPILE WITH -lssl -lcrypto ************/
/************* RUN THE PROGRAM WITH SUDO ************/

#define MTU 1400
#define BUFF_SIZE 1500
#define MIN_PORT 1024
#define MAX_PORT 65535

static volatile int loop_stopper = 1;
static char server_ip[128] = {'\0'};
static int server_port = 0;
static char ca_crt_path[256] = {'\0'};

/* Function:  ReadCAPath 
 * --------------------
 *   reads path to CA certificate file from a configuration file
 *
 *   file: pointer to opened configuration file
 *
 *   returns: 0 on success, -1 if CA path not found
 */
int ReadCAPath(FILE *file) 
{
    char line[256] = {'\0'};
    char ca_path[256]= {'\0'}; 
    char real_ca_path[PATH_MAX];

    while (fgets(line, sizeof(line), file)) 
    {
        if (1 == sscanf(line, "CA Path: %255s", ca_path)) 
        {
        	if(NULL == realpath(ca_path, real_ca_path))
        	{
        		return -1;
        	}
		strncpy(ca_crt_path, ca_path, sizeof(ca_crt_path) - 1);
		return 0; 
        }
    }
    
    return -1; 
}

/* Function:  ValidateIPAddress 
 * --------------------
 *   validates an IP address string
 *
 *   ip: pointer to IP address string
 *
 *   returns: 0 if IP address is valid, -1 otherwise
 */
int ValidateIPAddress(const char *ip)
{
	int i = 0;
	int num = 0;
	char *part = NULL;
	char copy_ip[128] = {'\0'};
	
	strncpy(copy_ip, ip, sizeof(copy_ip));
	part = strtok(copy_ip, ".");

	for(i = 0; i < 4; i++)
	{
		if(!part || 1 != sscanf(part, "%d", &num) || 0 > num || 255 < num)
		{
			return -1;
		}
		
		part = strtok(NULL, ".");
	}
	
	if(part)
	{
		return -1;
	}
	
	return 0;
}

/* Function:  ReadServerIP 
 * --------------------
 *   reads server IP address from a configuration file
 *
 *   file: pointer to opened configuration file
 *
 *   returns: 0 on success, -1 if server IP not found/invalid	
 */
int ReadServerIP(FILE *file) 
{
	char line[256] = {'\0'};
	char ip_value[128] = {'\0'};

	while (fgets(line, sizeof(line), file)) 
	{
		if (1 == sscanf(line, "Server IP: %127s", ip_value)) 
		{
	    		if (0 == ValidateIPAddress(ip_value)) 
	    		{
				strncpy(server_ip, ip_value, sizeof(server_ip) - 1);
				return 0; 
	    		} 
	    		else 
	    		{
				return -1; 
	    		}
		}
	}

	return -1; 
}

/* Function:  ValidatePort 
 * --------------------
 *   validates a port number
 *
 *   port: port number
 *
 *   returns: 0 if port is valid, -1 otherwise
 */
int ValidatePort(int port)
{
	if (MIN_PORT > port || MAX_PORT < port)
	{
		return -1;
	}
	return 0;
}

/* Function:  ReadServerPort 
 * --------------------
 *   reads server port from a configuration file
 *
 *   file: pointer to opened configuration file
 *
 *   returns: 0 on success, -1 if server port not found/invalid		
 */
int ReadServerPort(FILE *file) 
{
	char line[256] = {'\0'};
	int port_value = 0;

	while (fgets(line, sizeof(line), file)) 
	{
		if (sscanf(line, "Server Port: %d", &(port_value)) == 1 && server_port == 0) 
		{
	    		if (0 == ValidatePort(port_value)) 
	    		{
				server_port = port_value;
				return 0; 
	    		} 
	    		else 
	    		{
				return -1; 
	    		}
		}
	}

	return -1; 
}

/* Function:  ReadConfigFile 
 * --------------------
 *   reads configuration file and extracts server IP, port, and CA certificate path information
 *
 *   filename: file to be read
 *
 *   returns: 0 on success, -1 if server IP/port/CA path not found/invalid
 */
int ReadConfigFile(const char *filename) 
{
	int ip_result = 0;
	int port_result = 0;
	int ca_path_result = 0;
	FILE *file = fopen(filename, "r");
	if (NULL == file) 
	{
		return -1; 
	}

	ip_result = ReadServerIP(file);
	port_result = ReadServerPort(file);
	ca_path_result = ReadCAPath(file); 

	fclose(file);

	if (0 != ip_result || 0 != port_result || 0 != ca_path_result) 
	{
		return -1; 
	}

	return 0; 
}

/* Function:  CreateVirtualNIC 
 * --------------------
 *   creates new virtual NIC (TUN device)
 *
 *   returns: file descriptor for TUN device
 */
int CreateVirtualNIC()
{
	struct ifreq ifr;
	char *dev = "tun0";
	char cmd[1024] = {'\0'};
	int err = 0;
	int file_desc = 0;
	
	system("sudo ip tuntap add mode tun tun0");
	
	file_desc = open("/dev/net/tun", O_RDWR); /* open device for read & write */
	if (0 > file_desc)
	{
		return file_desc;
	}

	memset(&ifr, 0, sizeof(ifr));  /* fill ifr struct with 0's */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  /* IFF_NO_PI - IP version is derived from first byte of the packet. IFF_TUN - tell the kernel we want a TUN device */
	strncpy(ifr.ifr_name, dev, IFNAMSIZ); /* IFNAMSIZ - size of device name (16) */

	err = ioctl(file_desc, TUNSETIFF, &ifr); /* system call to create tun device */
	if (0 > err)
	{
		close(file_desc);
		return err;
	}
	
	snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.2/24 mtu %d up", MTU);	
	system("sudo ip link set dev tun0 up");
	
	return file_desc;
}

/* Function:  CreateTCPSSLConnection 
 * --------------------
 *   establishes TCP connection with server using SSL/TLS
 *
 *   ctx: pointer to SSL context
 *   ssl: pointer to SSL connection
 *
 *   returns: file descriptor for TCP connection
 */
int CreateTCPSSLConnection(SSL_CTX **ctx, SSL **ssl)
{
	int sockfd = 0;
	int result = 0;
	struct sockaddr_in servaddr;

	*ctx = SSL_CTX_new(TLS_client_method());
	if (*ctx == NULL) 
	{
		return -1;
	}
	
	if (1 != SSL_CTX_use_certificate_file(*ctx, ca_crt_path, SSL_FILETYPE_PEM)) 
	{
		SSL_CTX_free(*ctx);
		return -1;
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;   
	servaddr.sin_port = htons(server_port);
	servaddr.sin_addr.s_addr = inet_addr(server_ip);
	
	if (0 > (sockfd = socket(AF_INET, SOCK_STREAM, 0))) 	
	{
		SSL_CTX_free(*ctx);
		return -1;
	}
	
	*ssl = SSL_new(*ctx);
	if(NULL == *ssl)
	{
		close(sockfd);
		SSL_CTX_free(*ctx);
		return -1;
	}
	
	SSL_set_fd(*ssl, sockfd);
	
	result = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if(-1 == result)
	{
		close(sockfd);
		SSL_free(*ssl);
		SSL_CTX_free(*ctx);
		return -1;
	}
	
	result = SSL_connect(*ssl);
	if(0 > result)
	{
		close(sockfd);
		SSL_free(*ssl);
		SSL_CTX_free(*ctx);
		return -1;
	}
	
	printf("Connected to the server\n");
	return sockfd;
}

/* Function:  CloseVirtualNIC 
 * --------------------
 *   closes virtual NIC
 *
 *   virtual_nic: pointer to virtual NIC file descriptor
 *
 *   returns: no return value
 */
void CloseVirtualNIC(int *virtual_nic)
{
	close(*virtual_nic);
	system("sudo ip link delete tun0");
}

/* Function:  ClearRoutingTable 
 * --------------------
 *   clears routing table rules for the VPN tunnel
 *
 *   returns: no return value
 */
void ClearRoutingTable()
{
	char cmd[1024] = {'\0'};
	
	system("iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE");
	system("iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");
	snprintf(cmd, sizeof(cmd), "ip route del %s via %s", server_ip, server_ip);
  	system(cmd);
  	system("ip route del 0/1 dev tun0");
  	system("ip route del 128/1 dev tun0");
}

/* Function:  ModifyRoutingTable 
 * --------------------
 *   modifies the routing table to redirect traffic through the VPN tunnel
 *
 *   returns: no return value
 */
void ModifyRoutingTable()
{
	char cmd[1024] = {'\0'};
	
	system("sysctl -w net.ipv4.ip_forward=1");		/* allow forwarding */
  	system("iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE");	/* masquerade outgoing traffic - IS THIS NECCESARY???? */

  	system("iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT");	/* accept return traffic that was established by client */
  	system("iptables -I FORWARD 1 -o tun0 -j ACCEPT");
  	snprintf(cmd, sizeof(cmd), "ip route add %s via %s", server_ip, server_ip);
  	system(cmd);						/* outgoing traffic */
										/* WHAT ABOUT TRAFFIC TO THE LOCAL VLAN? IT FORWARDS EVERYTHING TO VPN??? */
  	system("ip route add 0/1 dev tun0");
  	system("ip route add 128/1 dev tun0");
}

/* Function:  max 
 * --------------------
 *   returns the maximum of two integers
 *
 *   x: first int
 *   y: second int
 *
 *   returns: maximum of x and y
 */
int max(int x, int y)
{
	if(x > y)
	{
		return x;
	}
	return y;
}

/* Function:  HandleClientToServer 
 * --------------------
 *   handles data flow from client (local machine) to server through the SSL tunnel
 *
 *   virtual_nic: file descriptor of the virtual NIC
 *   ssl        : pointer to SSL connection
 *
 *   returns: 0 on success, -1 on failure
 */
int HandleClientToServer(int virtual_nic, SSL *ssl)
{
	int ret = 0;
	char buffer[BUFF_SIZE] = {'\0'};
	
	ret = read(virtual_nic, buffer, sizeof(buffer));
	if(0 > ret)
	{
		printf("Read from tun0 failed\n");
		return -1;
	}
	
	ret = SSL_write(ssl, buffer, ret);
	if(0 >= ret)
	{
		printf("Write to socket failed\n");
		return -1;
	}
	
	bzero(buffer, sizeof(buffer));
	return 0;
}

/* Function:  HandleServerToClient 
 * --------------------
 *   handles data flow from server through SSL tunnel to local client machine
 *
 *   virtual_nic: file descriptor of the virtual NIC
 *   ssl        : pointer to SSL connection
 *
 *   returns: 0 on success, -1 on failure
 */
int HandleServerToClient(int virtual_nic, SSL *ssl)
{
	int ret = 0;
	char buffer[BUFF_SIZE] = {'\0'};
	
	ret = SSL_read(ssl, buffer, sizeof(buffer));
	if(0 >= ret)
	{
		printf("Read from socket failed\n");
		return -1;
	}
	
	ret = write(virtual_nic, (const void*)buffer, ret);
	if(-1 == ret)
	{
		printf("Write to virtual nic failed\n");
		return -1;
	}
	
	bzero(buffer, sizeof(buffer));
	return 0;
}

/* Function:  CleanUp 
 * --------------------
 *   clean up resources and terminates the program gracefully
 *
 *   virtual_nic: file descriptor of virtual NIC
 *   socket_fd:   client socket file descriptor
 *   ctx:         pointer to SSL contex
 *   ssl:         pointer to SSL connection
 *
 *   returns: no return value
 */
 void CleanUp(int virtual_nic, int socket_fd, SSL_CTX *ctx, SSL *ssl)
 {
 	CloseVirtualNIC(&virtual_nic);
 	ClearRoutingTable();
 	close(socket_fd);
 	SSL_free(ssl);
 	SSL_CTX_free(ctx);

 }

/* Function:  HandleSIGINT 
 * --------------------
 *   changes global variable to stop while loop in main
 *
 *   nothing: dummy parameter
 *
 *   returns: no return value
 */
 void HandleSIGINT(int nothing)
 {
 	loop_stopper = 0;
 }
 
int main()
{
	int virtual_nic = 0;
	int socket_fd = 0;
	int max_fdp = 0;
	fd_set r_set;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	if (0 != ReadConfigFile("client_config.txt")) 
	{
       	return -1; 
    	}
    
	virtual_nic = CreateVirtualNIC();
	if (0 > virtual_nic)
	{
		return -1;
	}

	socket_fd = CreateTCPSSLConnection(&ctx, &ssl);
	if (0 > socket_fd)
	{
		CloseVirtualNIC(&virtual_nic);
		return -1;
	}

	ModifyRoutingTable();
	
	signal(SIGINT, HandleSIGINT);

	while(loop_stopper)
	{	
		FD_ZERO(&r_set);
		FD_SET(virtual_nic, &r_set);
		FD_SET(socket_fd, &r_set);
		FD_SET(0, &r_set);
	
		max_fdp = max(virtual_nic, socket_fd);
		select(max_fdp+1, &r_set, NULL, NULL, NULL);
		
		if(FD_ISSET(virtual_nic, &r_set))
		{
			if(-1 == HandleClientToServer(virtual_nic, ssl))
			{
				close(socket_fd);
				SSL_CTX_free(ctx);
				SSL_free(ssl);
				ClearRoutingTable();
				CloseVirtualNIC(&virtual_nic);
				return -1;
			}
		}
		
		if(FD_ISSET(socket_fd, &r_set))
		{
			if(-1 == HandleServerToClient(virtual_nic, ssl))
			{
				close(socket_fd);
				SSL_CTX_free(ctx);
				SSL_free(ssl);
				ClearRoutingTable();
				CloseVirtualNIC(&virtual_nic);
				return -1;
			}
		}
	}
	
	CleanUp(virtual_nic, socket_fd, ctx, ssl);

	return 0;
}
