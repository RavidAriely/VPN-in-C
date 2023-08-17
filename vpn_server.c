
#include <linux/if_tun.h> 	/* IFF_TUN, IFF_NO_PI					*/
#include <linux/if.h>	  	/* struct ifreq ifr 					*/
#include <sys/ioctl.h>	  	/* ioctl 						*/
#include <fcntl.h>		/* open 						*/
#include <sys/socket.h>	/* socket						*/
#include <arpa/inet.h>		/* inet_addr 						*/
#include <openssl/ssl.h>	/* open ssl (sudo apt install openssl libssl-dev) 	*/
#include <unistd.h>		/* close 						*/
#include <errno.h>		/* perror 						*/
#include <sys/select.h> 	/* select 						*/
#include <string.h> 		/* strncmp 						*/
#include <strings.h>		/* bzero 						*/
#include <signal.h>		/* SIGINT hanldler 					*/
#include <stdio.h>		/* sprintf 						*/
#include <limits.h> 		/* PATH_MAX						*/
#include <unistd.h>  		/* realpath						*/ 

#define MTU 1400
#define BUFF_SIZE 1500

static volatile int loop_stopper = 1;
static int port = 0;
static char interface[15] = {'\0'};
static char server_cert_path[256] = {'\0'};
static char server_key_path[256] = {'\0'};

/************ COMPILE WITH -lssl -lcrypto ************/
/************* RUN THE PROGRAM WITH SUDO *************/

/* Function:  ReadServerKeyPath 
 * --------------------
 *   reads path to server's private key from a configuration file
 * 
 *   file: pointer to opened configuration file
 *
 *   returns: 0 if private key path is found and stored, -1 otherwise 
 */
int ReadServerKeyPath(FILE *file)
{
    char line[256] = {'\0'};
    char key_path[256] = {'\0'}; 

    while (fgets(line, sizeof(line), file))
    {
        if (1 == sscanf(line, "Server Private Key: %255s", key_path))
        {
		strncpy(server_key_path, key_path, sizeof(server_key_path) - 1);
		return 0;
        }
    }

    return -1;
}

/* Function:  ReadServerCertPath 
 * --------------------
 *   reads path to server's certificate from a configuration file
 * 
 *   file: pointer to opened configuration file
 *
 *   returns: 0 if certificate path is found and stored, -1 otherwise 
 */
int ReadServerCertPath(FILE *file)
{
    char line[256] = {'\0'};
    char cert_path[256] = {'\0'}; 
    char resolved_path[PATH_MAX] = {'\0'};

    while (fgets(line, sizeof(line), file))
    {
        if (1 == sscanf(line, "Server Certificate: %255s", cert_path))
        {
        	if(NULL == realpath(cert_path, resolved_path))
        	{
        		return -1;
        	}
        	
		strncpy(server_cert_path, cert_path, sizeof(server_cert_path) - 1);
		return 0;
        }
    }

    return -1;
}

/* Function:  ReadInterface 
 * --------------------
 *   reads the network interface from a configuration file
 * 
 *   file: pointer to opened configuration file
 *
 *   returns: 0 if interface is found, -1 otherwise
 */
int ReadInterface(FILE *file)
{
	char line[256] = {'\0'};

	while(fgets(line, sizeof(line), file))
	{
		if(1 == sscanf(line, "Network Interface: %14s", interface))
		{
			return 0;
		}
	}
	
	return -1;
}

/* Function:  ValidatePort 
 * --------------------
 *   Checks whether the provided port number falls within the valid range of 104 to 65535
 * 
 *   port: port number to be validated
 *
 *   returns: 0 if port is valid, -1 otherwise
 */
int ValidatePort(int port)
{
	if (1024 > port || 65535 < port)
	{
		return -1;
	}
	
	return 0;
}

/* Function:  ReadPort 
 * --------------------
 *   reads the server port from a configuration file 
 * 
 *   file: configuration file to be read
 *
 *   returns: 0 if port found and validated, -1 otherwise
 */
int ReadPort(FILE *file)
{
	char line[256] = {'\0'};
	int port_value = 0;
	
	while(fgets(line, sizeof(line), file))
	{
		if (sscanf(line, "Server Port: %d", &(port_value)) == 1 && port == 0) 
		{
			if(0 == ValidatePort(port_value))
			{
				port = port_value;
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
 *   reads the configuration file and extracts server port and network interface information
 * 
 *   filename: configuration file to be read
 *
 *   returns: 0 if port and interface found and validated, -1 otherwise
 */
int ReadConfigFile(const char *filename)
{
	int port_result = 0;
	int interface_result = 0;
	int cert_path_result = 0;
    	int key_path_result = 0;
	
	FILE *file = fopen(filename, "r");
	if(NULL == file)
	{
		return -1;
	}
	
	port_result = ReadPort(file);
	interface_result = ReadInterface(file);
	cert_path_result = ReadServerCertPath(file); 
    	key_path_result = ReadServerKeyPath(file);
	
	fclose(file);
	
	if(0 != port_result || 0 != interface_result || 0 != cert_path_result || 0 != key_path_result) 
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
	
	system("ip tuntap add mode tun tun0");
	
	file_desc = open("/dev/net/tun", O_RDWR); /* open device for read & write */
	if (0 > file_desc)
	{
		return file_desc;
	}

	memset(&ifr, 0, sizeof(ifr));		  /* fill ifr struct with 0's */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  /* IFF_NO_PI - IP version is derived from first byte of the packet. IFF_TUN - tell the kernel we want a TUN device */
	strncpy(ifr.ifr_name, dev, IFNAMSIZ); /* IFNAMSIZ - size of device name (16) */

	err = ioctl(file_desc, TUNSETIFF, &ifr); /* system call to create tun device */
	if (0 > err)
	{
		close(file_desc);
		return err;
	}
	
	snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/24 mtu %d up", MTU);
	system(cmd);
	
	system("ip link set dev tun0 up");
	
	return file_desc;
}

/* Function:  CreateTCPSSLConnection 
 * --------------------
 *   establishes TCP connection with clients using SSL
 *   
 *   ctx: pointer to SSL context
 *   ssl: pointer to SSL connection
 *
 *   returns: file descriptor for TCP connection
 */
int CreateTCPSSLConnection(SSL_CTX **ctx, SSL **ssl)
{
	int sockfd = 0;
	struct sockaddr_in servaddr;
	
	*ctx = SSL_CTX_new(TLS_server_method());
	if(NULL == *ctx)
	{
		return -1;
	}
	
	if(1 != SSL_CTX_use_certificate_file(*ctx, server_cert_path, SSL_FILETYPE_PEM))
	{
		SSL_CTX_free(*ctx);
		return -1;
	}
	
	SSL_CTX_use_PrivateKey_file(*ctx, server_key_path, SSL_FILETYPE_PEM);
	
	if (0 > (sockfd = socket(AF_INET, SOCK_STREAM, 0))) 	/* Create socket */
	{
		printf("Create socket failed\n");
		return -1;
	}

	servaddr.sin_family = AF_INET;    /* Set the address and port of the server to connect to */
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = INADDR_ANY;
	
	if(0 > (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))))
	{
		printf("Bind failed\n");
		return -1;
	}
	
	if(0 > listen(sockfd, 1))
	{
		printf("Listen failed\n");
		return -1;
	}

	return sockfd;
}

/* Function:  NAT 
 * --------------------
 *   configures Network Address Translation for routing
 *   
 *   returns: no return value
 */
void NAT()
{
	char command[256] = {'\0'};
	system("sysctl -w net.ipv4.ip_forward=1");
	snprintf(command, sizeof(command), "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", interface);
	system(command);
}

/* Function:  ClearRoutingTable 
 * --------------------
 *   clears the routing table rules for VPN tunnel
 *   
 *   returns: no return value
 */
void ClearRoutingTable()
{
	char command[256] = {'\0'};
	system("sysctl -w net.ipv4.ip_forward=1");
	snprintf(command, sizeof(command), "iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", interface);
	system(command);
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

/* Function:  AcceptConnection 
 * --------------------
 *   accepts a connection request from a client
 *
 *   socket_fd: server socket file descriptor
 *   ctx: pointer to SSL context
 *   ssl: pointer to SSL connection
 *
 *   returns: file descriptor for client connection
 */
int AcceptConnection(int socket_fd, SSL_CTX **ctx, SSL **ssl)
{
	int connfd = 0;
	int result = 0;
	int socket_flags = 0;
	socklen_t len;
	struct sockaddr_in cliaddr;
	
	len = sizeof(cliaddr);
	
	socket_flags = fcntl(socket_fd, F_GETFL, 0);
	if(0 > socket_flags)
	{
		return -1;
	}
	
	if(fcntl(socket_fd, F_SETFL, socket_flags | O_NONBLOCK) < 0)
	{
		return -1;
	}
	
	connfd = accept(socket_fd, (struct sockaddr*)&cliaddr, &len);	
	if(-1 == connfd)
	{
		return -1;
	}
	
	*ssl = SSL_new(*ctx);
	SSL_set_fd(*ssl, connfd);
	
	result = SSL_accept(*ssl);
	if(1 != result)
	{
		printf("Ssl connection failed\n");
		return -1;
	}
	
	printf("Client connection succeeded\n");
	return connfd;
}

/* Function:  HandleServerToClient 
 * --------------------
 *   handles data flow from server's SSL tunnel and forwards it to client
 *
 *   virtual_nic: file descriptor of virtual NIC
 *   ssl: pointer to SSL connection
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
		return -1;
	}
	
	ret = write(virtual_nic, (const char*)buffer, ret);
	if(-1 == ret)
	{
		printf("Failed to write to virtual nic\n");
	}
	
	bzero(buffer, sizeof(buffer));
	return 0;
}

/* Function:  HandleClientToServer 
 * --------------------
 *   handles data flow from virtual NIC and forwards it to the server through SSL tunnel
 *
 *   virtual_nic: file descriptor of virtual NIC
 *   ssl: pointer to SSL connection
 *
 *   returns: 0 on success, -1 on failure
 */
int HandleClientToServer(int virtual_nic, SSL *ssl)
{
	int ret = 0;
	ssize_t ret_write = 0;
	char buffer[BUFF_SIZE] = {'\0'};
	
	ret = read(virtual_nic, buffer, sizeof(buffer));
	if(0 > ret)
	{
		printf("Read from virtual nic failed\n");
		return -1;
	}
	
	ret_write = SSL_write(ssl, buffer, ret);
	if(0 >= ret_write)
	{
		printf("Failed to write to socket\n");
		return -1;
	}
	
	bzero(buffer, sizeof(buffer));
	return 0;
}

/* Function:  ClearVirtualNIC 
 * --------------------
 *   clears virtual NIC and associated resources
 *
 *   virtual_nic: file descriptor of virtual NIC
 *
 *   returns: no return value
 */
void ClearVirtualNIC(int virtual_nic)
{
	system("sudo ip link delete tun0");
	close(virtual_nic);
}

/* Function:  CleanUp 
 * --------------------
 *   cleans up resources and terminates the program gracefully
 *
 *   virtual_nic: file descriptor of virtual NIC
 *   socket_fd:   server socket file descriptor
 *   conn_fd:     client connection file descriptor
 *   ctx:         pointer to SSL context
 *   ssl:         pointer to SSL connection
 *
 *   returns: no return value
 */
void CleanUp(int virtual_nic, int socket_fd, int conn_fd, SSL_CTX *ctx, SSL *ssl)
{	
	ClearVirtualNIC(virtual_nic);
	ClearRoutingTable();
	close(socket_fd);
	close(conn_fd);
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
	int conn_fd = 0;
	int max_fdp = 0;
	fd_set r_set;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL ;
	
	if(0 != ReadConfigFile("server_config.txt"))
	{
		return -1;
	}

	virtual_nic = CreateVirtualNIC();
	if (0 > virtual_nic)
	{
		return -1;
	}
	
	NAT();

	socket_fd = CreateTCPSSLConnection(&ctx, &ssl);
	if (0 > socket_fd)
	{
		ClearVirtualNIC(virtual_nic);
		ClearRoutingTable();
		return -1;
	}
	
	printf("Server is up, waiting for clients...\n");
	signal(SIGINT, HandleSIGINT);
	
	while(loop_stopper)
	{
		conn_fd = AcceptConnection(socket_fd, &ctx, &ssl); 
	
		while(-1 != conn_fd)
		{
			FD_ZERO(&r_set);
			FD_SET(virtual_nic, &r_set);
			FD_SET(conn_fd, &r_set);
			
			max_fdp = max(virtual_nic, conn_fd);
			select(max_fdp+1, &r_set, NULL, NULL, NULL);
			
			if(FD_ISSET(virtual_nic, &r_set))
			{
				if(-1 == HandleClientToServer(virtual_nic, ssl))
				{
					 break;
				}	
			}
			
			if(FD_ISSET(conn_fd, &r_set))
			{	
				if(-1 == HandleServerToClient(virtual_nic, ssl))
				{
					break;
				}
			}
		}
	}
	
	CleanUp(virtual_nic, socket_fd, conn_fd, ctx, ssl);
	
	return 0;
}
