#include "gbn.h"

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	close(sockfd);

	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	//Setting packet state to SYN Sent
	s.state = SYN_SENT;
	printf("SYN packet sent, trying to setup connection")

	//Initializing SYN, SYN_ACK and ACK packets for 3 way handshake

	//Initiailizing SYN packet
	gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    SYN_packet->type = SYN;
    SYN_packet->seqnum = s.seqnum;
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));
    SYN_packet->checksum = checksum(SYN_packet); 


	// Initializing  SYN_ACK packet
	gbnhdr *SYN_ACK_packet = malloc(sizeof(*SYN_ACK_packet));
	memset(SYN_ACK_packet->data, '\0', sizeof(SYN_ACK_packet->data));
	struct sockaddr from;
	socklen_t from_len = sizeof(from);

	// Initializing ACK packet
	gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));
	ACK_packet->type = DATAACK;
	memset(ACK_packet->data, '\0', sizeof(ACK_packet->data));

    int attempts = 0;

    while(s.state!= CLOSED && s.state!= ESTABLISHED)
    {
    	switch(s.state);
    	{
    		case SYN_SENT:
    			if(attempts> MAX_ATTEMPTS){
    				s.state = CLOSED;
    				printf("ERROR : Max Attempts Reached. Connection Closed");
    				break;
    			}
    			else if(sendto(sockfd, SYN_packet, sizeof(*SYN_packet), 0, server, socklen)==-1){
    				s.state = CLOSED;
    				printf("ERROR SENDING SYN PACKET : Connection Closed\n");
    				break;
    			}

    			printf("SUCCESS: SYN_packet Sent\n");

    			//Now starting timer
    			alarm(TIMEOUT);
    			attempts++;

    			//Waiting to receive SYN_ACK
    			if(recvfrom(sockfd, SYN_ACK_packet, sizeof(*SYN_ACK_packet), 0, &from, &from_len) == -1 ){
    				if(errno!=EINTR){
    					printf("ERROR: TImeout occured for SYN_ACK, Connection Closed\n");
    					s.state = CLOSED;
    					break;
    				}
    			}
    			else{
    				printf("Received a packet\n");
    				printf("type: %d\tseqnum:%dchecksum(received)%dchecksum(calculated)%d\n", SYN_ACK_packet->type, SYN_ACK_packet->seqnum, SYN_ACK_packet->checksum, checksum(SYN_ACK_packet));

    				if(SYN_ACK->type == SYNACK && SYN_ACK->checksum == checksum(SYN_ACK)){
    					printf("SUCCESS: SYN_ACK Received. Connection Established\n");

    					s.state = ESTABLISHED;
						s.address = *server;
						s.sck_len = socklen;
						s.seqnum = SYN_ACK_packet ->seqnum;
						ACK_packet->seqnum = s.seqnum;
						ACK_packet->checksum = checksum(ACK_packet);
						
						//Sending ACK to complete Handshake.
						if(sendto(sockfd, ACK_packet, sizeof(*ACK_packet), 0, server, socklen) == -1){
							printf("ERROR: Unable to send ACK\n");
							s.state = CLOSED;
							break;
						}
    				}
    			}
    			break;

    			default:
    				break;

    	}

    	free(SYN_packet);
    	free(SYN_ACK_packet);
    	free(ACK_packet);
    	return (s.state == ESTABLISHED)? 0 : -1;


    }
}

int gbn_listen(int sockfd, int backlog){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	return bind(sockfd, server socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
	printf("Function : socket()");

	//Encoding the state information for the current connection
	s = *(state_t*)malloc(sizeof(s));
    s.seqnum = (uint8_t)rand();
    s.fin = false;
    s.fin_ack = false;

    s.window_size = 1;

    //setting up the timer to trigger the timeout fucntion
    signal(SIGALARM, timeout);
    //using siginterrupt to interupt the procedure when the flag arguement is true
    siginterrupt(SIGALARM,1);

    int sockfd = socket(domain, type, protocol);
    printf("Creating Socket descriptor:%d\n", sockfd);

    return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */

	return(-1);
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);
	
	
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
