#include "gbn.h"

volatile sig_atomic_t timeout_indicator = false;

state_t s;

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t p_checksum(gbnhdr *packet)
{
	int noBytes = sizeof(packet->type) + sizeof(packet->seqnum) + sizeof(packet->data);
	int noWords = noBytes / (sizeof(uint16_t));
	uint16_t buff[noWords];
	uint16_t p_header = ((uint16_t)packet->type << 8) + ((uint16_t)packet->seqnum);
	buff[0] = p_header;
	for (int i = 1; i <= sizeof(packet->data); i++) {
		int index = (i+1)/2;
		if ((i%2)==0) {
			buff[index] = buff[index] << 8;
			buff[index] += packet->data[i-1];
		} else {
			buff[index] = packet->data[i-1];
		}
	}
	return checksum(buff, noWords);
}

void timeout(int s) {
	timeout_indicator = true;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	int attempts = 0;
    size_t data_sent = 0;

	printf("Entering Function: send()\n");
	printf("Sending data...");

	//Initialising the data packet
	gbnhdr *DATA_packet = malloc(sizeof(*DATA_packet));
	DATA_packet->type = DATA;
	memset(DATA_packet->data, '\0', sizeof(DATA_packet->data));

	//Initialising the ACK for SYN ACK if server didn't receive first one
	gbnhdr *ACK_SYNACK_packet = malloc(sizeof(*ACK_SYNACK_packet));
	ACK_SYNACK_packet->type = DATA;
	memset(ACK_SYNACK_packet->data, '\0', sizeof(ACK_SYNACK_packet->data));

	//Making space for ACK packet from server
	gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));
	memset(ACK_packet->data, '\0', sizeof(ACK_packet->data));

	// Initalizing the client socket address
    struct sockaddr client_sockaddr;
    socklen_t client_socklen = sizeof(client_sockaddr);


    int unacked_packets_counter = 0;
    size_t data_offset = 0;

    while (len > 0) {
        switch (s.state) {
            case ESTABLISHED:
                printf("STATE: ESTABLISHED CONNECTION\n");
                unacked_packets_counter = 0;
                data_offset = 0;

                for(int counter=0; counter<s.window_size; counter++){
                	size_t datalen_remained = len - (DATALEN - DATALEN_BYTES)*counter;
                	if(datalen_remained>0)
                	{
                		DATA_packet->seqnum = s.seqnum + (uint8_t)counter;
                		memset(DATA_packet->data, '\0', sizeof(DATA_packet->data)); 

                        // Calculate the DATA payload size to be sent
                        size_t data_len = min(datalen_remained, DATALEN - DATALEN_BYTES);

                        memcpy(DATA_packet->data, (uint16_t *)&data_len, DATALEN_BYTES);
                        memcpy(DATA_packet->data + DATALEN_BYTES, buf + data_sent + data_offset, data_len);
                        data_offset += data_len;

                        data_packet->checksum = checksum(data_packet);
                        
                	}
                }


	DATA_pack = 
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
	/*Setting packet state to SYN Sent*/
	printf("Entering Function: connect()\n")
	s.state = SYN_SENT;
	printf("SYN packet sent, trying to setup connection\n");

	//Initializing SYN, SYN_ACK and ACK packets for 3 way handshake

	//Initiailizing SYN packet
	gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    SYN_packet->type = SYN;
    SYN_packet->seqnum = s.seqnum;
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));
    SYN_packet->checksum = p_checksum(SYN_packet); 


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
    	switch(s.state)
    	{
    		case SYN_SENT:
    			if(attempts> MAX_ATTEMPTS){
    				s.state = CLOSED;
    				printf("ERROR : Max Attempts Reached. Connection Closed\n");
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
    				printf("type: %d\tseqnum:%dchecksum(received)%dchecksum(calculated)%d\n", SYN_ACK_packet->type, SYN_ACK_packet->seqnum, SYN_ACK_packet->checksum, p_checksum(SYN_ACK_packet));

    				if(SYN_ACK_packet->type == SYNACK && SYN_ACK_packet->checksum == p_checksum(SYN_ACK_packet)){
    					printf("SUCCESS: SYN_ACK Received. Connection Established\n");

    					s.state = ESTABLISHED;
						s.address = *server;
						s.sck_len = socklen;
						s.seqnum = SYN_ACK_packet ->seqnum;
						ACK_packet->seqnum = s.seqnum;
						ACK_packet->checksum = p_checksum(ACK_packet);
						
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
	printf("Entering Function : listen()\n");

	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	printf("Entering fucntion: bind()\n");
	/* TODO: Your code here. */
	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
	printf("Entering Function : socket()\n");

	//Encoding the state information for the current connection
	s = *(state_t*)malloc(sizeof(s));
    s.seqnum = (uint8_t)rand();
    s.fin = false;
    s.fin_ack = false;

    s.window_size = 1;

    //setting up the timer to trigger the timeout fucntion
    signal(SIGALRM, timeout);
    //using siginterrupt to interupt the procedure when the flag arguement is true
    siginterrupt(SIGALRM,1);

    int sockfd = socket(domain, type, protocol);
    printf("Creating Socket descriptor:%d\n", sockfd);

    return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */

	printf("Entering function: accept()\n");

    s.state = CLOSED;

    // Intialize SYN packet
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));

    // Initialize SYNACK packet
    gbnhdr *SYNACK_packet = malloc(sizeof(*SYNACK_packet));
    SYNACK_packet->type = SYNACK;
    memset(SYNACK_packet->data, '\0', sizeof(SYNACK_packet->data));

    // Initialize the ACK packet
    gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));

    int attempts = 0;

    while (s.state != ESTABLISHED) {
        switch (s.state) {
            case CLOSED:
				printf("STATE: CLOSED\n");

                // Check if receiving a valid SYN packet
                if (recvfrom(sockfd, SYN_packet, sizeof(*SYN_packet), 0, client, socklen) == -1 ) {
                	printf("ERROR: Unable to receive SYN.\n");
                    s.state = CLOSED;
					break;
				} 
				else {                
					printf("SUCCESS: Received SYN\n");

                    if (SYN_packet->type == SYN && SYN_packet->checksum == p_checksum(SYN_packet)) {
                        // If a valid SYN is received
                        printf("SUCCESS: Received a valid SYN_packet\n");
                        s.seqnum = SYN_packet->seqnum + (uint8_t) 1;
                        s.state = SYN_RCVD;
                    } 
                    else {
                        // If a invalid SYN is received
                        printf("ERROR: Received invalid SYN.\n");
                        s.state = CLOSED;
                    }
                }
                break;

            case SYN_RCVD:
				printf("STATE: SYN_RCVD\n");
				// Send SYNACK after a valid SYN is received

                // Set SYNACK packet's Sequence number and Checksum
                SYNACK_packet->seqnum = s.seqnum;
                SYNACK_packet->checksum = p_checksum(SYNACK_packet);

                if (attempts > MAX_ATTEMPTS) {
                    // If max handshake is reached, close the connection
                    printf("ERROR: Reached max handshakes. Closing connection...\n");
                    errno = 0;
                    s.state = CLOSED;
                    break;
                } 
                else if (sendto(sockfd, SYNACK_packet, sizeof(*SYNACK_packet), 0, client, *socklen) == -1) {
                    // If the SYNCACK is sent with error, close the connection
                    s.state = CLOSED;
                    break;
                } 
                else {
                    // If the SYNACK is sent successfully, waiting for ACK
                    printf("SUCCESS: Sent SYNACK.\n");

                    // Use timeout and handshake counter to avoid lost ACK hanging the loop
                    alarm(TIMEOUT);
                    attempts++;

                    if (recvfrom(sockfd, ACK_packet, sizeof(*ACK_packet), 0, client, socklen) == -1) {

						// If an ERROR is received
                         if(errno != EINTR) {
                            // some problem other than timeout
                            printf("ERROR: Unable to receive ACK .");
                            s.state = CLOSED;
                            break;
                        }
                    } else if (ACK_packet->type == DATAACK && ACK_packet->checksum == p_checksum(ACK_packet)) {
                        // If a valid ACK is received, change to ESTABLISHED state
                        printf("SUCCESS: Accepted a valid ACK packet.\n");
                        s.state = ESTABLISHED;
                        s.address = *client;
                        s.sck_len = *socklen;
                        printf("STATE: ESTABLISHED.\n");
                        free(SYN_packet);
                        free(SYNACK_packet);
                        free(ACK_packet);
                        printf("FUNCTION: gbn_accept returns %d.\n", sockfd);
                        return sockfd;
                    }

				}
                break;
            default:
                break;
        }
    }
    printf("Exiting function");
	return -1;
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
