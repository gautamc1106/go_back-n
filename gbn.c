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

size_t min(size_t a, size_t b) {
    return a < b ? a : b;
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
                printf("STATE: ESTABLISHED CONNECTION. SEDNING DATA\n");
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

                        DATA_packet->checksum = p_checksum(DATA_packet);

                        if (attempts > MAX_ATTEMPTS) {
                            // If the max attempts are reached
                            printf("ERROR: Max attempts are reached.\n");
                            errno = 0;
                            s.state = CLOSED;
                            break;

                        } else if (maybe_sendto(sockfd, DATA_packet, sizeof(*DATA_packet), 0, &s.address, s.sck_len) == -1) {
                            // If error in sending DATA packet due to some other reason
                            printf("ERROR: Unable to send DATA packet.\n");
                            s.state = CLOSED;
                            break;
                        }
                            // Successfully sent a DATA packet
                            printf("SUCCESS: Sent DATA packet (%d)\n", DATA_packet->seqnum);
                            printf("type: %d\t seqnum: %d\t checksum(received): %d\t checksum(calculated):%d \n", DATA_packet->type, DATA_packet->seqnum, DATA_packet->checksum, p_checksum(DATA_packet));

                            if (counter == 0) {
                                // If first packet, set time out before FIN
                                alarm(TIMEOUT);
                           }
                           unacked_packets_counter++;
                        }
                	}
                	attempts++;
             

 				while (unacked_packets_counter > 0) {
                    if (recvfrom(sockfd, ACK_packet, sizeof(*ACK_packet), 0, &client_sockaddr, &client_socklen) == -1) {
                        // If error in receiving ACK packet
                        printf("ERROR: Unable to receive ACK!\n");
                        //Checking reason for error
                        if (errno != EINTR) {
                            // Some other problem besides time out
                            printf("ERROR: Error when receiving ACK.\n");
                            s.state = CLOSED;
                            break;
                        } 
                        else {
                            printf("ERROR: Timeout when receiving ACK.\n");
                            // If time out, half the window size and start sending DATA_packet again
                            if (s.window_size > 1) {
                                printf("INFO: Window size is: %d\n", s.window_size);
                                s.window_size /= 2;
                                printf("INFO: Window size is changed to: %d\n", s.window_size);
                            }
                            break;
                        }
                    } 
                    else {
                        // If received ACK packet successfully
                        printf("SUCCESS: Received ACK packet.\n");
                        if (ACK_packet->type == DATAACK && ACK_packet->checksum == p_checksum(ACK_packet)) {
                            // If an valid DATAACK packet is received, update sequence number and amount of DATA_packet sent
                            printf("SUCCESS: Received valid DATAACK(%d).\n", (ACK_packet->seqnum));
                            int seqnum_diff = (int)ACK_packet->seqnum - (int)s.seqnum;

                            seqnum_diff =  (seqnum_diff < 0) ?  seqnum_diff + 256: seqnum_diff;
                            size_t acked_packets_num = (size_t)seqnum_diff;
                            // Track `Last ACK Received (LAR)`
                            s.seqnum = ACK_packet->seqnum;

                            size_t ACK_len = (DATALEN - DATALEN_BYTES) * acked_packets_num;
                            size_t dataSent = min(len, ACK_len);
                            len -= dataSent;
                            data_sent += dataSent;
                            attempts = 0;
                            unacked_packets_counter -= acked_packets_num;
                            (unacked_packets_counter == 0) ? alarm(0): alarm(TIMEOUT);

                            if (s.window_size < MAX_WINDOW_SIZE) {
                            	//switching to fast mode
                                s.window_size ++;
                                printf("INFO: Window size is changed to %d\n", s.window_size);
                            }
                        } 
                        else if (ACK_packet->type == FIN && ACK_packet->checksum == p_checksum(ACK_packet)) {
                            // connection closed from other end
                            printf("SUCCESS: Received a valid FIN.\n");
                            attempts = 0;
                            s.state = FIN_RCVD;
                            alarm(0);
                            break;
                        }
                        else if(ACK_packet->type == SYNACK && ACK_packet->checksum == p_checksum(ACK_packet)) {
                            printf("SUCCESS: Received valid SYNACK packet.\n");
                            ACK_SYNACK_packet->seqnum = s.seqnum;
                            ACK_SYNACK_packet->checksum = p_checksum(ACK_SYNACK_packet);
                            if (maybe_sendto(sockfd, ACK_SYNACK_packet, sizeof(*ACK_SYNACK_packet), 0, &s.address, s.sck_len) == -1) {
                                // can't send for some other reason, bail
                                printf("ERROR: Unable to send ACKSYNACK.\n");
                                s.state = CLOSED;
                                break;
                        }
                    }
                }
            }
             printf("Ending Window with %d Unacked Packets\n", unacked_packets_counter);
                break;
            case FIN_RCVD:
                printf("STATE: FIN_RCVD\n");
                gbn_close(sockfd);
                break;
            case CLOSED:
                // some error happened, bail
                printf("STATE: CLOSED\n");
                return -1;
            default:
                break;
        }
    }
    free(DATA_packet);
    free(ACK_packet);
    free(ACK_SYNACK_packet);
    return (s.state == ESTABLISHED) ? data_sent: -1;
}





ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	printf("Entering function: recv()\n");
	struct sockaddr client;
    socklen_t clientlen = sizeof(client);

	gbnhdr *data = malloc(sizeof(*data));
	memset(data->data, '\0', sizeof(data->data));

	//make the ACK packet
	gbnhdr *ACK = malloc(sizeof(*ACK));
	ACK->type = DATAACK;
	memset(ACK->data, '\0', sizeof(ACK->data));

	bool newData = false;
	size_t lenData = 0;

	//read data while checking for errors
	while (!newData && s.state == ESTABLISHED) {
		if (recvfrom(sockfd, data, sizeof(*data), 0, &client, &clientlen) == -1) {
			if (errno != EINTR) {
				s.state = CLOSED;
			}
		} 
		else {
			//data packet received
			printf("Got something\n");
			printf("%d -- %d -- %d -- %d\n", data->type, data->seqnum, data->checksum, p_checksum(data));
			if (data->type == DATA && data->checksum == p_checksum(data)) {
				if (data->seqnum == s.seqnum) {
					printf("Data packet has the correct sequence number\n");
					memcpy(&lenData, data->data, 2);
					memcpy(buf, data->data+2, lenData);
					s.seqnum = data->seqnum + (uint8_t)1;
					newData = true;
					ACK->seqnum = s.seqnum;
					ACK->checksum = p_checksum(ACK);
					if (maybe_sendto(sockfd, ACK, sizeof(*ACK), 0, &s.address, s.sck_len)==-1) {
						printf("ERROR: Unable to send ACK\n");
						s.state = CLOSED;
						break;
					}
					printf("Sent ACK(%d)\n", ACK->seqnum);
				} 
				else {
					printf("Data packet has the wrong sequence number\n");
					ACK->seqnum = s.seqnum;
					ACK->checksum = p_checksum(ACK);
					if (maybe_sendto(sockfd, ACK, sizeof(*ACK), 0, &s.address, s.sck_len)==-1) {
						printf("Could not send Data \n");
						s.state = CLOSED;
						break;
					}
					printf("Duplicate ACK sent(%d) \n", ACK->seqnum);
				}
			}
			else if (data->type == FIN  && data->checksum == p_checksum(data)) {
					printf("It's a FIN packet\n");
					s.seqnum = data->seqnum + (uint8_t)1;
					s.state = FIN_RCVD;
				}
		} 	
	}

	free(data);
	free(ACK);
	if (s.state == ESTABLISHED) {
		return lenData;
	} else if (s.state != CLOSED) {
		return 0;
	} else {
		return -1;
	}
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	printf("Entering function close()\n");

    if (s.state != FIN_RCVD) {
        s.state = FIN_SENT;
    }


	struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int attempts = 0;

    //FIN packet
    gbnhdr *FIN_packet = malloc(sizeof(*FIN_packet));
    FIN_packet->type = FIN;
    memset(FIN_packet->data, '\0', sizeof(FIN_packet->data));

    //FIN_ACK packet
    gbnhdr *FIN_ACK_packet = malloc(sizeof(*FIN_ACK_packet));
    FIN_ACK_packet->type = FINACK;
    memset(FIN_ACK_packet->data, '\0', sizeof(FIN_ACK_packet->data));

    //make space for receiving FIN packet
    gbnhdr *FIN_RCV_packet = malloc(sizeof(*FIN_RCV_packet));
    memset(FIN_RCV_packet->data, '\0', sizeof(FIN_RCV_packet->data));

    //make space for receiving FIN_ACK packet
    gbnhdr *FIN_ACK_RCV_packet = malloc(sizeof(*FIN_ACK_RCV_packet));
    memset(FIN_ACK_RCV_packet->data, '\0', sizeof(FIN_ACK_RCV_packet->data));


    while(s.state != CLOSED ){
        switch (s.state){
            //receive finack, update state established
            case FIN_SENT:

            	FIN_packet->seqnum = s.seqnum;
            	FIN_packet->checksum = p_checksum(FIN_packet);

            	if(attempts >= MAX_ATTEMPTS){
            		 printf("ERROR: max tries, change state to close. Time out: %d\n", TIMEOUT);
                    errno = 0;
                    s.state = CLOSED;
                    break;
                }
                else if(sendto(sockfd, FIN_packet, sizeof(*FIN_packet), 0, &s.address, s.sck_len) == -1){
                    printf("ERROR: send Fin fail, max try: %d !! %s\n", attempts++, strerror(errno));
                    s.state = CLOSED;
                    break;
                }

                printf("SUCCESS: Sent FIN\n");

                if(recvfrom(sockfd, FIN_ACK_RCV_packet, sizeof(*FIN_ACK_RCV_packet), 0, &from, &fromlen) == -1){
                    //timeout try one more time
                    if(errno != EINTR){
                        s.state = CLOSED;
                        printf("ERROR : Not time out error!\n");
                        break;
                    }
                    else{
                        printf("ERROR: Timeout\n");
                        break;
                    }
                }
                else{
                    printf("SUCCESS: Recieved Something for FIN.\n");
                    alarm(0);
                    if(FIN_ACK_RCV_packet->type == FINACK && FIN_ACK_RCV_packet->checksum == p_checksum(FIN_ACK_RCV_packet)){
                    	printf("SUCCESS: Recevied FIN ACK packet!");
                        s.fin = true;
                        if(s.fin_ack){
                        	printf("SUCCESS: Process over. Connection closed.\n");
                        	s.state = CLOSED;
                        }
                        else{
                        s.state = FIN_WAIT;
                    }
                }
                    else if (FIN_ACK_RCV_packet->type == FIN && FIN_ACK_RCV_packet->checksum == p_checksum(FIN_ACK_RCV_packet)) {
                        printf("It's a FIN!\n");
                        s.state = FIN_RCVD;
                }
            }
                break;

                case FIN_RCVD:
                // Received a FIN from other side
                FIN_ACK_packet->seqnum = s.seqnum;
                FIN_ACK_packet->checksum = p_checksum(FIN_ACK_packet);
                if(sendto(sockfd, FIN_ACK_packet, sizeof(*FIN_ACK_packet), 0, &s.address, s.sck_len) == -1) {
                    // can't send for some reason, bail
                    printf("Couldn't send FINACK! %s\n", strerror(errno));
                } else {
                    printf("Sent FINACK!\n");
                }
                // only close the connection if this side has also done the FIN-FINACK procedure
                // otherwise send a FIN and wait for FINACK before closing
                s.fin_ack = true;
                if (s.fin) {
                    s.state = CLOSED;
                } else {
                    s.state = FIN_SENT;
                }
                break;

            case FIN_WAIT:
                if (recvfrom(sockfd, FIN_RCV_packet, sizeof(*FIN_RCV_packet), 0, &from, &fromlen) == -1) {
                    // didn't receive because of timeout or some other issue
                    // if timeout, try again
                    if(errno != EINTR) {
                        // some problem other than timeout
                        s.state = CLOSED;
                        break;
                    }
                } else {
                    printf("Got something...\n");
                    // got a FIN
                    if (FIN_RCV_packet->type == FIN && FIN_RCV_packet->checksum == p_checksum(FIN_RCV_packet)) {
                        printf("It's a FIN!\n");
                        s.seqnum = FIN_RCV_packet->seqnum + (uint8_t)1;
                        s.state = FIN_RCVD;
                    }
                }
                break;
            default:
                break;

        }
    }

    free(FIN_packet);
    free(FIN_ACK_packet);
    free(FIN_RCV_packet);
    free(FIN_ACK_RCV_packet);

    return(s.state == CLOSED ? close(sockfd) : -1);


}


int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	/*Setting packet state to SYN Sent*/
	printf("Entering Function: connect()\n");
	s.state = SYN_SENT;
	printf("Sending SYN packet, trying to setup connection\n");

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

    			printf("SUCCESS: SYN_packet sent. Waiting for SYN ACK\n");

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
    				printf("type: %d\tseqnum:%d checksum(received) %dchecksum(calculated)%d\n", SYN_ACK_packet->type, SYN_ACK_packet->seqnum, SYN_ACK_packet->checksum, p_checksum(SYN_ACK_packet));

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
    	printf("SUCESS: CONNECTED\n");
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
				printf("STATE: CLOSED. Waiting for connection.\n");

                // Check if receiving a valid SYN packet
                if (recvfrom(sockfd, SYN_packet, sizeof(*SYN_packet), 0, client, socklen) == -1 ) {
                	printf("ERROR: Unable to receive SYN.\n");
                    s.state = CLOSED;
					break;
				} 
				else {                
					printf("SUCCESS: Received Something\n");

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
                        printf("FUNCTION: gbn_accept returns socket %d.\n", sockfd);
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
