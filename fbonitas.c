#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <mysql/mysql.h>

int obtenerDatos(int ds,unsigned char* MACorigen, unsigned char* iporigen, unsigned char* netmask){
	char nombre[10];
	int index,i;
 	struct ifreq interfaz;
	printf("\nInserta el nombre: ");
	fgets(nombre,10,stdin);
	strcpy(interfaz.ifr_name,nombre);
	if(ioctl(ds,SIOCGIFINDEX,&interfaz)==-1){
		perror("\nError al obtener el indice");
		exit(0);
	}
	else{
		index=interfaz.ifr_ifindex;
		if(ioctl(ds,SIOCGIFHWADDR,&interfaz)==-1){
			perror("\nError al obtener la MAC");
			exit(0);
		}
		else{
			memcpy(MACorigen,interfaz.ifr_hwaddr.sa_data,6);
			printf("La MAC del dispositivo es: \n");
			for(i=0;i<5;i++){
				printf("%.2x:", MACorigen[i]);
			}
			printf("%.2x\n", MACorigen[i]);
		}
		if(ioctl(ds,SIOCGIFADDR,&interfaz)==-1){
			perror("\nError al obtener la IP");
			exit(0);
		}
		else{
			memcpy(iporigen,interfaz.ifr_addr.sa_data+2,4);
			printf("ip origen: ");
			for(i=0;i<3;i++){
				printf("%d.",iporigen[i]);
			}
			printf("%d\n",iporigen[i]);
		}
		if(ioctl(ds,SIOCGIFNETMASK,&interfaz)==-1){
			perror("\nError al obtener la mascara de subred");
			exit(0);
		}
		else{
			memcpy(netmask,interfaz.ifr_netmask.sa_data+2,4);
			printf("La mascara de subred es: \n");
			for(i=0;i<3;i++){
				printf("%d.", netmask[i]);
			}
			printf("%d\n", netmask[i]);
		}
	printf("El indice de interfaz es: %d\n",index );

	return index;
	}
}

int inred(unsigned char* iporigen, unsigned char* ipdestino, unsigned char* netmask){
  char i;
  for(i=0;i<4;i++){
    if(iporigen[i]&netmask[i]!=ipdestino[i]&netmask[i])return 0;
  }
  return 1;
}

void estructuraTramaARP(unsigned char *trama, unsigned char* MACorigen, unsigned char* iporigen, unsigned char* ipdestino){
	unsigned char thw[2]={0x00,0x01};
	unsigned char tpc[2]={0x08,0x00};
	unsigned char opcode[2]={0x00,0x01};
  unsigned char ethertype[2]={0x08,0x06};
	unsigned char* MACbroadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff}

	memcpy(trama+0,MACbroadcast,6);
	memcpy(trama+6,MACorigen,6);
	memcpy(trama+12,ethertype,2);
	memcpy(trama+14,thw,2);
	memcpy(trama+16,tpc,2);
	*(trama+18)=6;
	*(trama+19)=4;
	memcpy(trama+20,opcode,2);
	memcpy(trama+22,MACorigen,6);
	memcpy(trama+28,iporigen,4);
	memset(trama+32,0x00,6);
	memcpy(trama+38,ipdestino,4);
}

void enviarTrama(int ds,int index,unsigned char *trama, unsigned char* ipdestino){
	int tam;
	struct sockaddr_ll nic;
	memset(&nic,0x00,sizeof(nic));
	nic.sll_family=AF_PACKET;
	nic.sll_protocol=htons(ETH_P_ALL); /* Physical-layer protocol */
	nic.sll_ifindex=index;
	tam=sendto(ds,trama,60,0,(struct sockaddr *)&nic,sizeof(nic));
	if(tam==-1){
		perror("\nError al enviar\n");
		exit(0);

	}
	else
    	printf("\nEnviando trama a %d.%d.%d.%d\n",ipdestino[0],ipdestino[1],ipdestino[2],ipdestino[3]);
}

void imprimeTrama(unsigned char *trama, int tam){
	int i;
	for(i=0;i<tam;i++){
		if(i%16==0)
		printf("\n");
		printf(" %.2x",trama[i]);
	}
	printf("\n");
}

int filtroARP(unsigned char* trama, unsigned char* MACorigen, unsigned char* iporigen, unsigned char* ipdestino){
  unsigned char opcoderes[2]={0x00,0x02};
  unsigned char ethertype[2]={0x08,0x06};
  if(!memcmp(trama+0,MACorigen,6) && !memcmp(trama+12,ethertype,2)&& !memcmp(trama+20,opcoderes,2)&& !memcmp(trama+32,MACorigen,6) && !memcmp(trama+38,iporigen,4) && !memcmp(trama+28,ipdestino,4))
  return 1;
  return 0;
}

int filtroLLC(unsigned char *paq,int len)
{
int tamanio=0;
tamanio=(paq[12]<<8)+paq[13];
if(tamanio<1500)
  {
  return 1;
  }
else
  return 0;
}

void estructuraTramaLLC(unsigned char *trama, unsigned char* MACdestino, unsigned char* MACorigen, unsigned char* longitud)
{
//Encabezado MAC
memcpy(trama+0,MACdestino,6);
memcpy(trama+6,MACorigen,6);
memcpy(trama+12,longitud,2);
//Encabezado LLC
trama[14]=0xf0; //DSAP
trama[15]=0x0f; //SSAP
trama[16]=0x7f; //Control
}


int recibeTramaLLC(int ds,unsigned char *trama)
{
int tam,bandera=0;
while(1)
  {
  bandera=0;
tam=recvfrom(ds,trama,1514,0,NULL,0);
if(tam==-1)
    perror("\nError al recibir");
  else
    {
    bandera=filtroLLC(trama,tam);
    if(bandera==1)
      {
      return tam;
      }
    }
  }
}

int recibeTramaARP(int ds, unsigned char *trama,unsigned char* MACorigen, unsigned char* MACdestino, unsigned char* iporigen, unsigned char* ipdestino){
	int tam,i;
	char bandera=0;
	long mtime=0, seconds, useconds;
	struct timeval start, end;
	gettimeofday(&start, NULL);

	while(mtime<300){
		tam=recvfrom(ds,trama,1514,MSG_DONTWAIT,NULL,0);
		if(tam==-1){
			perror("\nError al recibir\n");
		}
 		else{
			if(filtroARP(trama,MACorigen,iporigen,ipdestino)){
			memcpy(MACdestino,trama+6,6);
			printf("La MAC del dispositivo objetivo es: ");
			for(i=0;i<5;i++)
				printf("%.2x:", MACdestino[i]);
			printf("%.2x\n", MACdestino[i]);
			imprimeTrama(trama,tam);
			bandera=1;
			}
		}
		gettimeofday(&end, NULL);
 		seconds  = end.tv_sec  - start.tv_sec;
 		useconds = end.tv_usec - start.tv_usec;
  		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
  		if(bandera==1)
    		break;
	}
	printf("Elapsed time: %ld milliseconds\n", mtime);
}

void checksumip(unsigned char* trama){
	unsigned short int aux=0,res=0;
	char i;
	for(i=14;i<34;i+=2){
		memcpy(&aux,trama+i,2);
		res+=aux;
	}
	res+=2;
	res=0xFFFF-res;

}
