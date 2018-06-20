#include "fbonitas.h"

int archivo(){
  unsigned char trama[1514],MACorigen[6],MACdestino[6],iporigen[4],ipdestino[4];
  unsigned char netmask[4], iprouter[4];
  int packet_socket,indice,i;
  FILE * f ;
  char nombre[20];
  do {
    printf("\nIntroduzca el nombre del archivo: ");
    fflush(stdin);
    getchar();
    fgets(nombre,19,stdin);
    printf("%s",nombre);
    f=fopen("nombre","r");
    if(f==NULL)
    perror("Archivo inexistente" );
  } while(f==NULL);

	packet_socket=socket(AF_PACKET, SOCK_RAW,htons(ETH_P_ALL));
	if(packet_socket==-1){
		perror("\nERROR al abrir socket");
		exit(0);
	}
	else{
		perror("\nExito al abrir el socket");
		indice=obtenerDatos(packet_socket,MACorigen,iporigen,netmask);
    if(inred(iporigen,ipdestino,netmask)){
      estructuraTramaARP(trama,MACorigen,iporigen,ipdestino);
      enviarTrama(packet_socket,indice,trama,ipdestino);
      recibeTramaARP(packet_socket,trama,MACorigen,MACdestino,iporigen,ipdestino);
    }
    else{
      for(i=0;i<4;i++){
        iprouter[i]=iporigen[i]&netmask[i];
      }
      iprouter[3]=1;
      estructuraTramaARP(trama,MACorigen,iporigen,iprouter);
      enviarTrama(packet_socket,indice,trama,iprouter);
    }
  }

  close(packet_socket);
	return 0;
}

int main (void){
  char opcion;
  do {
    printf("\nTRANSFERENCIA DE ARCHIVOS\n");
    printf("1.-Elegir archivo a transferir\n2.-Salir\nOpcion: ");
    fflush(stdin);
    opcion=getchar();
    if(opcion=='1'){
      archivo();
    }
  } while(opcion!='2');
  return 0;
}
