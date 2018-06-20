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

int obtenerDatos(int ds,unsigned char* MACorigen, unsigned char* iporigen, unsigned char* netmask);
int inred(unsigned char* iporigen, unsigned char* ipdestino, unsigned char* netmask);
void estructuraTramaARP(unsigned char *trama, unsigned char* MACorigen, unsigned char* iporigen, unsigned char* ipdestino);
void enviarTrama(int ds,int index,unsigned char *trama, unsigned char* ipdestino);
void imprimeTrama(unsigned char *trama, int tam);
int filtroARP(unsigned char* trama, unsigned char* MACorigen, unsigned char* iporigen, unsigned char* ipdestino);
int filtroLLC(unsigned char *paq,int len);
void estructuraTramaLLC(unsigned char *trama, unsigned char* MACdestino, unsigned char* MACorigen, unsigned char* longitud);
int recibeTramaLLC(int ds,unsigned char *trama);
int recibeTramaARP(int ds, unsigned char *trama,unsigned char* MACorigen, unsigned char* MACdestino, unsigned char* iporigen, unsigned char* ipdestino);
