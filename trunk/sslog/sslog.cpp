// sslog.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#pragma comment( lib, "ws2_32.lib" )
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <errno.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "syslog.h"

//#pragma comment( lib, "libmsvcrt.lib" )
#include "wingetopt.h"
#ifndef EHOSTDOWN
#define EHOSTDOWN WSAEHOSTDOWN
#endif


const char* VERSION="0.2.6";

char my_first_netmask[15];
char my_first_broadcast[15];
char my_first_ip[15];
char my_hostname[128] = "unkown-hostname";
int option;
int bSilent = 1;
//char event[25];
char identifier[6]="sslog";
//char logHost[256]="sslog";
char *logHost = NULL;
char *event = NULL;
char userName[256]="unkown";
DWORD userBuffer = 256;
char domainName[256] = "unkown";

DWORD sid_size = 256;
DWORD userNameSize = sizeof(userName);
DWORD domain_size = sizeof(domainName);
SID *sid;
SID_NAME_USE account_type;

void suppress_crash_handlers( void );
long WINAPI unhandled_exception_handler( EXCEPTION_POINTERS* p_exceptions );

void usage(void)
{
  printf(
	 "\n sslog (%s) written by scuq(at)abyle.org\n \
	 \n simple syslog client for windows \
 	 \n thx to gisle vanem for the bsd-compatible syslog client code at codeproject.com \
	 \n sends syslog in this format:  sslog;my_hostname;event;my_first_ip;my_first_netmask;my_first_broadcast;domainName;userName \
	 \nUsage: sslog [options] \n \
	 \nRecommendation: sslog -s -e [EVENT] \n \
	 \n  -s            disable silent mode, supressing output to stdout \
	 \n  -e            event string (max length 25), use -H to get my eventlist definitions \
 	 \n  -H            show predefined events \
     \n  -l            loghost, per default set to: sslog", VERSION);
  exit(0);
}

void myeventlist(void)
{
  printf("Events (max length 25):\n\
UP \n\
DOWN\n\
LOGIN\n\
LOGOUT\n\
");
     
  exit(0);
}

/*
int getuserinfo()
{
	try {
	GetUserName(userName, &userBuffer);
	return 0;
	} catch( char * str ) {
		 if (bSilent == 0)
		 {
			 std::cout << "Exception raised: " << str << '\n';
		 }
	}

}
*/

int getuserinfo()
{
    if (!GetUserName(userName, &userNameSize)) {
    //printf("User name lookup failed.\n");
    return 1;
  }
  else {
      sid = (SID*)malloc (256);
      if (!LookupAccountName (NULL, userName, sid, &sid_size,
       domainName, &domain_size, &account_type)) {
                   //fprintf (stderr, "error: lookup: %d\n", GetLastError());
                   return 2;
       } else {
                  return 0;
       }
  }
  



    //printf("User name is %s\n", domainName);
    //printf("User name is %s\n", userName);

}



int getipinfo()
{
    
    SOCKET sd = WSASocket(AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    if (sd == SOCKET_ERROR) {
        //fprintf (stderr, "Failed to get a socket. Error %s\n", WSAGetLastError());
        return 1;
    }

    INTERFACE_INFO InterfaceList[20];
    unsigned long nBytesReturned;
    if (WSAIoctl(sd, SIO_GET_INTERFACE_LIST, 0, 0, &InterfaceList,
			sizeof(InterfaceList), &nBytesReturned, 0, 0) == SOCKET_ERROR) {
                                   //fprintf (stderr, "Failed calling WSAIoctl: error %s\n", WSAGetLastError());
		return 1;
    }

    int nNumInterfaces = nBytesReturned / sizeof(INTERFACE_INFO);
   
    
     int i = 0;

    for (i = 0; i < nNumInterfaces; ++i) {

        SOCKADDR_IN *pAddress;
        
        pAddress = (SOCKADDR_IN *) & (InterfaceList[i].iiAddress);
        memset(&my_first_ip, 0, sizeof(my_first_ip));
        memcpy ( my_first_ip, inet_ntoa(pAddress->sin_addr), 15 );

        pAddress = (SOCKADDR_IN *) & (InterfaceList[i].iiNetmask);
        memset(&my_first_netmask, 0, sizeof(my_first_netmask));
        memcpy ( my_first_netmask, inet_ntoa(pAddress->sin_addr), 15 );

        pAddress = (SOCKADDR_IN *) & (InterfaceList[i].iiBroadcastAddress);
        memset(&my_first_broadcast, 0, sizeof(my_first_broadcast));
        memcpy ( my_first_broadcast, inet_ntoa(pAddress->sin_addr), 15 );      

        // fprintf (stderr, "IP %s\n", my_first_ip);
        if(gethostname(my_hostname, sizeof(my_hostname) - 1));
        



        u_long nFlags = InterfaceList[i].iiFlags;

        if (nFlags & IFF_UP)
           if (nFlags | IFF_POINTTOPOINT)
              if (nFlags | IFF_LOOPBACK)
                 break;
                 

                       


    }

    return 0;
}

void result (int fail, unsigned line)
{
  const char *err = syslog_strerror();

  if (fail)
       fprintf (stderr, "sslog failed at line %d: %s\n", line, err);
  else fprintf (stderr, "sslog result at line %d: %s\n", line, err[0] ? err : "<ok>");
}

void myUnexpected(void)
{
	std::cout << "...an unexpected exception....\n";
	exit(9);
}

void suppress_crash_handlers( )
{
	
  // Register our own unhandled exception handler
  // http://msdn.microsoft.com/en-us/library/ms680634(v=vs.85).aspx
  SetUnhandledExceptionFilter( unhandled_exception_handler );
 
  // Minimize what notifications are made when an error occurs
  // http://msdn.microsoft.com/en-us/library/ms680621(v=vs.85).aspx
  SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX );
 
  // When the app crashes, don't print the abort message and don't call Dr. Watson to make a crash dump.
  // http://msdn.microsoft.com/en-us/library/e631wekh(v=VS.100).aspx
  _set_abort_behavior( 0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT );
}
 
long WINAPI unhandled_exception_handler( EXCEPTION_POINTERS* p_exceptions )
{
  // Suppress C4100 Warnings unused parameters required to match the
  // function signature of the API call.
  (void*)p_exceptions;
 
  // Throw any and all exceptions to the ground.
  return EXCEPTION_EXECUTE_HANDLER;
}

int _tmain(int argc, _TCHAR* argv[])
{
	std::set_unexpected(myUnexpected);
	suppress_crash_handlers( );

	   
    //
    // option parsing
    //
		
   	if (argc == 1)
	{
		usage();
	}
    
	try {
    	while ((option = getopt(argc, argv, "?Hhse:l:")) !=  -1)
	{
		switch (option)
		{
			case 'h':
				    usage();
				    return 0;
					break;
			case 'H':
                    myeventlist();
					break;
			case 'e':
					event = _strdup(optarg);
					if (strlen(event) > 25)
					{ 
						event="event string length exceeded.";
					}
					break;	
			case 'l':
					logHost = _strdup(optarg);
					if (strlen(logHost) > 255)
					{ 
						logHost="127.0.0.1";
					}
					break;	
			case 's':
				    bSilent = 0;
					break;                    	
			default:
				usage();
                return FALSE;
                break;
		}
	}
	} catch( char * str ) {
	    
		 fprintf (stderr, "Exception raised (option parsing): %s\n", str);
		exit(3);  
   }
   
    if (bSilent == 0)
    {
       fprintf (stderr, "event: %s\n", event);
       fprintf (stderr, "loghost: %s\n", logHost);
       fprintf (stderr, "silent is: %i\n", bSilent);
    }
    //
    // end option parsing
    //    
	 
   try {
   if (!syslog_loghost(logHost))
   {
      if (bSilent == 0) {
              fprintf (stderr, "Failed to log to remote server %s; %s\n", logHost, syslog_strerror());   
      }
              exit(3);              
   }    
   } catch( char * str ) {
	    std::cout << "Exception raised: " << str << '\n';
		exit(3);  
   }
  
   // get ip address info of local computer
   int nRetValIpInfo = getipinfo();
   if (nRetValIpInfo != 0) {
      if (bSilent == 0) {
         fprintf (stderr, "get ip infos failed. %i\n", nRetValIpInfo);
      }
      exit(4);
   }
   
   int nRetValUserInfo = getuserinfo();
   if (nRetValUserInfo != 0) {
      if (bSilent == 0) {
         fprintf (stderr, "get user infos failed. %i\n", nRetValUserInfo);
      }
      exit(5);
   }
   
   // cleaning up wsa 
   WSACleanup();
   
   
   // init wsa for syslogging
   WSADATA WinsockData;
   if (WSAStartup(MAKEWORD(2, 2), &WinsockData) != 0) {
      if (bSilent == 0) {
      fprintf (stderr, "Failed to find Winsock 2.2!\n");
      }
      exit(2);
   }
   

  // send syslog
  openlog ("sslog", LOG_PID | LOG_CONS, LOG_LOCAL2);
  syslog (LOG_INFO, "%s;%s;%s;%s;%s;%s;%s;%s", identifier,my_hostname,event,my_first_ip, my_first_netmask, my_first_broadcast, domainName, userName);
  closelog();
  // close log
  
  // enable for debug
  //SLOGS (openlog ("sslog", LOG_PID | LOG_CONS, LOG_LOCAL2));
  //SLOGS (syslog (LOG_INFO, "ip %s;%s;%s;%s,%s,%s", my_hostname,my_first_ip, my_first_netmask, my_first_broadcast, domainName, userName));
  //SLOGS (closelog());


  

	return 0;
}

