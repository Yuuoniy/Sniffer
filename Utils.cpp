//char* hexToCharIP(struct in_addr addrIP)
//{
//    char* ip;
//    unsigned int intIP;
//    memcpy(&intIP, &addrIP,sizeof(unsigned int));
//    int a = (intIP >> 24) & 0xFF;
//    int b = (intIP >> 16) & 0xFF;
//    int c = (intIP >> 8) & 0xFF;
//    int d = intIP & 0xFF;
//    if((ip = (char*)malloc(16*sizeof(char))) == NULL)
//    {
//    return NULL;
//    }
//    sprintf(ip, "%d.%d.%d.%d", d,c,b,a);
//    return ip;
//}




