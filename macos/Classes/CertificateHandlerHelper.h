#ifndef CertificateHandlerHelper_h
#define CertificateHandlerHelper_h
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>

int check_non_repudiation(const unsigned char *data, long length);

CFDataRef sign_data(SecKeyRef privateKey, const unsigned char *dataToSign, size_t dataLength);

#endif /* CertificateHandlerHelper_h */
