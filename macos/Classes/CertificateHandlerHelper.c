#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h> // Include this header for X509V3_EXT_d2i
#include <Security/Security.h>
#include <stdio.h>

int check_non_repudiation(const unsigned char *data, long length)
{
    const unsigned char *p = data;
    X509 *x509 = d2i_X509(NULL, &p, length);
    if (!x509)
    {
        fprintf(stderr, "Error: Failed to parse X509 certificate.\n");
        return -1; // error
    }

    int ext_loc = X509_get_ext_by_NID(x509, NID_key_usage, -1);
    X509_EXTENSION *ext = X509_get_ext(x509, ext_loc);
    if (!ext)
    {
        fprintf(stderr, "Error: Failed to get key usage extension.\n");
        X509_free(x509);
        return -1; // error
    }

    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (!ext_data)
    {
        fprintf(stderr, "Error: Failed to get extension data.\n");
        X509_free(x509);
        return -1; // error
    }

    const unsigned char *pp = ext_data->data;
    ASN1_BIT_STRING *usage = d2i_ASN1_BIT_STRING(NULL, &pp, ext_data->length);
    if (!usage)
    {
        fprintf(stderr, "Error: Failed to decode key usage extension.\n");
        X509_free(x509);
        return -1; // error
    }

    int result = ASN1_BIT_STRING_get_bit(usage, 1); // Assume zero-based indexing for bits

    ASN1_BIT_STRING_free(usage);
    X509_free(x509);
    return result;
}

CFDataRef sign_data(SecKeyRef privateKey, const unsigned char *dataToSign, size_t dataLength)
{
    CFDataRef data = CFDataCreate(NULL, dataToSign, dataLength);
    if (!data)
    {
        return NULL;
    }

    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    CFErrorRef error = NULL;
    CFDataRef signature = SecKeyCreateSignature(privateKey, algorithm, data, &error);

    CFRelease(data);

    if (error)
    {
        CFRelease(error);
        return NULL;
    }

    return signature;
}
