import Foundation
import Security

public class CertificateHandler {
    
    func getCertificates() -> [[UInt8]]? {
         var certDerList = [[UInt8]]()
    
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                kSecReturnRef as String: true,
                                kSecMatchLimit as String: kSecMatchLimitAll]
    
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
    
        guard status == errSecSuccess else {
            // Handle error
            return nil
        }
    
        let certificates = item as! Array<SecCertificate>
        for certificate in certificates {
            if let data = SecCertificateCopyData(certificate) as Data? {
                let result = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
                    guard let baseAddress = bytes.baseAddress else { return -1 }
                    return check_non_repudiation(baseAddress.assumingMemoryBound(to: UInt8.self), data.count)
                }

                if result == 1 {
                    certDerList.append([UInt8](data))
                }
            }
        }
    
        return certDerList
    }

    func signData(certificate: [Data], dataToSign: [UInt8]) -> [UInt8]? {
    if let certificateData = certificate.first,
       let privateKey = getPrivateKey(forCertificateData: certificateData) {
        let signatureDataUnmanaged = sign_data(privateKey, dataToSign, dataToSign.count)
        guard let signatureData = signatureDataUnmanaged?.takeRetainedValue() else { return nil }
        let signatureArray = Array(signatureData as Data)
        return signatureArray
    }
    return nil
    }


    func getPrivateKey(forCertificateData certificateData: Data) -> SecKey? {
    // Import certificate data into a SecCertificate
    guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
        print("Failed to create SecCertificate")
        return nil
    }
    
    // Prepare a dictionary to query the keychain for an identity
    let query: [String: Any] = [
        kSecClass as String: kSecClassIdentity,
        kSecReturnRef as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecMatchItemList as String: [certificate]
    ]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    
    guard status == errSecSuccess else {
        print("Failed to find identity: \(status)")
        return nil
    }
    
    let identity = item as! SecIdentity

    var privateKey: SecKey?
    let privateKeyStatus = SecIdentityCopyPrivateKey(identity, &privateKey)
    
    guard privateKeyStatus == errSecSuccess else {
        print("Failed to get private key: \(privateKeyStatus)")
        return nil
    }
    
    return privateKey
    }
}
