//
//  File 2.swift
//  
//
//  Created by ZHXW on 2021/8/23.
//

import Foundation

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
@_implementationOnly import CNIOBoringSSLShims
#else
import CNIOBoringSSL
import CNIOBoringSSLShims
#endif

public class CNIOCert {
    static let Country = "CN"
    static let ST = "GuangDong"
    static let L = "GuangZhou"
    static let O = "Pump Ltd"
    static let OU = "Pump Ltd"
    
    public static func generateCA() -> (NIOSSLCertificate, NIOSSLPrivateKey) {
        return _generateCA()
    }
    
    public static func generateRSAPrivateKey() -> NIOSSLPrivateKey {
        let keyPtr = _generateRSAPrivateKey()
        return NIOSSLPrivateKey.fromUnsafePointer(takingOwnership: keyPtr)
    }
    
    private static func _generateCA() -> (NIOSSLCertificate, NIOSSLPrivateKey) {
        let reqAndKey = makeCARequest()
        let req = reqAndKey.0
        let reqKey = reqAndKey.1
        
//        let crt = CNIOBoringSSL_X509_REQ_to_X509(req, 365 * 10, reqKey)
        
        let crt = CNIOBoringSSL_X509_new()
        
        let subjectName = CNIOBoringSSL_X509_REQ_get_subject_name(req)
        CNIOBoringSSL_X509_set_issuer_name(crt, subjectName)

        let notBefore = CNIOBoringSSL_ASN1_TIME_new()!
        var now = time(nil)
        CNIOBoringSSL_ASN1_TIME_set(notBefore, now)
        let notAfter = CNIOBoringSSL_ASN1_TIME_new()!
        now += 86400 * 365 * 10
        CNIOBoringSSL_ASN1_TIME_set(notAfter, now)
        CNIOBoringSSL_X509_set_notBefore(crt, notBefore)
        CNIOBoringSSL_X509_set_notAfter(crt, notAfter)
        CNIOBoringSSL_ASN1_TIME_free(notBefore)
        CNIOBoringSSL_ASN1_TIME_free(notAfter)
        
        CNIOBoringSSL_X509_set_subject_name(crt, subjectName)
        let reqPubKey = CNIOBoringSSL_X509_REQ_get_pubkey(req)
        CNIOBoringSSL_X509_set_pubkey(crt, reqPubKey)
        CNIOBoringSSL_EVP_PKEY_free(reqPubKey)
        
        
        CNIOBoringSSL_X509_REQ_free(req)
        
        /* Set version to X509v3 */
        CNIOBoringSSL_X509_set_version(crt, 2)
        
        /* Generate random 20 byte serial. */
        let serial = Int(arc4random_uniform(UInt32.max))
        CNIOBoringSSL_ASN1_INTEGER_set(CNIOBoringSSL_X509_get_serialNumber(crt), serial)

        addExtension(x509: crt!, nid: NID_subject_key_identifier, value: "hash")
        addExtension(x509: crt!, nid: NID_authority_key_identifier, value: "keyid:always,issuer")
        addExtension(x509: crt!, nid: NID_basic_constraints, value: "critical,CA:TRUE")
        addExtension(x509: crt!, nid: NID_key_usage, value: "critical,keyCertSign")
        addExtension(x509: crt!, nid: NID_ext_key_usage, value: "serverAuth")
        
        CNIOBoringSSL_X509_sign(crt!, reqKey, CNIOBoringSSL_EVP_sha256())
        
        let cert = NIOSSLCertificate.fromUnsafePointer(takingOwnership: crt!)

        let priKey = NIOSSLPrivateKey.fromUnsafePointer(takingOwnership: reqKey)
        return (cert, priKey)
    }
    
    public static func generateCert(host:String, rsaKey:NIOSSLPrivateKey, caKey: NIOSSLPrivateKey, caCert: NIOSSLCertificate) -> NIOSSLCertificate {
        
        let caPriKey = caKey._ref.assumingMemoryBound(to: EVP_PKEY.self)
        let req = CNIOBoringSSL_X509_REQ_new()
        let key:UnsafeMutablePointer<EVP_PKEY> = rsaKey._ref.assumingMemoryBound(to: EVP_PKEY.self)//generateRSAPrivateKey()
        /* Set the public key. */
        CNIOBoringSSL_X509_REQ_set_pubkey(req, key)
        /* Set the DN of the request. */
        let name = CNIOBoringSSL_X509_NAME_new()
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "SE", -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, "", -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, "", -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "Company", -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, "", -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, host, -1, -1, 0);
        CNIOBoringSSL_X509_REQ_set_subject_name(req, name)
        /* Self-sign the request to prove that we posses the key. */
        CNIOBoringSSL_X509_REQ_sign(req, key, CNIOBoringSSL_EVP_sha256())
        /* Sign with the CA. */
        let crt = CNIOBoringSSL_X509_new() // nil?
        /* Set version to X509v3 */
        CNIOBoringSSL_X509_set_version(crt, 2)
        /* Generate random 20 byte serial. */
        let serial = Int(arc4random_uniform(UInt32.max))
//        print("生成一次随机数-------")
        CNIOBoringSSL_ASN1_INTEGER_set(CNIOBoringSSL_X509_get_serialNumber(crt), serial)
//        serial = 0
        /* Set issuer to CA's subject. */
        // TODO:1125:这句也会报错！fix
        CNIOBoringSSL_X509_set_issuer_name(crt, CNIOBoringSSL_X509_get_subject_name(caCert._ref.assumingMemoryBound(to: X509.self)))
        /* Set validity of certificate to 1 years. */
        let notBefore = CNIOBoringSSL_ASN1_TIME_new()!
        var now = time(nil)
        CNIOBoringSSL_ASN1_TIME_set(notBefore, now)
        let notAfter = CNIOBoringSSL_ASN1_TIME_new()!
        now += 86400 * 365
        CNIOBoringSSL_ASN1_TIME_set(notAfter, now)
        CNIOBoringSSL_X509_set_notBefore(crt, notBefore)
        CNIOBoringSSL_X509_set_notAfter(crt, notAfter)
        CNIOBoringSSL_ASN1_TIME_free(notBefore)
        CNIOBoringSSL_ASN1_TIME_free(notAfter)
        /* Get the request's subject and just use it (we don't bother checking it since we generated it ourself). Also take the request's public key. */
        CNIOBoringSSL_X509_set_subject_name(crt, name)
        let reqPubKey = CNIOBoringSSL_X509_REQ_get_pubkey(req)
        CNIOBoringSSL_X509_set_pubkey(crt, reqPubKey)
        CNIOBoringSSL_EVP_PKEY_free(reqPubKey)

        // 满足iOS13要求. See https://support.apple.com/en-us/HT210176
        addExtension(x509: crt!, nid: NID_basic_constraints, value: "critical,CA:FALSE")
        addExtension(x509: crt!, nid: NID_ext_key_usage, value: "serverAuth,OCSPSigning")
        addExtension(x509: crt!, nid: NID_subject_key_identifier, value: "hash")
        addExtension(x509: crt!, nid: NID_subject_alt_name, value: "DNS:" + host)

        /* Now perform the actual signing with the CA. */
        CNIOBoringSSL_X509_sign(crt, caPriKey, CNIOBoringSSL_EVP_sha256())
        CNIOBoringSSL_X509_REQ_free(req)

        let copyCrt2 = CNIOBoringSSL_X509_dup(crt!)!
        let cert = NIOSSLCertificate.fromUnsafePointer(takingOwnership: copyCrt2)

        CNIOBoringSSL_X509_free(crt!)
        return cert
    }
    
    private static func randomSerialNumber() -> ASN1_INTEGER {
        let bytesToRead = 20
        let fd = open("/dev/urandom", O_RDONLY)
        precondition(fd != -1)
        defer {
            close(fd)
        }

        var readBytes = Array.init(repeating: UInt8(0), count: bytesToRead)
        let readCount = readBytes.withUnsafeMutableBytes {
            return read(fd, $0.baseAddress, bytesToRead)
        }
        precondition(readCount == bytesToRead)

        // Our 20-byte number needs to be converted into an integer. This is
        // too big for Swift's numbers, but BoringSSL can handle it fine.
        let bn = CNIOBoringSSL_BN_new()
        defer {
            CNIOBoringSSL_BN_free(bn)
        }
        
        _ = readBytes.withUnsafeBufferPointer {
            CNIOBoringSSL_BN_bin2bn($0.baseAddress, $0.count, bn)
        }

        // We want to bitshift this right by 1 bit to ensure it's smaller than
        // 2^159.
        CNIOBoringSSL_BN_rshift1(bn, bn)

        // Now we can turn this into our ASN1_INTEGER.
        var asn1int = ASN1_INTEGER()
        CNIOBoringSSL_BN_to_ASN1_INTEGER(bn, &asn1int)

        return asn1int
    }
    
    private static func _generateRSAPrivateKey() -> UnsafeMutablePointer<EVP_PKEY> {
        let exponent = CNIOBoringSSL_BN_new()
        defer {
            CNIOBoringSSL_BN_free(exponent)
        }
        
        CNIOBoringSSL_BN_set_u64(exponent, 0x10001)
        let rsa = CNIOBoringSSL_RSA_new()!
        
        let generateRC = CNIOBoringSSL_RSA_generate_key_ex(rsa, CInt(2048), exponent, nil)
        precondition(generateRC == 1)
        
        let pkey = CNIOBoringSSL_EVP_PKEY_new()!
        let assignRC = CNIOBoringSSL_EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa)
        
        precondition(assignRC == 1)
        return pkey
    }
    
    private static func makeCARequest() -> (OpaquePointer, UnsafeMutablePointer<EVP_PKEY>) {
        let uid = UUID()
        let cnLastName = uid.uuidString.split(separator: "-")[1]
        let cn = "Pump Ltd CA \(cnLastName)"
        
        let req = CNIOBoringSSL_X509_REQ_new()
        
        let key:UnsafeMutablePointer<EVP_PKEY> = _generateRSAPrivateKey()
        /* Set the public key. */
        CNIOBoringSSL_X509_REQ_set_pubkey(req, key)
        /* Set the DN of the request. */
        let name = CNIOBoringSSL_X509_NAME_new()
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, Country, -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, ST, -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, L, -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, O, -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, OU, -1, -1, 0);
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
        CNIOBoringSSL_X509_REQ_set_subject_name(req, name)
        /* Self-sign the request to prove that we posses the key. */
        CNIOBoringSSL_X509_REQ_sign(req, key, CNIOBoringSSL_EVP_sha256())
        
        return (req!, key)
    }
    
    private static func addExtension(x509: UnsafeMutablePointer<X509>, nid: CInt, value: String) {
        var extensionContext = X509V3_CTX()
        
        CNIOBoringSSL_X509V3_set_ctx(&extensionContext, x509, x509, nil, nil, 0)
        let ext = value.withCString { (pointer) in
            return CNIOBoringSSL_X509V3_EXT_nconf_nid(nil, &extensionContext, nid, UnsafeMutablePointer(mutating: pointer))
        }!
        CNIOBoringSSL_X509_add_ext(x509, ext, -1)
        CNIOBoringSSL_X509_EXTENSION_free(ext)
    }
    
    public static func getNotAfter(cert: NIOSSLCertificate) -> Date {
        
        let notAfter = CNIOBoringSSL_X509_get0_notAfter(cert.ref)!
        let seconds = notAfter.timeSinceEpoch
        return Date(timeIntervalSince1970: TimeInterval(seconds))
    }
}

public extension NIOSSLPrivateKey {
    func toBytes() throws -> [UInt8] {
        return try self.withUnsafePrivateKeyBuffer({ Array($0) })
    }

    func withUnsafePrivateKeyBuffer<T>(_ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
        guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
            fatalError("Failed to malloc for a BIO Handler")
        }
        
        defer {
            CNIOBoringSSL_BIO_free(bio)
        }
        
        let rc = CNIOBoringSSL_i2d_PrivateKey_bio(bio, self.ref)
        guard rc == 1 else {
            let errorStack = BoringSSLError.buildErrorStack()
            throw BoringSSLError.unknownError(errorStack)
        }
        
        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)
        
        guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
            fatalError("Failed to map bytes from a private key")
        }
        
        return try body(bytes)
    }
}
