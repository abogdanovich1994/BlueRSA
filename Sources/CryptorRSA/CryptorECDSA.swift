//  Copyright © 2018 IBM. All rights reserved.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.
//
import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
import CommonCrypto
#elseif os(Linux)
import OpenSSL
#endif


/// ECDSA Signing/Verification
///
@available(macOS 10.12, iOS 10.0, *)
public class CryptorECDSA {
    // Sign the data using the given private key.
    // The signature is two integers in ASN1 format
    public static func createSignature(data: Data, privateKey: PrivateKey) -> Data? {
        
        let signature: Data
        
        #if os(Linux)
        // Hash digest to 256 bytes
        var hash = [UInt8](repeating: 0, count: CC_LONG(SHA256_DIGEST_LENGTH))
        let digestContext = EVP_MD_CTX_create()
        // EVP_Digest return 1 for success or 0 for fail
        EVP_DigestInit(digestContext, EVP_sha256())
        _ = data.withUnsafeBytes { (message: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DigestUpdate(digestContext, message, data.count)
        }
        EVP_DigestFinal(digestContext, &hash, nil)
        EVP_MD_CTX_destroy(digestContext)
        
        let signedBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: 73)
        let signedBytesLength = UnsafeMutablePointer<UInt32>.allocate(capacity: 1)
        defer {
            signedBytes.deallocate()
            signedBytesLength.deallocate()
        }
        ECDSA_sign(0, hash, Int32(hash.count), signedBytes, signedBytesLength, privateKey.nativeKey)
        signature = Data(bytes: signedBytes, count: Int(signedBytesLength.pointee))
        #else
        // MacOS, iOS ect.
        
        // SHA256 Digest must be exactly 32 bytes(CC_SHA256_DIGEST_LENGTH) for asymmetric encryption.
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256((data as NSData).bytes, CC_LONG(data.count), &hash)
        let hashedData = Data(bytes: hash)
        
        // Memory storage for error from SecKeyCreateSignature
        var error: Unmanaged<CFError>? = nil
        
        // cfSignature is CFData that is ANS1 encoded as a sequence of two 32 Byte UInt (r and s)
        guard let cfSignature = SecKeyCreateSignature(privateKey.nativeKey, .ecdsaSignatureDigestX962SHA256, hashedData as CFData, &error)  else {
            let thrownError = error?.takeRetainedValue()
            print("cfSignature failed: \(thrownError as Any)")
            return nil
        }
        signature = cfSignature as Data
        #endif
        
        // Parse ASN into just r,s data as defined in:
        // https://tools.ietf.org/html/rfc7518#section-3.4
        let (asnSig, _) = toASN1Element(data: signature)
        guard case let ASN1Element.seq(elements: seq) = asnSig,
            seq.count >= 2,
            case let ASN1Element.bytes(data: rData) = seq[0],
            case let ASN1Element.bytes(data: sData) = seq[1]
        else {
            print("Failed to decode cfSignature ASN1")
            return nil
        }
        // ASN adds 00 bytes in front of negative Int to mark it as positive.
        // These must be removed to make r,a a valid EC signature
        let rExtra = rData.count - 32
        let trimmedRData = rData.dropFirst(rExtra)
        let sExtra = sData.count - 32
        let trimmedSData = sData.dropFirst(sExtra)
        return trimmedRData + trimmedSData
    }
    
    // Verify the signature using the given public key.
    public static func verifySignature(digestData: Data, signatureData: Data, publicKey: PublicKey) -> Bool {
        
        // Signature must be 64 bytes or it is invalid
        guard signatureData.count == 64 else {
            print("invalid signatureData length: \(signatureData.count)")
            return false
        }
        
        // Convert r,s signature to ASN1 for SecKeyVerifySignature
        var asnSignature = Data()
        // r value is first 32 bytes
        var rSig =  Data(signatureData.dropLast(32))
        // If first bit is 1, add a 00 byte to mark it as positive for ASN1
        if rSig[0].leadingZeroBitCount == 0 {
            rSig = Data(count: 1) + rSig
        }
        // r value is last 32 bytes
        var sSig = Data(signatureData.dropFirst(32))
        // If first bit is 1, add a 00 byte to mark it as positive for ASN1
        if sSig[0].leadingZeroBitCount == 0 {
            sSig = Data(count: 1) + sSig
        }
        // Count Byte lengths for ASN1 length bytes
        let rLengthByte = UInt8(rSig.count)
        let sLengthByte = UInt8(sSig.count)
        // total bytes is r + s + rLengthByte + sLengthByte byte + Integer marking bytes
        let tLengthByte = rLengthByte + sLengthByte + 4
        // 0x30 means sequence, 0x02 means Integer
        asnSignature.append(contentsOf: [0x30, tLengthByte, 0x02, rLengthByte])
        asnSignature.append(rSig)
        asnSignature.append(contentsOf: [0x02, sLengthByte])
        asnSignature.append(sSig)
        
        #if os(Linux)
        // Hash digest to 256 bytes
        var hash = [UInt8](repeating: 0, count: CC_LONG(SHA256_DIGEST_LENGTH))
        let digestContext = EVP_MD_CTX_create()
        // EVP_Digest return 1 for success or 0 for fail
        EVP_DigestInit(digestContext, EVP_sha256())
        _ = digestData.withUnsafeBytes { (message: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DigestUpdate(digestContext, message, digestData.count)
        }
        EVP_DigestFinal(digestContext, &hash, nil)
        EVP_MD_CTX_destroy(digestContext)
        
        let signatureBytes = [UInt8](asnSignature)
        let verify = ECDSA_verify(0, hash, Int32(hash.count), signatureBytes, Int32(signatureBytes.count), publicKey.nativeKey)
        return verify == 1
        #else
        // MacOS, iOS ect.
        
        // SHA256 Digest must be exactly 32 bytes(CC_SHA256_DIGEST_LENGTH) for asymmetric encryption.
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256((digestData as NSData).bytes, CC_LONG(digestData.count), &hash)
        let hashedData = Data(bytes: hash)
        
        // Memory storage for error from SecKeyVerifySignature
        // ecdsaSignatureDigestX962SHA256 is p-256 sha-256 ECDSA
        var error: Unmanaged<CFError>? = nil
        if SecKeyVerifySignature(publicKey.nativeKey,
                                 .ecdsaSignatureDigestX962SHA256,
                                 hashedData as CFData,
                                 asnSignature as CFData,
                                 &error) {
            return true
        } else {
            let thrownError = error?.takeRetainedValue()
            print("Failed to verify asnSignature: \(thrownError as Any)")
            return false
        }
        #endif
    }
    
    // struct to convert
    public struct PrivateKey {
        #if os(Linux)
        public typealias NativeKey = OpaquePointer?
        #else
        public typealias NativeKey = SecKey
        #endif
        let nativeKey: NativeKey
        
        public init?(p8Key: String) {
            #if os(Linux)
            self.init(pemKey: p8Key)
            #else
            guard let asn1Key = CryptorECDSA.toASN1(key: p8Key) else {
                return nil
            }
            let (result, _) = toASN1Element(data: asn1Key)
            
            guard case let ASN1Element.seq(elements: es) = result,
                es.count > 2,
                case let ASN1Element.bytes(data: privateOctest) = es[2] else {
                    return nil
            }
            let (octest, _) = toASN1Element(data: privateOctest)
            guard case let ASN1Element.seq(elements: seq) = octest,
                seq.count >= 3,
                case let ASN1Element.bytes(data: privateKeyData) = seq[1],
                case let ASN1Element.constructed(tag: _, elem: publicElement) = seq[2],
                case let ASN1Element.bytes(data: publicKeyData) = publicElement else {
                    return nil
            }
            
            let keyData = publicKeyData.drop(while: { $0 == 0x00}) + privateKeyData
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
            else {
                let thrownError = error?.takeRetainedValue()
                print(thrownError as Any)
                return nil
            }
            self.nativeKey = secKey
            #endif
        }
        
        public init?(pemKey: String) {
            #if os(Linux)
                guard let key = pemKey.data(using: .utf8) else {
                    return nil
                }
                let bio = BIO_new(BIO_s_mem())
                key.withUnsafeBytes { (bytes: UnsafePointer<Int8>) -> Void in
                    BIO_puts(bio, bytes)
                }
                let privateKey = PEM_read_bio_ECPrivateKey(bio, nil, nil, nil)
                BIO_free(bio)
                self.nativeKey = privateKey
            #else
                guard let asn1Key = CryptorECDSA.toASN1(key: pemKey) else {
                    return nil
                }
                let (result, _) = toASN1Element(data: asn1Key)
                guard case let ASN1Element.seq(elements: seq) = result,
                    seq.count > 3,
                    case let ASN1Element.bytes(data: privateKeyData) = seq[1],
                    case let ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
                    case let ASN1Element.bytes(data: publicKeyData) = publicElement else {
                        return nil
                }
            
                let keyData = publicKeyData.drop(while: { $0 == 0x00}) + privateKeyData
                var error: Unmanaged<CFError>? = nil
                guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                        [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
                else {
                    let thrownError = error?.takeRetainedValue()
                    print(thrownError as Any)
                    return nil
                }
                self.nativeKey = secKey
            #endif
        }
    }
    
    public struct PublicKey {
        #if os(Linux)
        public typealias NativeKey = OpaquePointer?
        #else
        public typealias NativeKey = SecKey
        #endif
        let nativeKey: NativeKey
        
        public init?(pemKey: String) {
            #if os(Linux)
                guard let key = pemKey.data(using: .utf8) else {
                    return nil
                }
                let bio = BIO_new(BIO_s_mem())
                key.withUnsafeBytes { (bytes: UnsafePointer<Int8>) -> Void in
                    BIO_puts(bio, bytes)
                }
                let privateKey = PEM_read_bio_EC_PUBKEY(bio, nil, nil, nil)
                BIO_free(bio)
                self.nativeKey = privateKey
            #else
                guard let asn1Key = CryptorECDSA.toASN1(key: pemKey) else {
                    return nil
                }
                let (result, _) = toASN1Element(data: asn1Key)
                guard case let ASN1Element.seq(elements: seq) = result,
                    seq.count > 1,
                    case let ASN1Element.bytes(data: publicKeyData) = seq[1] else {
                        return nil
                }
                let keyData = publicKeyData.drop(while: { $0 == 0x00})
                var error: Unmanaged<CFError>? = nil
                guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                        [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
                    else {
                        let thrownError = error?.takeRetainedValue()
                        print(thrownError as Any)
                        return nil
                }
                self.nativeKey = secKey
            #endif
        }
    }
    
    // Private and public keys are stores in ASN1 format.
    // The following code is used to parse the data and retrieve the required elements.
    
    private indirect enum ASN1Element {
        case seq(elements: [ASN1Element])
        case integer(int: Int)
        case bytes(data: Data)
        case constructed(tag: Int, elem: ASN1Element)
        case unknown
    }
    
    private static func toASN1Element(data: Data) -> (ASN1Element, Int) {
        guard data.count >= 2 else {
            // format error
            return (.unknown, data.count)
        }
        
        switch data[0] {
        case 0x30: // sequence
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            var result: [ASN1Element] = []
            var subdata = data.advanced(by: 1 + lengthOfLength)
            var alreadyRead = 0
            
            while alreadyRead < length {
                let (e, l) = toASN1Element(data: subdata)
                result.append(e)
                subdata = subdata.count > l ? subdata.advanced(by: l) : Data()
                alreadyRead += l
            }
            return (.seq(elements: result), 1 + lengthOfLength + length)
            
        case 0x02: // integer
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            if length < 8 {
                var result: Int = 0
                let subdata = data.advanced(by: 1 + lengthOfLength)
                // ignore negative case
                for i in 0..<length {
                    result = 256 * result + Int(subdata[i])
                }
                return (.integer(int: result), 1 + lengthOfLength + length)
            }
            // number is too large to fit in Int; return the bytes
            return (.bytes(data: data.subdata(in: (1 + lengthOfLength) ..< (1 + lengthOfLength + length))), 1 + lengthOfLength + length)
            
            
        case let s where (s & 0xe0) == 0xa0: // constructed
            let tag = Int(s & 0x1f)
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            let subdata = data.advanced(by: 1 + lengthOfLength)
            let (e, _) = toASN1Element(data: subdata)
            return (.constructed(tag: tag, elem: e), 1 + lengthOfLength + length)
            
        default: // octet string
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            return (.bytes(data: data.subdata(in: (1 + lengthOfLength) ..< (1 + lengthOfLength + length))), 1 + lengthOfLength + length)
        }
    }
    
    private static func readLength(data: Data) -> (Int, Int) {
        if data[0] & 0x80 == 0x00 { // short form
            return (Int(data[0]), 1)
        } else {
            let lenghOfLength = Int(data[0] & 0x7F)
            var result: Int = 0
            for i in 1..<(1 + lenghOfLength) {
                result = 256 * result + Int(data[i])
            }
            return (result, 1 + lenghOfLength)
        }
    }
    
    private static func toASN1(key: String) -> Data? {
        let base64 = key
            .split(separator: "\n")
            .map({String($0)})
            .filter({ $0.hasPrefix("-----") == false })
            .joined(separator: "")
        guard let asn1 = Data(base64Encoded: base64) else {
            return nil
        }
        return asn1
    }
}
