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
        #if os(Linux)
        let dataBytes = [UInt8](data)
        let signedBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: 73)
        let signedBytesLength = UnsafeMutablePointer<UInt32>.allocate(capacity: 1)
        defer {
            signedBytes.deallocate()
            signedBytesLength.deallocate()
        }
        ECDSA_sign(0, dataBytes, Int32(dataBytes.count), signedBytes, signedBytesLength, privateKey.nativeKey)
        return Data(bytes: signedBytes, count: Int(signedBytesLength.pointee))
        #else
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256((data as NSData).bytes, CC_LONG(data.count), &hash)
        let digestData = Data(bytes: hash)
        
        var error: Unmanaged<CFError>? = nil
        guard let cfSignature = SecKeyCreateSignature(privateKey.nativeKey, .ecdsaSignatureMessageX962SHA256, digestData as CFData, &error)  else {
            let thrownError = error?.takeRetainedValue()
            print(thrownError as Any)
            return nil
        }
        let signature = cfSignature as Data
        let (asnSig, _) = toASN1Element(data: signature)
        guard case let ASN1Element.seq(elements: seq) = asnSig,
            seq.count >= 2,
            case let ASN1Element.bytes(data: rData) = seq[0],
            case let ASN1Element.bytes(data: sData) = seq[1]
        else {
                return nil
        }
        let rExtra = rData.count - 32
        let trimmedRData = rData.dropFirst(rExtra)
        let sExtra = sData.count - 32
        let trimmedSData = sData.dropFirst(sExtra)
        let rsSignature = trimmedRData + trimmedSData
        return rsSignature
        #endif
    }
    
    // Verify the signature using the given public key.
    public static func verifySignature(digestData: Data, signatureData: Data, publicKey: PublicKey) -> Bool {
        #if os(Linux)
        let dataBytes = [UInt8](digestData)
        let signatureBytes = [UInt8](signatureData)
        let verify = ECDSA_verify(0, dataBytes, Int32(dataBytes.count), signatureBytes, Int32(signatureBytes.count), publicKey.nativeKey)
        return verify == 1
        #else
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256((digestData as NSData).bytes, CC_LONG(digestData.count), &hash)
        let digestData = Data(bytes: hash)
        
        var error: Unmanaged<CFError>? = nil
        if SecKeyVerifySignature(publicKey.nativeKey,
                                 .ecdsaSignatureMessageX962SHA256,
                                 digestData as CFData,
                                 signatureData as CFData,
                                 &error)
        {
            return true
        } else {
            let thrownError = error?.takeRetainedValue()
            print(thrownError as Any)
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
                seq.count > 3,
                case let ASN1Element.bytes(data: privateKeyData) = seq[1],
                case let ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
                case let ASN1Element.bytes(data: publicKeyData) = publicElement else {
                    return nil
            }
            
            let keyData = publicKeyData.drop(while: { $0 == 0x00}) + privateKeyData
            guard let nativeKey = CryptorECDSA.PrivateKey.keyDataToNativeKey(key: keyData) else {
                return nil
            }
            self.nativeKey = nativeKey
        }
        
        public init?(pemKey: String) {
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
            guard let nativeKey = CryptorECDSA.PrivateKey.keyDataToNativeKey(key: keyData) else {
                return nil
            }
            self.nativeKey = nativeKey
        }
        
        private static func keyDataToNativeKey(key: Data) ->  NativeKey? {
            #if os(Linux)
            // This is not currently producing a working ecKey.
            // Investigate using EC_KEY_oct2priv()
            let keyBytes = [UInt8](key)
            let privateKeyBigNum = BN_new()
            BN_bin2bn(keyBytes, Int32(keyBytes.count), privateKeyBigNum)
            let eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
            EC_KEY_set_private_key(eckey, privateKeyBigNum)
            return eckey
            #else
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(key as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
                else {
                    let thrownError = error?.takeRetainedValue()
                    print(thrownError as Any)
                    return nil
            }
            return secKey
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
            guard let nativeKey = CryptorECDSA.PublicKey.keyDataToNativeKey(key: keyData) else {
                return nil
            }
            self.nativeKey = nativeKey
        }
        
        private static func keyDataToNativeKey(key: Data) ->  NativeKey? {
            #if os(Linux)
            // This is not currently producing a working ecKey
            // Investigate using EC_KEY_oct2key()
            let ecGroup = EC_GROUP_new_by_curve_name(NID_secp256k1)
            let eckey = EC_KEY_new_by_curve_name(NID_secp256k1)
            let ecPoint = EC_POINT_new(ecGroup)
            let bigNumCtx = BN_CTX_new()
            let keyBytes = [UInt8](key)
            EC_POINT_oct2point(ecGroup, ecPoint, keyBytes, keyBytes.count, bigNumCtx)
            EC_KEY_set_public_key(eckey, ecPoint)
            return eckey
            #else
            var error: Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(key as CFData,
                                                    [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits: 256] as CFDictionary, &error)
                else {
                    let thrownError = error?.takeRetainedValue()
                    print(thrownError as Any)
                    return nil
            }
            return secKey
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
            if (length < 8) {
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
            .filter({ $0.hasPrefix("-----") == false })
            .joined(separator: "")
        guard let asn1 = Data(base64Encoded: base64) else {
            return nil
        }
        return asn1
    }
}
