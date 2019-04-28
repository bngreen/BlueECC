
import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
import CommonCrypto
import Security
#elseif os(Linux)
import OpenSSL
#endif


@available(OSX 10.13, *)
public class ECDHKeyExchange { 

    private let privateKey : ECPrivateKey;
    public var hashEngine = ECHashEngine.sha256;

    public convenience init(for curve: EllipticCurve = .secp521r1) throws {
        self.init(key: try ECPrivateKey.make(for: curve));
    }
    public init(key: ECPrivateKey) {
        privateKey = key;
    }

    public func deriveKey(peerKey: ECPublicKey) -> Data {
        #if os(Linux)
            let ec_group = EC_KEY_get0_group(privateKey.nativeKey)
            let skey_len = Int((EC_GROUP_get_degree(ec_group) + 7) / 8)
            let symKey = UnsafeMutablePointer<UInt8>.allocate(capacity: skey_len)
            defer {
                #if swift(>=4.1)
                symKey.deallocate()
                #else
                symKey.deallocate(capacity: skey_len)
                #endif
            }
            ECDH_compute_key(symKey, skey_len, EC_KEY_get0_public_key(peerKey.nativeKey), privateKey.nativeKey, nil);
            return hashEngine.digest(data: Data(bytes: symKey, count: skey_len));
        #else
            return hashEngine.digest(data: SecKeyCopyKeyExchangeResult(privateKey.nativeKey, .ecdhKeyExchangeStandard, peerKey.nativeKey, [:] as CFDictionary, nil)! as Data)
        #endif
    }

}