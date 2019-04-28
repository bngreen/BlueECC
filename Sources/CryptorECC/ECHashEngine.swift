import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
    import CommonCrypto
#elseif os(Linux)
    import OpenSSL
#endif

public struct ECHashEngine {


    #if os(Linux)
    typealias CC_LONG = size_t
    let hashEngine: (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?
    let hashLength: CC_LONG
    #else
    let hashEngine: (_ data: UnsafeRawPointer?, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?
    let hashLength: CC_LONG
    #endif
    #if os(Linux)
    public static let sha256 = ECHashEngine(hashEngine:SHA256, hashLength:CC_LONG(SHA256_DIGEST_LENGTH))
    public static let sha384 = ECHashEngine(hashEngine:SHA384, hashLength:CC_LONG(SHA384_DIGEST_LENGTH))
    public static let sha512 = ECHashEngine(hashEngine:SHA512, hashLength:CC_LONG(SHA512_DIGEST_LENGTH))
    #else
    public static let sha256 = ECHashEngine(hashEngine:CC_SHA256, hashLength:CC_LONG(CC_SHA256_DIGEST_LENGTH))
    public static let sha384 = ECHashEngine(hashEngine:CC_SHA384, hashLength:CC_LONG(CC_SHA384_DIGEST_LENGTH))
    public static let sha512 = ECHashEngine(hashEngine:CC_SHA512, hashLength:CC_LONG(CC_SHA512_DIGEST_LENGTH))
    #endif

    func digest(data: Data) -> Data {
        
        var hash = [UInt8](repeating: 0, count: Int(self.hashLength))
        data.withUnsafeBytes { ptr in
            guard let baseAddress = ptr.baseAddress else { return }
            _ = self.hashEngine(baseAddress.assumingMemoryBound(to: UInt8.self), CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}
