//
//  HexConversion.swift
//  WebcashWallet
//
//  Created by Karl-Johan Alm on 2021-04-13.
//  From https://stackoverflow.com/questions/40276322/hex-binary-string-conversion-in-swift
//

import Foundation

extension Data {
    var hexString: String { map { String(format: "%02hhx", $0) }.joined() }

    init?(fromHexEncodedString string: String) {
        // Convert 0 ... 9, a ... f, A ...F to their decimal value,
        // return nil for all other input characters
        func decodeNibble(_ nib: UInt16) -> UInt8? {
            switch nib {
            case 0x30 ... 0x39:
                return UInt8(nib - 0x30)
            case 0x41 ... 0x46:
                return UInt8(nib - 0x41 + 10)
            case 0x61 ... 0x66:
                return UInt8(nib - 0x61 + 10)
            default:
                return nil
            }
        }
        self.init(capacity: string.utf16.count/2)
        var even = true
        var byte: UInt8 = 0
        for nib in string.utf16 {
            guard let val = decodeNibble(nib) else { return nil }
            if even {
                byte = val << 4
            } else {
                byte += val
                self.append(byte)
            }
            even = !even
        }
        guard even else { return nil }
    }
}
