#!/usr/bin/env swift
import CryptoKit
import Foundation
import IOKit

enum EncryptedHardwareProperty {
    // IORegistry keys read from IOPower:/.
    static let platformSerialNumber = "Gq3489ugfi"
    static let platformUUID = "Fyp98tpgj"
    static let bootUUID = "kbjfrfpoJU" // Named root_disk_uuid_enc in the protobuf.
    static let rom = "oycqAZloTNDm"
    static let mlb = "abKPld1EcMni"
}

enum AppleClientMetadata {
    // Sent as the IDS x-protocol-version header, not a protobuf version.
    static let idsProtocolVersion: Int32 = 1640
    // Fixed client metadata; these are not the host's installed versions.
    static let iCloudUserAgent = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
    // Included in the X-Mme-Client-Info header.
    static let aosKitClientInfo = "com.apple.AOSKit/282 (com.apple.accountsd/113)"
}

enum HwInfoError: Error, CustomStringConvertible {
    case missing(String)
    case serialize

    var description: String {
        switch self {
        case .missing(let key):
            return "Missing hardware property: \(key)"
        case .serialize:
            return "Failed to serialize hardware info"
        }
    }
}

struct ProtoWriter {
    private(set) var data = Data()

    mutating func string(_ field: Int, _ value: String) {
        guard !value.isEmpty else { return }
        lengthDelimited(field, Data(value.utf8))
    }

    mutating func bytes(_ field: Int, _ value: Data) {
        guard !value.isEmpty else { return }
        lengthDelimited(field, value)
    }

    mutating func message(_ field: Int, _ value: Data) {
        lengthDelimited(field, value)
    }

    mutating func int32(_ field: Int, _ value: Int32) {
        guard value != 0 else { return }
        tag(field, wire: 0)
        putVarint(UInt64(bitPattern: Int64(value)))
    }

    private mutating func lengthDelimited(_ field: Int, _ value: Data) {
        tag(field, wire: 2)
        putVarint(UInt64(value.count))
        data.append(value)
    }

    private mutating func tag(_ field: Int, wire: UInt8) {
        putVarint(UInt64(field << 3 | Int(wire)))
    }

    private mutating func putVarint(_ value: UInt64) {
        var value = value
        while value > 0x7F {
            data.append(UInt8(value & 0x7F) | 0x80)
            value >>= 7
        }
        data.append(UInt8(value))
    }
}

func debugLog(_ message: String) {
    guard ProcessInfo.processInfo.environment["HWINFO_DEBUG"] == "1" else { return }
    fputs(message + "\n", stderr)
}

func getMainPort() -> mach_port_t {
    if #available(macOS 12.0, *) {
        return kIOMainPortDefault
    } else {
        return kIOMasterPortDefault
    }
}

func getData(_ device: io_registry_entry_t, _ key: String) -> Data? {
    debugLog("reading val " + key)
    guard let value = IORegistryEntryCreateCFProperty(device, key as CFString, kCFAllocatorDefault, 0) else {
        return nil
    }
    return (value.takeRetainedValue() as? NSData) as Data?
}

func getString(_ device: io_registry_entry_t, _ key: String) -> String? {
    debugLog("reading val " + key)
    guard let value = IORegistryEntryCreateCFProperty(device, key as CFString, kCFAllocatorDefault, 0) else {
        return nil
    }
    return (value.takeRetainedValue() as? NSString) as String?
}

func getItem(_ device: io_registry_entry_t, _ key: String) -> String? {
    guard let value = getData(device, key) else { return nil }
    return String(data: value, encoding: .utf8)
}

func requireData(_ device: io_registry_entry_t, _ key: String) throws -> Data {
    guard let value = getData(device, key) else { throw HwInfoError.missing(key) }
    return value
}

func requireString(_ device: io_registry_entry_t, _ key: String) throws -> String {
    guard let value = getString(device, key) else { throw HwInfoError.missing(key) }
    return value
}

func requireItem(_ device: io_registry_entry_t, _ key: String) throws -> String {
    guard let value = getItem(device, key) else { throw HwInfoError.missing(key) }
    return value
}

func sysctl(name: String) -> String {
    var size = 0
    sysctlbyname(name, nil, &size, nil, 0)
    var val = [CChar](repeating: 0, count: size)
    sysctlbyname(name, &val, &size, nil, 0)
    return String(cString: val)
}

func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

func getMacAddress() throws -> Data {
    let filter = IOServiceMatching("IOEthernetInterface") as NSMutableDictionary
    filter["IOPropertyMatch"] = [
        "IOPrimaryInterface": true
    ] as CFDictionary

    var iterator: io_iterator_t = 0
    IOServiceGetMatchingServices(getMainPort(), filter, &iterator)

    let ethService = IOIteratorNext(iterator)
    guard ethService != 0 else { throw HwInfoError.missing("IOEthernetInterface") }

    var parentService: io_registry_entry_t = 0
    IORegistryEntryGetParentEntry(ethService, kIOServicePlane, &parentService)
    return try requireData(parentService, "IOMACAddress")
}

func hexBytes(_ data: Data) -> String {
    data.map { String(format: "%02hhx", $0) }.joined()
}

func collectHwInfo() throws -> Data {
    let deviceTree = IORegistryEntryFromPath(getMainPort(), "IODeviceTree:/")
    let ioPower = IORegistryEntryFromPath(getMainPort(), "IOPower:/")
    let optionsTree = IORegistryEntryFromPath(getMainPort(), "IODeviceTree:/options")
    let chosenTree = IORegistryEntryFromPath(getMainPort(), "IODeviceTree:/chosen")

    let rom: Data
    if let optionRom = getData(optionsTree, "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM") {
        rom = optionRom
    } else {
        rom = sha256(try requireData(chosenTree, "unique-chip-id")).suffix(6)
    }

    let productName: String
    if let name = getItem(deviceTree, "product-name") {
        productName = name.trimmingCharacters(in: CharacterSet(["\0"]))
    } else {
        productName = (try requireItem(deviceTree, "model")).trimmingCharacters(in: CharacterSet(["\0"]))
    }
    let platformUuid = try requireString(deviceTree, "IOPlatformUUID")
    let boardID: String
    if let id = getItem(deviceTree, "board-id")?.trimmingCharacters(in: CharacterSet(["\0"])) {
        boardID = id
    } else {
        boardID = "Mac-" + hexBytes(try requireData(chosenTree, "board-id"))
    }
    let mlb: String
    if let value = getItem(optionsTree, "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB") {
        mlb = value
    } else {
        mlb = (try requireItem(deviceTree, "mlb-serial-number")).trimmingCharacters(in: CharacterSet(["\0"]))
    }

    var inner = ProtoWriter()
    inner.string(1, productName)
    inner.bytes(2, try getMacAddress())
    inner.string(3, try requireString(deviceTree, "IOPlatformSerialNumber"))
    inner.string(4, platformUuid)
    inner.string(5, (try requireItem(chosenTree, "boot-uuid")).trimmingCharacters(in: CharacterSet(["\0"])))
    inner.string(6, boardID)
    inner.string(7, sysctl(name: "kern.osversion"))
    inner.bytes(8, try requireData(ioPower, EncryptedHardwareProperty.platformSerialNumber))
    inner.bytes(9, try requireData(ioPower, EncryptedHardwareProperty.platformUUID))
    inner.bytes(10, try requireData(ioPower, EncryptedHardwareProperty.bootUUID))
    inner.bytes(11, rom)
    inner.bytes(12, try requireData(ioPower, EncryptedHardwareProperty.rom))
    inner.string(13, mlb)
    inner.bytes(14, try requireData(ioPower, EncryptedHardwareProperty.mlb))

    var outer = ProtoWriter()
    outer.message(1, inner.data)
    outer.string(2, sysctl(name: "kern.osproductversion"))
    outer.int32(3, AppleClientMetadata.idsProtocolVersion)
    outer.string(4, platformUuid)
    outer.string(5, AppleClientMetadata.iCloudUserAgent)
    outer.string(6, AppleClientMetadata.aosKitClientInfo)
    return outer.data
}

do {
    print(try collectHwInfo().base64EncodedString())
} catch {
    fputs("Failed to serialize hardware info: \(error)\n", stderr)
    exit(1)
}
