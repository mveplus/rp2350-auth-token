import hid

VID = 0xCAFE
PID = 0x4011

REQ_VERSION = 1
CMD_GET_STATE = 3


def main() -> None:
    selected = None
    for d in hid.enumerate():
        if d["vendor_id"] == VID and d["product_id"] == PID:
            print("Found:", d)
            if selected is None:
                selected = d

    if selected is None:
        raise SystemExit("Token not found")

    pkt = bytearray(64)
    pkt[0] = REQ_VERSION
    pkt[1] = CMD_GET_STATE
    pkt[2] = 0
    pkt[3] = 0

    dev = hid.Device(path=selected["path"])
    dev.write(b"\x00" + bytes(pkt))
    resp = bytes(dev.read(64, timeout=2000))
    dev.close()

    if len(resp) != 64:
        raise SystemExit("Bad response length")

    status = resp[1]
    if status != 0:
        raise SystemExit(f"GET_STATE failed with status={status}")

    flags = resp[6]
    runtime_counter = int.from_bytes(resp[8:12], "little")
    persisted_counter = int.from_bytes(resp[12:16], "little")
    generation = int.from_bytes(resp[16:20], "little")
    uid_hex = resp[20:28].hex().upper()

    print("status            :", status)
    print("protocol_version  :", resp[4])
    print("flush_interval    :", resp[5])
    print("master_provisioned:", bool(flags & 0x01))
    print("counter_dirty_ram :", bool(flags & 0x02))
    print("runtime_counter   :", runtime_counter)
    print("persisted_counter :", persisted_counter)
    print("state_generation  :", generation)
    print("uid               :", uid_hex)


if __name__ == "__main__":
    main()
