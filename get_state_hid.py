import hid

from host_protocol import CMD_GET_STATE, PID, REQ_VERSION, VID, parse_get_state_response


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

    state = parse_get_state_response(resp)

    print("status            :", state["status"])
    print("protocol_version  :", state["protocol_version"])
    print("flush_interval    :", state["flush_interval"])
    print("replay_protection :", state["replay_protection_mode_name"])
    print("master_provisioned:", state["master_provisioned"])
    print("provisioning_locked:", state["provisioning_locked"])
    print("storage_protected :", state["storage_protection_active"])
    print("secret_loaded     :", state["secret_loaded"])
    print("counter_dirty_ram :", state["counter_dirty_ram"])
    print("runtime_counter   :", state["runtime_counter"])
    print("persisted_counter :", state["persisted_counter"])
    print("state_generation  :", state["state_generation"])
    print("uid               :", state["uid_hex"])


if __name__ == "__main__":
    main()
