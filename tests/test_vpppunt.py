import pytest

from vppdhc.vpppunt import VPP


@pytest.mark.asyncio
async def test_connect():
    vpp = await VPP.create()
    assert vpp is not None

    rv = await vpp.vpp_interface_info(1)
    print("RV:", rv)

    # Expect an exception
    with pytest.raises(IndexError):
        await vpp.vpp_interface_info(10)

    print(await vpp.vpp_probe_is_duplicate(1, "aa:bb:cc:dd:ee:ff", "1::1"))

    rv = await vpp.vpp_ip6_route_add("::/0", "1::1")
    print("RV:", rv)

    rv = await vpp.vpp_ip_address(1, "2::123/128")
    print("RV:", rv)

    await vpp.vpp.disconnect()


if __name__ == "__main__":
    pytest.main()
