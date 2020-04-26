use netns::NetNS;

use crate::Device;

#[test]
fn it_works() {
    sudo::escalate_if_needed().unwrap();

    let ns = NetNS::new().unwrap();
    NetNS::set(ns).unwrap();

    let wg = Device::add("test_wg0").unwrap();
    let wg_list = Device::devices().unwrap();
    let wg = &wg_list[0];
    dbg!(&wg);
    wg.del().unwrap();
}
