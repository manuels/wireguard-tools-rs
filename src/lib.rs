#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as crypto;

use std::io::{Result, ErrorKind};
use std::io::Error;
use std::ffi::CStr;
use std::ffi::CString;
use std::ptr::NonNull;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::net::{SocketAddr, IpAddr};

#[cfg(test)]
mod tests;

mod sys {
    pub const WGDEVICE_REPLACE_PEERS: u32 = 1 << 0;
    pub const WGDEVICE_HAS_PRIVATE_KEY: u32 = 1 << 1;
    pub const WGDEVICE_HAS_PUBLIC_KEY: u32 = 1 << 2;
    pub const WGDEVICE_HAS_LISTEN_PORT: u32 = 1 << 3;
    pub const WGDEVICE_HAS_FWMARK: u32 = 1 << 4;

    pub const WGPEER_REMOVE_ME: u32 = 1 << 0;
    pub const WGPEER_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
    pub const WGPEER_HAS_PUBLIC_KEY: u32 = 1 << 2;
    pub const WGPEER_HAS_PRESHARED_KEY: u32 = 1 << 3;
    pub const WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL: u32 = 1 << 4;

    include!(concat!(env!("OUT_DIR"), "/sys.rs"));
}

pub struct Device(NonNull<sys::wg_device>);
pub struct Peer<'a>(NonNull<sys::wg_peer>, PhantomData<&'a Device>);
pub struct AllowedIp<'a>(NonNull<sys::wg_allowedip>, PhantomData<&'a Peer<'a>>);

pub use crypto::SecretKey;
pub use crypto::PublicKey;
pub struct PresharedKey(sys::wg_key);

impl Device {
    fn inner(&self) -> &sys::wg_device {
        unsafe { self.0.as_ref() }
    }

    fn inner_mut(&mut self) -> &mut sys::wg_device {
        unsafe { self.0.as_mut() }
    }

    pub fn name(&self) -> Result<String> {
        let n = self.inner().name;
        let n: &[u8; 16] = unsafe { std::mem::transmute(&n) };
        let len = n.iter().position(|c| *c == b'\0').unwrap_or(std::mem::size_of_val(&n));

        if let Ok(n) = CString::new(&n[..len]) {
            if let Ok(n) = n.into_string() {
                return Ok(n)
            }
        }
        Err(ErrorKind::InvalidData.into())
    }

    pub fn set_name<S: Into<CString>>(&mut self, name: S) -> Result<()> {
        let name = name.into();
        let bytes = name.as_bytes_with_nul();

        if bytes.len() > 1 { //std::mem::size_of_val(self.as_ref().name) {
            return Err(ErrorKind::InvalidInput.into())
        }

        let bytes = unsafe { &*(&bytes[..] as *const [u8] as *const [::std::os::raw::c_char]) };
        self.inner_mut().name[..].clone_from_slice(bytes);
        Ok(())
    }

    fn has_flag(&self, test_flag: u32) -> bool {
        self.inner().flags & test_flag == test_flag
    }

    fn add_flag(&mut self, flag: u32) {
        self.inner_mut().flags |= flag;
    }

    fn remove_flag(&mut self, flag: u32) {
        self.inner_mut().flags &= !flag;
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        if !self.has_flag(sys::WGDEVICE_HAS_PUBLIC_KEY) {
            return None;
        }
        Some(PublicKey(self.inner().public_key))
    }

    pub fn secret_key(&self) -> Option<SecretKey> {
        if !self.has_flag(sys::WGDEVICE_HAS_PRIVATE_KEY) {
            return None;
        }
        Some(SecretKey(self.inner().private_key))
    }

    pub fn set_secret_key(&mut self, secret_key: Option<SecretKey>) {
        if let Some(key) = secret_key {
            self.inner_mut().private_key = key.0;
            self.add_flag(sys::WGDEVICE_HAS_PRIVATE_KEY)
        } else {
            self.remove_flag(sys::WGDEVICE_HAS_PRIVATE_KEY)
        }
    }

    pub fn listen_port(&self) -> Option<u16> {
        if !self.has_flag(sys::WGDEVICE_HAS_LISTEN_PORT) {
            return None;
        }
        Some(self.inner().listen_port)
    }

    pub fn set_listen_port(&mut self, listen_port: Option<u16>) {
        if let Some(listen_port) = listen_port {
            self.inner_mut().listen_port = listen_port;
            self.add_flag(sys::WGDEVICE_HAS_LISTEN_PORT)
        } else {
            self.remove_flag(sys::WGDEVICE_HAS_LISTEN_PORT)
        }
    }

    pub fn fwmark(&self) -> Option<u32> {
        if !self.has_flag(sys::WGDEVICE_HAS_FWMARK) {
            return None;
        }
        Some(self.inner().fwmark)
    }

    pub fn set_fwmark(&mut self, fwmark: Option<u32>) {
        if let Some(fwmark) = fwmark {
            self.inner_mut().fwmark = fwmark;
            self.add_flag(sys::WGDEVICE_HAS_FWMARK)
        } else {
            self.remove_flag(sys::WGDEVICE_HAS_FWMARK)
        }
    }

    pub fn ifindex(&self) -> u32 {
        self.inner().ifindex
    }

    pub fn set_ifindex(&mut self, ifindex: u32) {
        self.inner_mut().ifindex = ifindex;
    }

    pub fn devices() -> Result<Vec<Device>> {
        let mut devices = vec![];

        let device_names = unsafe { sys::wg_list_device_names() };
        let mut ptr = device_names;
        assert!(!ptr.is_null());

        let mut len = 1;
        while len > 0 {
            let name = unsafe { CStr::from_ptr(ptr) };
            len = name.to_bytes().len();
            ptr = unsafe { ptr.add(len + 1) };  // + 1 because of nul byte

            if len > 0 {
                devices.push(Self::get(name.to_bytes())?);
            }
        }

        unsafe {
            libc::free(device_names as *mut _);
        }

        return Ok(devices)
    }

    pub fn get<S: Into<Vec<u8>>>(device_name: S) -> Result<Device> {
        if let Ok(device_name) = CString::new(device_name) {
            let mut dev: *mut sys::wg_device = std::ptr::null_mut();

            let res = unsafe {
                sys::wg_get_device(&mut dev, device_name.as_ptr())
            };
            dbg!(res, device_name);

            if let Some(dev) = NonNull::new(dev) {
                let dev = Device(dev);
                Ok(dev)
            } else {
                Err(Error::from_raw_os_error(res))
            }
        } else {
            Err(ErrorKind::InvalidInput.into())

        }
    }

    pub fn apply(&self) -> Result<()> {
        let res = unsafe {
            sys::wg_set_device(self.0.as_ptr())
        };

        if res < 0 {
            return Err(Error::from_raw_os_error(res));
        }

        Ok(())
    }

    pub fn add<S: Into<Vec<u8>>>(device_name: S) -> Result<()> {
        if let Ok(device_name) = CString::new(device_name) {
            let res = unsafe {
                sys::wg_add_device(device_name.as_ptr())
            };

            if res < 0 {
                return Err(Error::from_raw_os_error(res));
            }

            Ok(())
        } else {
            Err(ErrorKind::InvalidInput.into())
        }
    }

    pub fn del(&self) -> Result<()> {
        let res = unsafe {
            sys::wg_del_device(self.inner().name.as_ptr())
        };

        if res < 0 {
            return Err(Error::from_raw_os_error(res));
        }

        Ok(())
    }

    pub fn get_peer<'a>(&'a self, peer: &PublicKey) -> Option<Peer<'a>> {
        self.peers().into_iter().find(|p| p.public_key().as_ref() == Some(peer))
    }

    pub fn peers<'a>(&'a self) -> Vec<Peer<'a>> {
        let first = self.inner().first_peer;
        let mut it = NonNull::new(first).map(|p| Peer(p, PhantomData));

        let mut res = vec![];
        while let Some(peer) = it {
            it = peer.next_peer();
            res.push(peer);
        }

        res
    }

    pub fn next_handshake(&self) -> Option<Duration> {
        self.peers().iter().filter_map(|p| p.next_handshake()).min()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            sys::wg_free_device(self.0.as_ptr())
        }
    }
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgDevice")
            .field("flags", &self.inner().flags)
            .field("name", &self.name())
            .field("ifindex", &self.ifindex())
            .field("public_key", &self.public_key())
            .field("secret_key", &self.secret_key())
            .field("fwmark", &self.fwmark())
            .field("listen_port", &self.listen_port())
            .field("peers", &self.peers())
            .finish()
    }}

impl<'a> std::fmt::Debug for Peer<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeer")
            .field("flags", &self.inner().flags)
            .field("public_key", &self.public_key())
            .field("preshared_key", &self.preshared_key())
            .field("endpoint", &self.endpoint())
            .field("last_handshake_time", &self.last_handshake_time())
            .field("rx_bytes", &self.rx_bytes())
            .field("tx_bytes", &self.tx_bytes())
            .field("persistent_keepalive_interval", &self.persistent_keepalive_interval())
            .finish()
        /*
	wg_key public_key;
	wg_key preshared_key;

	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} endpoint;

	struct timespec64 last_handshake_time;
	uint64_t rx_bytes, tx_bytes;
	uint16_t persistent_keepalive_interval;

	struct wg_allowedip *first_allowedip, *last_allowedip;
	struct wg_peer *next_peer;
        */
    }
}

impl std::fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PresharedKey(omitted)")
    }
}

impl<'a> Peer<'a> {
    fn inner(&self) -> &sys::wg_peer {
        unsafe { self.0.as_ref() }
    }

    fn inner_mut(&mut self) -> &mut sys::wg_peer {
        unsafe { self.0.as_mut() }
    }

    pub fn last_handshake_time(&self) -> Option<SystemTime> {
        let time = self.inner().last_handshake_time;
        if time.tv_sec == 0 && time.tv_nsec == 0 {
            return None;
        }

        let time = Duration::from_secs(time.tv_sec as u64) + Duration::from_nanos(time.tv_nsec as u64);
        Some(UNIX_EPOCH + time)
    }

    fn has_flag(&self, test_flag: u32) -> bool {
        self.inner().flags & test_flag == test_flag
    }

    fn next_handshake(&self) -> Option<Duration> {
        if let Some(hs) = self.last_handshake_time() {
            if let Some(keep_alive) = self.persistent_keepalive_interval() {
                return (hs + keep_alive).duration_since(SystemTime::now()).ok()
            }
        }
        None
    }

    fn add_flag(&mut self, flag: u32) {
        self.inner_mut().flags |= flag;
    }

    fn remove_flag(&mut self, flag: u32) {
        self.inner_mut().flags &= !flag;
    }

    pub fn persistent_keepalive_interval(&self) -> Option<Duration> {
        if !self.has_flag(sys::WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) {
            return None;
        }
        let secs = self.inner().persistent_keepalive_interval;
        Some(Duration::from_secs(secs as u64))
    }

    pub fn set_persistent_keepalive_interval(&mut self, persistent_keepalive_interval: Option<Duration>) {
        if let Some(interval) = persistent_keepalive_interval {
            self.inner_mut().persistent_keepalive_interval = interval.as_secs() as u16;
            self.add_flag(sys::WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
        } else {
            self.remove_flag(sys::WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
        }
    }

    pub fn preshared_key(&self) -> Option<PresharedKey> {
        if !self.has_flag(sys::WGPEER_HAS_PRESHARED_KEY) {
            return None;
        }
        let key = self.inner().preshared_key;
        Some(PresharedKey(key))
    }

    pub fn set_preshared_key(&mut self, preshared_key: Option<PresharedKey>) {
        if let Some(psk) = preshared_key {
            self.inner_mut().preshared_key[..].copy_from_slice(&psk.0[..]);
            self.add_flag(sys::WGPEER_HAS_PRESHARED_KEY)
        } else {
            self.remove_flag(sys::WGPEER_HAS_PRESHARED_KEY)
        }
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        if !self.has_flag(sys::WGPEER_HAS_PUBLIC_KEY) {
            return None;
        }
        let key = self.inner().public_key;
        Some(PublicKey(key))
    }

    pub fn set_public_key(&mut self, public_key: Option<PublicKey>) {
        if let Some(key) = public_key {
            self.inner_mut().public_key[..].copy_from_slice(&key.0[..]);
            self.add_flag(sys::WGPEER_HAS_PUBLIC_KEY)
        } else {
            self.remove_flag(sys::WGPEER_HAS_PUBLIC_KEY)
        }
    }

    pub fn next_peer(&self) -> Option<Peer<'a>> {
        NonNull::new(self.inner().next_peer).map(|p| Peer(p, PhantomData))
    }

    pub fn rx_bytes(&self) -> u64 {
        self.inner().rx_bytes
    }

    pub fn tx_bytes(&self) -> u64 {
        self.inner().tx_bytes
    }

    pub fn remove_me(&mut self) {
        self.add_flag(sys::WGPEER_REMOVE_ME)
    }

    pub fn keep_me(&mut self) {
        self.remove_flag(sys::WGPEER_REMOVE_ME)
    }

    pub fn endpoint(&self) -> Option<SocketAddr> {
        use nix::sys::socket::SockAddr;

        let addr = self.inner().endpoint;
        let ptr = &addr as *const sys::wg_peer__bindgen_ty_1 as *const libc::sockaddr;
        let addr = unsafe { SockAddr::from_libc_sockaddr(ptr) };

        if let Some(SockAddr::Inet(addr)) = addr {
            return match addr.to_std() {
                SocketAddr::V4(addr4) if addr4.ip().is_unspecified() && addr4.port() == 0 => None,
                SocketAddr::V6(addr6) if addr6.ip().is_unspecified() && addr6.port() == 0 => None,
                addr => Some(addr)
            }
        }
        None
    }

    pub fn set_endpoint(&mut self, endpoint: &SocketAddr) {
        use nix::sys::socket::InetAddr;
        let endpoint = InetAddr::from_std(endpoint);

        match endpoint {
            InetAddr::V4(addr4) => unsafe { self.inner_mut().endpoint.addr4 = std::mem::transmute(addr4) }
            InetAddr::V6(addr6) => unsafe { self.inner_mut().endpoint.addr6 = std::mem::transmute(addr6) }
        }
    }

    pub fn allowed_ips(&self) -> Vec<AllowedIp<'a>> {
        dbg!("allowed_ips");
        let first = self.inner().first_allowedip;
        dbg!("allowed_ips1");
        dbg!(&first);
        let mut it = NonNull::new(first).map(|ip| AllowedIp(ip, PhantomData));
        //dbg!(&it);

        let mut res = vec![];
        while let Some(addr) = it {
            it = addr.next_allowedip();
            res.push(addr);
        }

        res
    }

    pub fn first_allowedip(&self) -> Option<AllowedIp<'a>> {
        unsafe { AllowedIp::from_ptr(self.inner().first_allowedip) }
    }

    pub fn add_allowedip(&mut self, addr: IpAddr, cidr: u8) {
        let allowedip = Box::new(unsafe { std::mem::zeroed() });
        let allowedip = unsafe { NonNull::new_unchecked(Box::into_raw(allowedip)) };

        let mut allowedip = unsafe { AllowedIp::from_non_null(allowedip) };
        allowedip.set_ip(&addr);
        allowedip.set_cidr(cidr);
        allowedip.set_next_allowedip(self.first_allowedip());

        self.inner_mut().first_allowedip = allowedip.0.as_ptr();
    }
}

// TODO: is this really safe?
unsafe impl Sync for Device {}
unsafe impl Send for Device {}

// TODO: is this really safe?
unsafe impl<'a> Sync for Peer<'a> {}
unsafe impl<'a> Send for Peer<'a> {}

impl<'a> AllowedIp<'a> {
    fn inner(&self) -> &sys::wg_allowedip {
        unsafe { self.0.as_ref() }
    }

    fn inner_mut(&mut self) -> &mut sys::wg_allowedip {
        unsafe { self.0.as_mut() }
    }

    pub unsafe fn from_ptr(ptr: *mut sys::wg_allowedip) -> Option<AllowedIp<'a>> {
        let allowedip = NonNull::new(ptr);
        allowedip.map(|ip| AllowedIp::from_non_null(ip))
    }

    pub unsafe fn from_non_null(allowedip: NonNull<sys::wg_allowedip>) -> AllowedIp<'a> {
        AllowedIp(allowedip, PhantomData)
    }

    pub fn next_allowedip(&self) -> Option<AllowedIp<'a>> {
        NonNull::new(self.inner().next_allowedip).map(|ip| AllowedIp(ip, PhantomData))
    }

    pub fn set_next_allowedip(&mut self, addr: Option<AllowedIp<'a>>) {
        if let Some(addr) = addr {
            self.inner_mut().next_allowedip = addr.0.as_ptr();
        } else {
            self.inner_mut().next_allowedip = std::ptr::null_mut();
        }
    }

    pub fn ip(&self) -> IpAddr {
        use nix::sys::socket::Ipv4Addr;
        use nix::sys::socket::Ipv6Addr;

        match self.inner().family as _ {
            libc::AF_INET => {
                let addr = unsafe { std::mem::transmute(self.inner().__bindgen_anon_1.ip4) };
                Ipv4Addr(addr).to_std().into()
            },
            libc::AF_INET6 => {
                let addr = unsafe { std::mem::transmute(self.inner().__bindgen_anon_1.ip6) };
                Ipv6Addr(addr).to_std().into()
            },
            _ => unreachable!("Another family than AF_INET/AF_INET6 found!")
        }
    }

    pub fn cidr(&self) -> u8 {
        self.inner().cidr
    }

    pub fn set_cidr(&mut self, cidr: u8) {
        self.inner_mut().cidr = cidr;
    }

    pub fn set_ip(&mut self, ip: &IpAddr) {
        use nix::sys::socket::IpAddr;
        use nix::sys::socket::Ipv4Addr;
        use nix::sys::socket::Ipv6Addr;

        let this = self.inner_mut();
        match IpAddr::from_std(ip) {
            IpAddr::V4(Ipv4Addr(addr4)) => unsafe {
                this.family = libc::AF_INET as _;
                this.__bindgen_anon_1.ip4 = std::mem::transmute(addr4)
            }
            IpAddr::V6(Ipv6Addr(addr6)) => unsafe {
                this.family = libc::AF_INET6 as _;
                this.__bindgen_anon_1.ip6 = std::mem::transmute(addr6)
            }
        }

    }
}

impl PresharedKey {
    pub fn new() -> PresharedKey {
        let mut key = [0; std::mem::size_of::<sys::wg_key>()];

        unsafe {
            sys::wg_generate_preshared_key(key.as_mut_ptr())
        }

        PresharedKey(key)
    }
}
