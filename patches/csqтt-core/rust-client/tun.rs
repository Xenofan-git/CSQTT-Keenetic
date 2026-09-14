// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Result, bail};
use std::fs::File;
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use tokio::io::unix::AsyncFd;

    const UNIX_PATH_MAX: usize = 108;
    const CONTROL_LEN: usize = 64;

    pub struct FdReceiver { listener: AsyncFd<OwnedFd> }

    impl FdReceiver {
        pub fn bind(name: &str) -> Result<Self> {
            let name = name.strip_prefix('@').unwrap_or(name);
            if name.is_empty() { bail!("TUN UDS name is empty"); }
            if name.len() + 1 > UNIX_PATH_MAX { bail!("TUN UDS name is too long: {} bytes", name.len()); }
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 { return Err(io::Error::last_os_error().into()); }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let addr = make_abstract_addr(name)?;
            let addr_len = abstract_addr_len(name.len());
            let rc = unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(), addr_len) };
            if rc < 0 { return Err(io::Error::last_os_error().into()); }
            let rc = unsafe { libc::listen(fd.as_raw_fd(), 4) };
            if rc < 0 { return Err(io::Error::last_os_error().into()); }
            let listener = AsyncFd::new(fd)?;
            crate::log_error!("[TUN] UDS listener ready: @{name}");
            Ok(Self { listener })
        }

        pub async fn receive(&self, cancel: &CancellationToken) -> Result<File> {
            loop {
                let mut guard = tokio::select! {
                    _ = cancel.cancelled() => bail!("TUN FD receiver cancelled"),
                    ready = self.listener.readable() => ready?,
                };
                loop {
                    match accept_nonblocking(self.listener.get_ref().as_raw_fd()) {
                        Ok(client_fd) => match recv_tun_fd(client_fd, cancel).await {
                            Ok(file) => { guard.clear_ready(); return Ok(file); }
                            Err(error) => { crate::log_error!("[TUN] Invalid UDS FD transfer: {error}"); continue; }
                        },
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => { guard.clear_ready(); break; }
                        Err(error) => { guard.clear_ready(); return Err(error.into()); }
                    }
                }
            }
        }
    }

    fn make_abstract_addr(name: &str) -> Result<libc::sockaddr_un> {
        if name.as_bytes().contains(&0) { bail!("TUN UDS name contains NUL byte"); }
        let bytes = name.as_bytes();
        if bytes.len() + 1 > UNIX_PATH_MAX { bail!("TUN UDS name is too long: {} bytes", name.len()); }
        let mut addr: libc::sockaddr_un = unsafe { zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (index, byte) in bytes.iter().enumerate() { addr.sun_path[index + 1] = *byte as libc::c_char; }
        Ok(addr)
    }

    fn abstract_addr_len(name_len: usize) -> libc::socklen_t { (size_of::<libc::sa_family_t>() + 1 + name_len) as libc::socklen_t }

    fn accept_nonblocking(listener: RawFd) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::accept4(listener, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
        if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) }
    }

    async fn send_tun_ack(socket: &AsyncFd<OwnedFd>, cancel: &CancellationToken) -> Result<()> {
        let ack = [1u8];
        loop {
            let mut guard = tokio::select! {
                _ = cancel.cancelled() => bail!("TUN FD ACK cancelled"),
                ready = socket.writable() => ready?,
            };
            let n = unsafe { libc::send(socket.get_ref().as_raw_fd(), ack.as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
            guard.clear_ready();
            if n == 1 { return Ok(()); }
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock { continue; }
                return Err(error.into());
            }
            bail!("short TUN ACK write: {} bytes", n);
        }
    }

    async fn recv_tun_fd(fd: OwnedFd, cancel: &CancellationToken) -> Result<File> {
        let socket = AsyncFd::new(fd)?;
        let mut payload = [0u8; 1];
        let mut control = [0usize; CONTROL_LEN / size_of::<usize>()];
        loop {
            let mut guard = tokio::select! {
                _ = cancel.cancelled() => bail!("TUN FD transfer cancelled"),
                ready = socket.readable() => ready?,
            };

            // Keep all non-Send libc message structures in this scope. They must be
            // dropped before the ACK await below, otherwise the spawned future is
            // not Send on musl/aarch64.
            let received_fd = {
                let mut iov = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: payload.len() };
                let mut msg: libc::msghdr = unsafe { zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = std::mem::size_of_val(&control) as libc::socklen_t;
                let n = unsafe { libc::recvmsg(socket.get_ref().as_raw_fd(), &mut msg, 0) };
                if n < 0 {
                    let error = io::Error::last_os_error();
                    guard.clear_ready();
                    if error.kind() == io::ErrorKind::WouldBlock { continue; }
                    return Err(error.into());
                }
                if n == 0 { guard.clear_ready(); return Err(anyhow::anyhow!("UDS peer closed before sending TUN FD")); }
                if (msg.msg_flags & libc::MSG_CTRUNC) != 0 { guard.clear_ready(); return Err(anyhow::anyhow!("UDS SCM_RIGHTS control data was truncated")); }

                let mut cursor = control.as_ptr().cast::<u8>();
                let end = unsafe { cursor.add(msg.msg_controllen as usize) };
                let mut received_fd = None;
                while (cursor as usize) + size_of::<libc::cmsghdr>() <= end as usize {
                    let header = unsafe { &*(cursor.cast::<libc::cmsghdr>()) };
                    if header.cmsg_len < size_of::<libc::cmsghdr>() as u32 { break; }
                    let next = unsafe { libc::CMSG_NXTHDR(&msg, header) };
                    if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                        let base = unsafe { libc::CMSG_LEN(0) as usize };
                        let data_len = (header.cmsg_len as usize).saturating_sub(base);
                        if data_len < size_of::<RawFd>() { guard.clear_ready(); return Err(anyhow::anyhow!("SCM_RIGHTS contains no file descriptor")); }
                        let fd_ptr = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
                        let fd = unsafe { *fd_ptr };
                        if fd < 0 { guard.clear_ready(); return Err(anyhow::anyhow!("SCM_RIGHTS returned invalid FD")); }
                        received_fd = Some(fd);
                        break;
                    }
                    match next { p if p.is_null() => break, p => cursor = p.cast::<u8>(), }
                }
                received_fd.ok_or_else(|| anyhow::anyhow!("UDS message does not contain SCM_RIGHTS TUN FD"))?
            };

            let file = unsafe { File::from_raw_fd(received_fd) };
            guard.clear_ready();
            send_tun_ack(&socket, cancel).await?;
            return Ok(file);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::FdReceiver;

#[cfg(not(target_os = "linux"))]
pub struct FdReceiver;

#[cfg(not(target_os = "linux"))]
impl FdReceiver {
    pub fn bind(_name: &str) -> Result<Self> { crate::log_error!("[TUN] Switching to proxy"); Ok(Self) }
    pub async fn receive(&self, _cancel: &CancellationToken) -> Result<File> { crate::log_error!("[TUN] Switching to proxy"); bail!("TUN FD is only supported on Linux/Android") }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn abstract_addr_length_is_correct() {
        assert_eq!(super::linux::abstract_addr_len(0), 3);
        assert_eq!(super::linux::abstract_addr_len(14), 17);
    }
}
