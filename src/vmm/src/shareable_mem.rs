// SPDX-License-Identifier: Apache-2.0
//
// Shareable guest RAM backing for the vhost-user transport.
//
// vhost-user's SET_MEM_TABLE hands the backend file descriptors it
// can mmap. On Linux that's memfd; on macOS there is no memfd, but
// POSIX named SHM (`shm_open`) returns an fd backed by a kernel
// object that survives `posix_spawn` and is mappable from a child
// process. The conduit data-SHM region already uses this pattern;
// this module extends it to main guest RAM so the same vhost-user
// backend can receive every memory region the guest sees.
//
// HVF maps the resulting host VA via `hv_vm_map` exactly as it does
// for anonymous mmap. The page-cache semantics differ (shm_open
// pages are managed by the POSIX SHM subsystem rather than anon
// VM) but from HVF's perspective the requirement is "pinnable host
// pages with R/W/X permission" and shm_open-backed mmap satisfies
// it. The existing 16 MB conduit data SHM region is the proof.
//
// This module is compiled only when the `vhost-user` feature is on.
// With the feature off, `create_guest_memory` falls through the
// anonymous-mmap path it has used since libkrun's inception.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;

/// Name pattern for guest-RAM SHM objects. The pid is the libkrun
/// process owner; the index disambiguates the low/high split on
/// x86_64 and any future multi-region layouts.
fn region_name(idx: usize) -> String {
    format!("/conduit-guest-ram-{}-{}", std::process::id(), idx)
}

/// Create a POSIX SHM-backed file sized to `size` bytes for guest
/// RAM region `idx`. Returns the owning `File` (whose lifetime
/// must outlive the resulting `GuestRegionMmap`) and the published
/// SHM name so callers can advertise it or unlink it on shutdown.
///
/// The file is created O_EXCL after an unconditional `shm_unlink`
/// of any stale predecessor — a crashed prior libkrun could have
/// left an orphan, and the unlink-then-create dance matches what
/// `data_shm::create_data_shm` does for the conduit region.
pub fn create_guest_ram_shm(idx: usize, size: usize) -> io::Result<(File, String)> {
    let name = region_name(idx);
    let cname = CString::new(name.clone()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest-ram shm name contains NUL",
        )
    })?;
    unsafe {
        libc::shm_unlink(cname.as_ptr());
    }
    let fd = unsafe {
        libc::shm_open(
            cname.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::ftruncate(fd, size as libc::off_t) } < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
            libc::shm_unlink(cname.as_ptr());
        }
        return Err(err);
    }
    Ok((unsafe { File::from_raw_fd(fd) }, name))
}
