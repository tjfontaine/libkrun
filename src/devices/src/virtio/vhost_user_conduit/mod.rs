// SPDX-License-Identifier: Apache-2.0
//
// vhost-user-device frontend for the bifrost conduit.
//
// This module is feature-gated on `vhost-user`. When the feature
// is on, libkrun's device builder registers `VhostUserConduit`
// in place of the in-tree `virtio/conduit/` device. The frontend
// holds no bifrost-specific protocol state; it just relays
// virtqueue traffic, kicks, calls, and the shared-memory region
// to an out-of-process `conduit-backend` reachable via a
// vhost-user UNIX socket.
//
// LAYERING
//
//   guest virtio driver
//        │   virtqueue descriptors via virtio-mmio
//        ▼
//   VhostUserConduit (this module)
//        │   vhost-user protocol over a UNIX socket
//        │   (SET_OWNER, SET_FEATURES, SET_MEM_TABLE with
//        │    shm_open-backed guest RAM fds, SET_VRING_*,
//        │    KICK/CALL EventFds, shmem-region SHARED_OBJECT)
//        ▼
//   conduit-backend (host/conduit-backend/)
//        │   ConduitCore (host/virtio-conduit/) — generic
//        ▼
//   bifrost CLI ← control SHM → user
//
// `VhostUserConduit` knows about:
//   - virtio-mmio device-type 42 (the conduit transport ID),
//   - three virtqueues (VQ_CTRL / VQ_EVENT / VQ_DOORBELL),
//   - the 16 MB virtio-shmem-region exposed by the backend,
//   - vhost-user master-side connection lifecycle.
//
// It does **not** know about:
//   - BFR7 wrapper bytes,
//   - control-SHM ring layout,
//   - bifrost wire-format opcodes,
//   - any per-record body shape.
//
// That separation is the layering invariant. A change here that
// reaches up into BFR7 or conduit protocol bytes is a layering
// violation per AGENTS.md "Transport / protocol / application".

use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::path::PathBuf;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vhost::vhost_user::message::{VhostUserHeaderFlag, VhostUserSharedMsg, VhostUserVirtioFeatures};
use vhost::vhost_user::{Frontend, VhostUserFrontend};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{
    Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, MemoryRegionAddress,
};
use vmm_sys_util::eventfd::EventFd as VuEventFd;

use super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
    VirtioShmRegion,
};
use crate::virtio::InterruptTransport;

// Same numeric ID as the in-tree adapter — the guest driver
// probes a single device type. The vhost-user carrier keeps the
// wire-level guest view byte-identical; only the host-side carrier changes.
pub const TYPE_VHOST_USER_CONDUIT: u32 = 42;

pub const VQ_CTRL: usize = 0;
pub const VQ_EVENT: usize = 1;
pub const VQ_DOORBELL: usize = 2;

const QUEUE_SIZE: u16 = 256;
const QUEUE_CONFIGS: [QueueConfig; 3] = [
    QueueConfig::new(QUEUE_SIZE),
    QueueConfig::new(QUEUE_SIZE),
    QueueConfig::new(QUEUE_SIZE),
];

const DEVICE_NAME: &str = "vhost-user-conduit";

/// Path the backend's UNIX socket is reached on. Set via the
/// `--vhost-user-conduit=<path>` smolvm flag or
/// `LIBKRUN_VHOST_USER_CONDUIT` env override.
#[derive(Clone, Debug)]
pub struct VhostUserConduitConfig {
    pub socket: PathBuf,
}

pub struct VhostUserConduit {
    config: VhostUserConduitConfig,
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    activate_evt: EventFd,
    queues: Option<Vec<DeviceQueue>>,
    virtio_shm_region: Option<VirtioShmRegion>,
    /// vhost-user master connection. Established by
    /// `activate()`; dropped on `reset()`.
    frontend: Option<Frontend>,
    /// CALL-fd LOCAL ends held alongside the connection. Each
    /// entry is the LOCAL half of a `socketpair(AF_UNIX,
    /// SOCK_STREAM)`; the OTHER half was sent to the backend
    /// via SET_VRING_CALL. When the backend signals used by
    /// writing to its half, bytes appear on these local halves
    /// and the per-fd routing thread drains them and calls
    /// `InterruptTransport::signal_used_queue` so the guest's
    /// virtio-mmio IRQ line fires.
    call_local_fds: Vec<RawFd>,
}

impl VhostUserConduit {
    pub fn new(config: VhostUserConduitConfig) -> std::io::Result<Self> {
        // Advertise VIRTIO_F_VERSION_1 (bit 32). The guest's
        // virtio-mmio probe asks the device for its feature
        // bitmask before deciding which ring layout to use.
        // Modern Linux virtio drivers (kernel 5.x+) require
        // VERSION_1 — without it, queue setup proceeds but
        // virtqueue_add_inbuf fails silently because the
        // driver's modern-split-queue expectations don't
        // line up with what it perceives as a legacy device.
        // The in-tree adapter happens to work with
        // avail_features=0 because libkrun's polly-driven
        // event path masks the failure; the vhost-user
        // worker is more literal and surfaces it as
        // "no descriptors on VQ_CTRL". Caught by inspecting
        // \`/conduit-guest-ram-<pid>-0\` directly: avail.idx
        // never incremented past 0.
        const VIRTIO_F_VERSION_1: u32 = 32;
        let avail_features = 1u64 << VIRTIO_F_VERSION_1;

        Ok(Self {
            config,
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)?,
            queues: None,
            virtio_shm_region: None,
            frontend: None,
            call_local_fds: Vec::new(),
        })
    }

    pub fn set_virtio_shm_region(&mut self, region: VirtioShmRegion) {
        self.virtio_shm_region = Some(region);
    }

    pub fn activate_event(&self) -> &EventFd {
        &self.activate_evt
    }

    pub fn config(&self) -> &VhostUserConduitConfig {
        &self.config
    }

    /// Perform the vhost-user handshake against the backend
    /// socket. Called by `activate()` once the guest memory and
    /// queues are known. Returns the negotiated `Frontend`
    /// connection and the per-queue call fds (kept alive on the
    /// `Self`).
    fn perform_handshake(
        &self,
        mem: &GuestMemoryMmap,
        queues: &[DeviceQueue],
    ) -> std::io::Result<(Frontend, Vec<RawFd>)> {
        let map_err = |e: vhost::Error| -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::Other, format!("vhost: {e:?}"))
        };

        // 1. Connect to the conduit-backend's UNIX socket.
        let mut frontend = Frontend::connect(&self.config.socket, queues.len() as u64)
            .map_err(map_err)?;
        // REPLY_ACK on every header so backend errors surface
        // immediately rather than at the next message.
        frontend.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);

        // 2. SET_OWNER → claim the master role.
        frontend.set_owner().map_err(map_err)?;

        // 3. GET_FEATURES / SET_FEATURES. Echo back the bits we
        //    offered to the guest, intersected with what the
        //    backend advertises. Crucially, OR in
        //    PROTOCOL_FEATURES (bit 30) so the subsequent
        //    get_protocol_features call is allowed — the bit is
        //    a marker indicating the master will use the protocol-
        //    features sub-channel, not a guest-visible feature.
        let backend_features = frontend.get_features().map_err(map_err)?;
        let proto_bit = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        frontend
            .set_features((self.acked_features | proto_bit) & backend_features)
            .map_err(map_err)?;

        // 4. GET_PROTOCOL_FEATURES / SET_PROTOCOL_FEATURES.
        //    SHARED_OBJECT is the one we care about (it carries
        //    the virtio-shmem-region fd back to us); MQ and
        //    CONFIG are advertised by the backend for forward-
        //    compat, accept whatever the backend offers.
        let backend_proto = frontend.get_protocol_features().map_err(map_err)?;
        frontend
            .set_protocol_features(backend_proto)
            .map_err(map_err)?;

        // 5. SET_MEM_TABLE — describe every guest RAM region
        //    by (gpa, host_va, size) plus the fd that the
        //    FileOffset surfaces.
        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
        for r in mem.iter() {
            // SHM regions (gpu, fs, conduit-data) are not main
            // RAM and do not belong in SET_MEM_TABLE — they reach
            // the backend via SHARED_OBJECT or live entirely on
            // the host side. Skip any region that does not have
            // a FileOffset (only main RAM carries a FileOffset).
            let Some(file_offset) = r.file_offset() else {
                continue;
            };
            let host_va = r
                .get_host_address(MemoryRegionAddress(0))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:?}")))?;
            regions.push(VhostUserMemoryRegionInfo {
                guest_phys_addr: r.start_addr().raw_value(),
                memory_size: r.len(),
                userspace_addr: host_va as u64,
                mmap_offset: file_offset.start(),
                mmap_handle: file_offset.file().as_raw_fd(),
            });
        }
        if regions.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no FileOffset-backed guest memory regions to publish; \
                 ensure libkrun is built with --features vhost-user",
            ));
        }
        frontend.set_mem_table(&regions).map_err(map_err)?;

        // 6. Per-vring configuration. Each vring needs:
        //    SET_VRING_NUM (negotiated queue size),
        //    SET_VRING_ADDR (desc/avail/used GPAs from libkrun's
        //                   Queue object),
        //    SET_VRING_BASE (start at 0),
        //    SET_VRING_KICK (the queue's event fd; guest writes
        //                   trigger backend wake-up),
        //    SET_VRING_CALL (a fresh fd we own; backend writes
        //                   trigger guest interrupt — routed
        //                   through InterruptTransport below),
        //    SET_VRING_ENABLE(true).
        let mut call_local_fds: Vec<RawFd> = Vec::with_capacity(queues.len());
        for (idx, dq) in queues.iter().enumerate() {
            let q = &dq.queue;
            // Only configure vrings the guest has fully set up.
            // libkrun's Queue::ready is flipped by the virtio-mmio
            // QueueReady register write that comes just before
            // DRIVER_OK; a vring with `ready == false` has no
            // valid desc/avail/used GPAs and SET_VRING_ADDR
            // would error MissingMemoryMapping. Insert a tracking
            // entry so the backend sees N callbacks regardless.
            if !q.ready {
                log::warn!(
                    "{DEVICE_NAME}: vring {idx} not yet ready at activate; \
                     skipping vhost-user setup for this queue"
                );
                continue;
            }
            // vhost-user-backend expects SET_VRING_ADDR to carry
            // host virtual addresses (QEMU convention). It
            // reverse-translates host_va → GPA via the memory
            // table it built from SET_MEM_TABLE. We hold GPAs in
            // libkrun's Queue, so translate explicitly.
            let to_host_va = |gpa: u64| -> std::io::Result<u64> {
                mem.get_host_address(vm_memory::GuestAddress(gpa))
                    .map(|p| p as u64)
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("gpa->host_va {gpa:#x}: {e:?}"),
                        )
                    })
            };
            let desc_host = to_host_va(q.desc_table.raw_value())?;
            let used_host = to_host_va(q.used_ring.raw_value())?;
            let avail_host = to_host_va(q.avail_ring.raw_value())?;
            log::info!(
                "{DEVICE_NAME}: vring {idx} desc_gpa={:#x} avail_gpa={:#x} used_gpa={:#x}",
                q.desc_table.raw_value(),
                q.avail_ring.raw_value(),
                q.used_ring.raw_value()
            );
            frontend
                .set_vring_num(idx, q.actual_size())
                .map_err(map_err)?;
            frontend
                .set_vring_addr(
                    idx,
                    &VringConfigData {
                        queue_max_size: QUEUE_SIZE,
                        queue_size: q.actual_size(),
                        flags: 0,
                        desc_table_addr: desc_host,
                        used_ring_addr: used_host,
                        avail_ring_addr: avail_host,
                        log_addr: None,
                    },
                )
                .map_err(map_err)?;
            frontend.set_vring_base(idx, 0).map_err(map_err)?;
            // KICK: clone the queue's event fd as a vmm-sys-util
            // EventFd by dup'ing the raw fd. The original lives
            // on the DeviceQueue; the dup goes to the backend.
            let kick_dup = unsafe { libc::dup(dq.event.as_raw_fd()) };
            if kick_dup < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let kick_efd = unsafe {
                <VuEventFd as std::os::fd::FromRawFd>::from_raw_fd(kick_dup)
            };
            frontend.set_vring_kick(idx, &kick_efd).map_err(map_err)?;
            // CALL: socketpair, send the REMOTE half to the
            // backend, keep the LOCAL half for the per-fd
            // routing thread. SOCK_STREAM is bidirectional, so
            // a backend write on its half lands as a read on
            // ours. The routing thread (below) drains the
            // local half and calls
            // InterruptTransport::signal_used_queue.
            let mut sv = [-1i32; 2];
            // SAFETY: sv is a valid two-element array.
            let rc = unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let local_fd = sv[0];
            let remote_fd = sv[1];
            // The routing thread drains until read(2) would block
            // and only raises the guest IRQ after that drain loop.
            // Keep the local half nonblocking so a single backend
            // CALL write cannot park the thread before the IRQ raise.
            let flags = unsafe { libc::fcntl(local_fd, libc::F_GETFL) };
            if flags < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(local_fd);
                    libc::close(remote_fd);
                }
                return Err(err);
            }
            if unsafe { libc::fcntl(local_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(local_fd);
                    libc::close(remote_fd);
                }
                return Err(err);
            }
            // Wrap the remote half as a VuEventFd just for the
            // type the frontend wants. set_vring_call will dup
            // the inner fd via SCM_RIGHTS to the backend; our
            // copy is dropped after the call.
            let remote_efd = unsafe {
                <VuEventFd as std::os::fd::FromRawFd>::from_raw_fd(remote_fd)
            };
            frontend.set_vring_call(idx, &remote_efd).map_err(map_err)?;
            // remote_efd drops here, closing remote_fd locally;
            // the backend retains its own copy via SCM_RIGHTS.
            drop(remote_efd);
            call_local_fds.push(local_fd);
            frontend
                .set_vring_enable(idx, true)
                .map_err(map_err)?;
        }

        Ok((frontend, call_local_fds))
    }
}

impl VirtioDevice for VhostUserConduit {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_VHOST_USER_CONDUIT
    }

    fn device_name(&self) -> &str {
        DEVICE_NAME
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIGS
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        // No virtio configuration space on the conduit transport.
        // Conduit protocol negotiation happens via control-SHM
        // out-of-band; the virtio bus only carries the vrings
        // and the shmem region.
        for b in data.iter_mut() {
            *b = 0;
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Same rationale as read_config — no config space.
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != QUEUE_CONFIGS.len() {
            log::error!(
                "{DEVICE_NAME}: activate: expected {} queues, got {}",
                QUEUE_CONFIGS.len(),
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        // Defensive: confirm at least one main-RAM region
        // carries a FileOffset. The first region (arch index 0)
        // is canonical main RAM; subsequent regions may be SHM
        // (gpu, fs, conduit-data) that take their backend-side
        // mapping path via SHARED_OBJECT, not SET_MEM_TABLE, and
        // legitimately have `file_offset() == None` from libkrun's
        // ShmManager. The vhost-user handshake later filters
        // SET_MEM_TABLE to regions that ARE FileOffset-backed.
        let main_ram_shareable = mem
            .iter()
            .next()
            .map(|r| r.file_offset().is_some())
            .unwrap_or(false);
        if !main_ram_shareable {
            log::error!(
                "{DEVICE_NAME}: main-RAM region is anonymous-mmap; \
                 rebuild libkrun with --features vhost-user to get \
                 shm_open-backed RAM"
            );
            return Err(ActivateError::BadActivate);
        }

        // Perform the vhost-user handshake before transferring
        // queue ownership so we can fail activation cleanly if
        // the backend rejects something.
        let (mut frontend, call_local_fds) = match self.perform_handshake(&mem, &queues) {
            Ok(pair) => pair,
            Err(err) => {
                log::error!(
                    "{DEVICE_NAME}: vhost-user handshake against {}: {err}",
                    self.config.socket.display()
                );
                return Err(ActivateError::BadActivate);
            }
        };

        // GET_SHARED_OBJECT for the conduit's virtio-shmem-region.
        // libkrun's shm_manager already published a stub
        // VirtioShmRegion at construction time
        // (set_virtio_shm_region), so the fd we receive here is
        // diagnostic — it confirms the backend exposes the SHM —
        // but does not replace the existing region mapping.
        // SHARED_OBJECT is best-effort: log and continue on
        // failure.
        match frontend.get_shared_object(&VhostUserSharedMsg::default()) {
            Ok(file) => {
                log::info!(
                    "{DEVICE_NAME}: backend returned shmem-region fd {}",
                    file.as_raw_fd()
                );
                drop(file);
            }
            Err(err) => {
                log::warn!(
                    "{DEVICE_NAME}: get_shared_object failed (continuing): {err:?}"
                );
            }
        }

        // Spawn a routing thread per CALL fd. When the backend
        // signals a used-ring update by writing to its CALL fd
        // (its end of the socketpair we sent via SET_VRING_CALL),
        // bytes land on OUR local end. The thread drains those
        // bytes via kqueue and calls
        // InterruptTransport::signal_used_queue, which raises
        // the virtio-mmio IRQ in the guest. Without this thread
        // the guest never learns of host-side used-ring updates
        // and stops re-posting buffers after the first HOST_PING
        // — VQ_CTRL falls silent and bifrost CLI LOAD_PROGs
        // time out.
        for &fd in call_local_fds.iter() {
            let interrupt_clone = interrupt.clone();
            std::thread::Builder::new()
                .name(format!("{DEVICE_NAME}-call-{fd}"))
                .spawn(move || {
                    let kq = unsafe { libc::kqueue() };
                    if kq < 0 {
                        log::warn!(
                            "{DEVICE_NAME}: kqueue() for call fd {fd}: {}",
                            std::io::Error::last_os_error()
                        );
                        return;
                    }
                    let kev = libc::kevent {
                        ident: fd as usize,
                        filter: libc::EVFILT_READ,
                        flags: libc::EV_ADD | libc::EV_ENABLE,
                        fflags: 0,
                        data: 0,
                        udata: std::ptr::null_mut(),
                    };
                    if unsafe {
                        libc::kevent(kq, &kev, 1, std::ptr::null_mut(), 0, std::ptr::null())
                    } < 0
                    {
                        log::warn!(
                            "{DEVICE_NAME}: kevent register call fd {fd}: {}",
                            std::io::Error::last_os_error()
                        );
                        unsafe { libc::close(kq) };
                        return;
                    }
                    loop {
                        let mut events = [libc::kevent {
                            ident: 0,
                            filter: 0,
                            flags: 0,
                            fflags: 0,
                            data: 0,
                            udata: std::ptr::null_mut(),
                        }];
                        let n = unsafe {
                            libc::kevent(
                                kq,
                                std::ptr::null(),
                                0,
                                events.as_mut_ptr(),
                                1,
                                std::ptr::null(),
                            )
                        };
                        if n < 0 {
                            let err = std::io::Error::last_os_error();
                            if err.raw_os_error() == Some(libc::EINTR) {
                                continue;
                            }
                            log::warn!("{DEVICE_NAME}: kevent wait call fd {fd}: {err}");
                            break;
                        }
                        if n == 0 {
                            continue;
                        }
                        // Drain the fd so kqueue stops firing (it's
                        // level-triggered by default).
                        let mut buf = [0u8; 64];
                        loop {
                            let r = unsafe {
                                libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len())
                            };
                            if r <= 0 {
                                break;
                            }
                        }
                        interrupt_clone.signal_used_queue();
                    }
                    unsafe { libc::close(kq) };
                })
                .ok();
        }

        self.frontend = Some(frontend);
        self.call_local_fds = call_local_fds;
        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        log::info!(
            "{DEVICE_NAME}: activated against {}; handshake complete",
            self.config.socket.display()
        );

        if let Err(err) = self.activate_evt.write(1) {
            log::warn!("{DEVICE_NAME}: activate_evt write: {err}");
        }
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        // Drop the vhost-user connection so the backend can be
        // restarted independently of libkrun's lifecycle.
        self.frontend = None;
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        true
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.virtio_shm_region.as_ref()
    }
}

// Subscriber wiring for the event manager. The vhost-user device
// has a *different* event surface than the in-tree adapter:
//
//   - Guest → backend wakes flow through the KICK fds. We dup'd
//     those into the backend's vhost-user connection during
//     activate(); libkrun does not need to react to them.
//   - Backend → guest wakes arrive on the CALL fds we kept on
//     `self.call_fds`. On each readable event, drain the fd and
//     fire InterruptTransport::signal_used_queue so the guest's
//     virtio-mmio config-change/used-ring interrupt path runs.
//
// At construction time we only know about `activate_evt`; the
// CALL-fd registrations happen lazily when activate() fires the
// activate event.
impl Subscriber for VhostUserConduit {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let activate_evt = self.activate_evt.as_raw_fd();
        if source == activate_evt {
            if let Err(err) = self.activate_evt.read() {
                log::warn!("{DEVICE_NAME}: read activate_evt: {err}");
                return;
            }
            // activate_evt fired once to confirm the device is
            // active. We don't poll CALL fds via the event
            // manager — per-fd routing threads spawned in
            // activate() handle those directly. Unregister
            // activate_evt and we're done; nothing else to
            // dispatch from this Subscriber.
            if let Err(err) = event_manager.unregister(activate_evt) {
                log::warn!("{DEVICE_NAME}: unregister activate_evt: {err:?}");
            }
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}

impl Drop for VhostUserConduit {
    fn drop(&mut self) {
        self.frontend = None;
    }
}

// SAFETY: the device's mutable state is protected by the outer
// Arc<Mutex<…>> the device manager wraps it in. The internal
// vhost Frontend uses an internal Mutex over its socket; call_fds
// are owned and not aliased across threads outside the lock.
unsafe impl Send for VhostUserConduit {}
unsafe impl Sync for VhostUserConduit {}
