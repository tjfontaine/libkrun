use std::collections::BTreeMap;

use arch::ArchMemoryInfo;
use vm_memory::{FileOffset, GuestAddress};
use vmm_sys_util::align_upwards;

#[derive(Debug)]
pub enum Error {
    ConduitShmCreate(std::io::Error),
    DuplicatedConduitRegion,
    DuplicatedGpuRegion,
    OutOfSpace,
}

#[derive(Clone)]
pub struct ShmRegion {
    pub guest_addr: GuestAddress,
    pub size: usize,
    pub file_offset: Option<FileOffset>,
    pub host_name: Option<String>,
}

pub struct ShmManager {
    next_guest_addr: u64,
    page_size: usize,
    conduit_region: Option<ShmRegion>,
    fs_regions: BTreeMap<usize, ShmRegion>,
    gpu_region: Option<ShmRegion>,
}

impl ShmManager {
    pub fn new(info: &ArchMemoryInfo) -> ShmManager {
        Self {
            next_guest_addr: info.shm_start_addr,
            page_size: info.page_size,
            conduit_region: None,
            fs_regions: BTreeMap::new(),
            gpu_region: None,
        }
    }

    pub fn regions(&self) -> Vec<(GuestAddress, usize, Option<FileOffset>)> {
        let mut regions: Vec<(GuestAddress, usize, Option<FileOffset>)> = Vec::new();

        for region in self.fs_regions.iter() {
            regions.push((
                region.1.guest_addr,
                region.1.size,
                region.1.file_offset.clone(),
            ));
        }

        if let Some(region) = &self.conduit_region {
            regions.push((region.guest_addr, region.size, region.file_offset.clone()));
        }

        if let Some(region) = &self.gpu_region {
            regions.push((region.guest_addr, region.size, region.file_offset.clone()));
        }

        regions
    }

    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    pub fn fs_region(&self, index: usize) -> Option<&ShmRegion> {
        self.fs_regions.get(&index)
    }

    pub fn conduit_region(&self) -> Option<&ShmRegion> {
        self.conduit_region.as_ref()
    }

    #[cfg(feature = "gpu")]
    pub fn gpu_region(&self) -> Option<&ShmRegion> {
        self.gpu_region.as_ref()
    }

    fn create_region(&mut self, size: usize) -> Result<ShmRegion, Error> {
        let size = align_upwards!(size, self.page_size);

        let region = ShmRegion {
            guest_addr: GuestAddress(self.next_guest_addr),
            size,
            file_offset: None,
            host_name: None,
        };

        if let Some(addr) = self.next_guest_addr.checked_add(size as u64) {
            self.next_guest_addr = addr;
            Ok(region)
        } else {
            Err(Error::OutOfSpace)
        }
    }

    pub fn create_gpu_region(&mut self, size: usize) -> Result<(), Error> {
        if self.gpu_region.is_some() {
            Err(Error::DuplicatedGpuRegion)
        } else {
            self.gpu_region = Some(self.create_region(size)?);
            Ok(())
        }
    }

    pub fn create_conduit_region(&mut self, size: usize) -> Result<(), Error> {
        if self.conduit_region.is_some() {
            Err(Error::DuplicatedConduitRegion)
        } else {
            let mut region = self.create_region(size)?;
            let (file, name) = krun_virtio_conduit::create_data_shm(region.size)
                .map_err(Error::ConduitShmCreate)?;
            region.file_offset = Some(FileOffset::new(file, 0));
            region.host_name = Some(name);
            self.conduit_region = Some(region);
            Ok(())
        }
    }

    #[cfg(not(feature = "tee"))]
    pub fn create_fs_region(&mut self, index: usize, size: usize) -> Result<(), Error> {
        let region = self.create_region(size)?;
        self.fs_regions.insert(index, region);
        Ok(())
    }
}
