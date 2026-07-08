use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

use crate::MAX_MESSAGE_SIZE;

pub struct RefGuard {
    buffer: Vec<u8>,
    pool: Arc<BufferPool>,
}

impl Deref for RefGuard {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for RefGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl Drop for RefGuard {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buffer);
        self.pool.push(buf);
    }
}

pub struct BufferPool {
    free: Mutex<Vec<Vec<u8>>>,
}

impl BufferPool {
    fn alloc() -> Vec<u8> {
        Vec::with_capacity(MAX_MESSAGE_SIZE)
    }

    pub fn new(size: usize) -> Self {
        Self {
            free: Mutex::new((0..size).map(|_| Self::alloc()).collect()),
        }
    }

    fn push(&self, mut buf: Vec<u8>) {
        let mut free = self.free.lock().unwrap();
        if free.len() != free.capacity() {
            buf.clear();
            free.push(buf);
        }
    }

    pub fn pop(self: Arc<Self>) -> RefGuard {
        let buf = self.free.lock().unwrap().pop().unwrap_or_else(Self::alloc);
        RefGuard {
            buffer: buf,
            pool: self,
        }
    }
}
