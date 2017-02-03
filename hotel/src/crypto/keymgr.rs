use core::cell::Cell;
use core::mem;
use hil::aes::{self, AesClient, Interrupt, AesModule, ParsedInterrupt};
use hil::digest::{DigestEngine, DigestMode, DigestError};
use kernel::common::volatile_cell::VolatileCell;
use super::keymgr::{KEYMGR0_REGS, Registers};

#[allow(unused)]
enum ShaTrigMask {
    Go = 0x1,
    Reset = 0x2,
    Step = 0x4,
    Stop = 0x8,
}

#[allow(unused)]
enum ShaCfgEnMask {
    BigEndian = 0x01,
    Sha1 = 0x02,

    BusError = 0x08,
    Livestream = 0x10,
    Hmac = 0x20,

    IntEnDone = 0x1_0000,
    IntMaskDone = 0x2_0000,
}

pub struct KeymgrEngine {
    regs: *mut Registers,
    client: Cell<Option<&'static AesClient>>,
    current_mode: Option<DigestMode>,
}

impl KeymgrEngine {
    const unsafe fn new(regs: *mut Registers) -> KeymgrEngine {
        KeymgrEngine {
            regs: regs,
            client: Cell::new(None),
        }
    }

    pub fn set_client(&self, client: &'static AesClient) {
        self.client.set(Some(client));
    }

    pub fn setup(&self, key_size: aes::KeySize, key: &[u32; 8]) {
        let ref regs = unsafe { &*self.regs }.aes;

        self.enable_all_interrupts();
        regs.ctrl.set(regs.ctrl.get() | key_size as u32 | AesModule::Enable as u32);

        for (i, word) in key.iter().enumerate() {
            regs.key[i].set(*word);
        }
        regs.key_start.set(1);
    }

    pub fn set_encrypt_mode(&self, encrypt: bool) {
        let ref regs = unsafe { &*self.regs }.aes;

        let flag = aes::Mode::Encrypt as u32;
        if encrypt {
            regs.ctrl.set(regs.ctrl.get() | flag);
        } else {
            regs.ctrl.set(regs.ctrl.get() & !flag);
        }
    }

    pub fn crypt(&self, input: &[u8]) -> usize {
        let ref regs = unsafe { &*self.regs }.aes;

        let mut written_bytes = 0;
        let mut written_words = 0;
        for word in input.chunks(4) {
            if regs.wfifo_full.get() != 0 || written_bytes >= 16 {
                break;
            }
            let d = word.iter()
                .map(|b| *b as u32)
                .enumerate()
                .fold(0, |accm, (i, byte)| accm | (byte << (i * 8)));
            regs.wfifo_data.set(d);
            written_bytes += word.len();
            written_words += 1;
        }

        // Make sure we wrote 128 bits (4 words)
        for _ in written_words..4 {
            regs.wfifo_data.set(0);
        }

        written_bytes
    }

    pub fn read_data(&self, output: &mut [u8]) -> usize {
        let ref regs = unsafe { &*self.regs }.aes;

        let mut i = 0;
        while regs.rfifo_empty.get() == 0 {
            if output.len() > i + 3 {
                let word = regs.rfifo_data.get();
                output[i + 0] = (word >> 0) as u8;
                output[i + 1] = (word >> 8) as u8;
                output[i + 2] = (word >> 16) as u8;
                output[i + 3] = (word >> 24) as u8;
                i += 4;
            } else {
                println!("Can't read any more data");
                break;
            }
        }

        i
    }

    pub fn enable_all_interrupts(&self) {
        self.enable_interrupt(Interrupt::WFIFOOverflow);
        self.enable_interrupt(Interrupt::RFIFOOverflow);
        self.enable_interrupt(Interrupt::RFIFOUnderflow);
        self.enable_interrupt(Interrupt::DoneCipher);
        self.enable_interrupt(Interrupt::DoneKeyExpansion);
        self.enable_interrupt(Interrupt::DoneWipeSecrets);
    }

    pub fn finish(&self) {
        let ref regs = unsafe { &*self.regs }.aes;

        regs.int_enable.set(0);
        regs.ctrl.set(0);
        regs.wipe_secrets.set(1);
    }

    pub fn enable_interrupt(&self, interrupt: Interrupt) {
        let ref regs = unsafe { &*self.regs }.aes;

        let current = regs.int_enable.get();
        regs.int_enable.set(current | (1 << interrupt as usize));
    }

    pub fn clear_interrupt(&self, interrupt: Interrupt) {
        let ref regs = unsafe { &*self.regs }.aes;

        regs.int_state.set(1 << interrupt as usize);
    }

    pub fn handle_interrupt(&self, interrupt: u32) {
        if let ParsedInterrupt::Found(int) = interrupt.into() {
            self.client.get().map(|client| match int {
                Interrupt::DoneCipher => client.done_cipher(),
                Interrupt::DoneKeyExpansion => client.done_key_expansion(),
                Interrupt::DoneWipeSecrets => client.done_wipe_secrets(),
                _ => println!("Interrupt {:?} fired", int),
            });
            self.clear_interrupt(int);
        } else {
            panic!("KeymgrEngine: Unexpected interrupt: {}", interrupt);
        }
    }
}

impl DigestEngine for KeymgrEngine {
    fn initialize(&mut self, mode: DigestMode) -> Result<(), DigestError> {
        let ref regs = unsafe { &*self.regs }.sha;

        // Compile-time check for DigestMode exhaustiveness
        match mode {
            DigestMode::Sha1 |
            DigestMode::Sha256 => (),
        };
        self.current_mode = Some(mode);

        regs.trig.set(ShaTrigMask::Stop as u32);

        let mut flags = ShaCfgEnMask::Livestream as u32 | ShaCfgEnMask::IntEnDone as u32;
        match mode {
            DigestMode::Sha1 => flags |= ShaCfgEnMask::Sha1 as u32,
            DigestMode::Sha256 => (),
        }
        regs.cfg_en.set(flags);

        regs.trig.set(ShaTrigMask::Go as u32);

        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> Result<usize, DigestError> {
        let ref regs = unsafe { &*self.regs }.sha;

        if self.current_mode.is_none() {
            return Err(DigestError::NotConfigured);
        }

        let fifo_u8: &VolatileCell<u8> = unsafe { mem::transmute(&regs.input_fifo) };

        // TODO(yuriks): Feed FIFO word at a time when possible
        for b in data {
            fifo_u8.set(*b);
        }

        Ok(data.len())
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<usize, DigestError> {
        let ref regs = unsafe { &*self.regs }.sha;

        let expected_output_size = match self.current_mode {
            None => return Err(DigestError::NotConfigured),
            Some(mode) => mode.output_size(),
        };
        if output.len() < expected_output_size {
            return Err(DigestError::BufferTooSmall(expected_output_size));
        }

        // Tell hardware we're done streaming and then wait for the hash calculation to finish.
        regs.itop.set(0);
        regs.trig.set(ShaTrigMask::Stop as u32);
        while regs.itop.get() == 0 {}

        for i in 0..(expected_output_size / 4) {
            let word = regs.sts_h[i].get();
            output[i * 4 + 0] = (word >> 0) as u8;
            output[i * 4 + 1] = (word >> 8) as u8;
            output[i * 4 + 2] = (word >> 16) as u8;
            output[i * 4 + 3] = (word >> 24) as u8;
        }

        regs.itop.set(0);

        Ok(expected_output_size)
    }
}

pub static mut KEYMGR: KeymgrEngine = unsafe { KeymgrEngine::new(KEYMGR0_REGS) };
