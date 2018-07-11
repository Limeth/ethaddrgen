use super::{ADDRESS_BYTES, ADDRESS_BYTE_INDEX, SECRET_KEY_SIZE, Context, BruteforceResult, to_hex_string};
use std::sync::mpsc::{Sender, Receiver};
use patterns::{PatternType, Patterns, StringPatterns, RegexPatterns};
use std::fmt;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread;
use std::thread::JoinHandle;
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicUsize};
use std::time::Duration;
use clap::{Arg, ArgMatches};
use rand::{Rng, OsRng, RngCore};
use regex::Regex;
use secp256k1::Secp256k1;
use secp256k1::key::{SecretKey, PublicKey};
use termcolor::{Color, ColorChoice, Buffer, BufferWriter};
use typenum::U40;
use tiny_keccak;
use ocl::Context as OpenCLContext;
use ocl::Device as OpenCLDevice;
use ocl::enums::{DeviceInfo, DeviceInfoResult};
use bus::Bus;

const RESULT_QUEUE_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Address([u8; ADDRESS_BYTES]);

impl<'a> From<&'a [u8]> for Address {
    fn from(slice: &'a [u8]) -> Self {
        let mut result = Address::default();

        result.0.copy_from_slice(slice);

        result
    }
}

/// A secret key with the corresponding address that matches the provided dictionary
pub struct Match {
    pub seckey: SecretKey,
    pub address: Address,
}

#[derive(Clone)]
pub enum WorkerCommand {
    Abort,
}

#[derive(Clone)]
pub struct RequestContext<P: Patterns + 'static> {
    pub patterns: P,
    pub stream: bool,
    pub incremental: bool,
    pub quiet: bool,
}

impl<P: Patterns + 'static> RequestContext<P> {
    pub fn new(matches: ArgMatches, patterns: P) -> Self {
        Self {
            patterns,
            stream: matches.is_present("stream"),
            incremental: matches.is_present("incremental"),
            quiet: matches.is_present("quiet"),
        }
    }
}

pub struct WorkerContext<P: Patterns + 'static> {
    request_context: Arc<RequestContext<P>>,
    alg: Arc<Secp256k1>,
    match_bus: Bus<Match>,
    // match_sender: Sender<Match>,
    command_bus: Bus<WorkerCommand>,
    // command_sender: Sender<WorkerCommand>,
    // command_receiver: Option<Receiver<WorkerCommand>>,
    iterations_this_second: Arc<AtomicUsize>,
}

impl<P: Patterns + 'static> WorkerContext<P> {
    pub fn new(request_context: Arc<RequestContext<P>>) -> Self {
        Self {
            request_context,
            alg: Arc::new(Secp256k1::new()),
            match_bus: Bus::new(RESULT_QUEUE_CAPACITY * 4),
            command_bus: Bus::new(1),
            iterations_this_second: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum WorkerDeviceType {
    Native,
    OpenCL(usize),
}

impl WorkerDeviceType {
    pub fn create_worker<P: Patterns + 'static>(&self, context: &OpenCLContext, request_context: Arc<RequestContext<P>>)
            -> Result<Box<dyn Worker<P>>, String> {
        match (*self, <P as Patterns>::ty()) {
            (WorkerDeviceType::Native, PatternType::String) => Ok(Box::new(NativeWorker::new(WorkerContext::new(request_context)))),
            (WorkerDeviceType::Native, PatternType::Regex) => Ok(Box::new(NativeWorker::new(WorkerContext::new(request_context)))),
            // TODO
            (WorkerDeviceType::OpenCL(device_index), PatternType::String) => unimplemented!(),
            (WorkerDeviceType::OpenCL(_), PatternType::Regex) => {
                Err(format!("Regex patterns are not supported by OpenCL devices."))
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct WorkerDevice {
    pub id: String,
    pub ty: WorkerDeviceType,
    pub description: String,
}

impl WorkerDevice {
    pub fn native() -> Self {
        WorkerDevice {
            id: "native".to_string(),
            ty: WorkerDeviceType::Native,
            description: "Native (The CPU your OS uses)".to_string(),
        }
    }

    pub fn ocl(context: &OpenCLContext, device_index: usize) -> Self {
        let ty = context.device_info(device_index, DeviceInfo::Type).unwrap();
        let name = context.device_info(device_index, DeviceInfo::Name).unwrap();
        let vendor = context.device_info(device_index, DeviceInfo::Vendor).unwrap();
        let driver_version = context.device_info(device_index, DeviceInfo::DriverVersion).unwrap();

        WorkerDevice {
            id: format!("ocl-{}", device_index), // TODO: Use PCI-E info to identify reliably
            ty: WorkerDeviceType::OpenCL(device_index),
            description: format!("OpenCl Device: {} ({}, {}, {})",
                                 name, ty, vendor, driver_version),
        }
    }

    pub fn create_worker<P: Patterns + 'static>(&self, ocl_context: &OpenCLContext, request_context: Arc<RequestContext<P>>)
            -> Result<Box<dyn Worker<P>>, String> {
        self.ty.create_worker(ocl_context, request_context)
    }
}

pub trait Worker<P: Patterns + 'static> {
    fn context_ref(&self) -> &WorkerContext<P>;
    fn context_mut(&mut self) -> &mut WorkerContext<P>;
    fn begin_work(self) -> JoinHandle<()>;
}

pub struct NativeWorker<P: Patterns + 'static> {
    pub worker_context: WorkerContext<P>,
}

impl<P: Patterns + 'static> NativeWorker<P> {
    fn new(worker_context: WorkerContext<P>) -> Self {
        Self {
            worker_context
        }
    }

    fn increment(bytes: &mut [u8]) -> bool {
        let len = bytes.len();
        let (mut rest, last) = bytes.split_at_mut(len - 1);

        if last[0] == 0xFF {
            last[0] = 0x00;

            if rest.len() > 0 {
                Self::increment(&mut rest)
            } else {
                true
            }
        } else {
            last[0] += 1;

            false
        }
    }

    fn iterations_this_second(&self) -> Arc<AtomicUsize> {
        self.worker_context.iterations_this_second.clone()
    }
}

impl<P: Patterns + 'static> Worker<P> for NativeWorker<P> {
    fn context_ref(&self) -> &WorkerContext<P> {
        &self.worker_context
    }

    fn context_mut(&mut self) -> &mut WorkerContext<P> {
        &mut self.worker_context
    }

    fn begin_work(mut self) -> JoinHandle<()> {
        // let command_receiver: Receiver<WorkerCommand> = self.worker_context.command_receiver.take()
        //     .expect("Worker already started.");
        let mut command_receiver = self.worker_context.command_bus.add_rx();

        thread::spawn(move || {
            let mut rng = OsRng::new()
                .expect("Could not create a secure random number generator. Please file a GitHub issue.");
            let mut bytes = [0u8; SECRET_KEY_SIZE];

            rng.fill_bytes(&mut bytes);

            let mut derive_next_secret_key: Box<FnMut(&mut [u8]) + Send> = if self.worker_context.request_context.incremental {
                Box::new(|seckey| { Self::increment(seckey); })
            } else {
                Box::new(move |seckey| rng.fill_bytes(seckey))
            };

            'dance:
            loop {
                for worker_command in (&mut command_receiver).iter() {
                    match worker_command {
                        WorkerCommand::Abort => { break 'dance; }
                    }
                }

                let private_key = match SecretKey::from_slice(&*self.worker_context.alg, &bytes) {
                    Ok(private_key) => private_key,
                    Err(_) => continue,
                };
                let public_key = match PublicKey::from_secret_key(&*self.worker_context.alg, &private_key) {
                    Ok(public_key) => public_key,
                    Err(_) => continue,
                };
                let public_key_array = &public_key.serialize()[1..];
                let keccak = tiny_keccak::keccak256(public_key_array);
                let address = to_hex_string(&keccak[ADDRESS_BYTE_INDEX..], 40);  // get rid of the constant 0x04 byte

                if self.worker_context.request_context.patterns.contains(&address) {
                    self.worker_context.match_bus.broadcast(Match {
                        seckey: SecretKey::from_slice(&self.worker_context.alg, &private_key[..]).expect("Matched invalid secret key, aborting."),
                        address: Address::from(&keccak[ADDRESS_BYTE_INDEX..]),
                    });

                    if !self.worker_context.request_context.stream {
                        break 'dance;
                    }
                }

                self.worker_context.iterations_this_second.fetch_add(1, Ordering::Relaxed);

                derive_next_secret_key(&mut bytes);
            }
        })
    }
}
