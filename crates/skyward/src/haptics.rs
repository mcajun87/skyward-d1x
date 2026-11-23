use crate::waveform::{RATE, TICKS_RATE, made, scaled, share, ticks};
use anyhow::{Context, Result, anyhow, ensure};
use evdev::raw_stream::RawDevice;
use skyward_config::Strength;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// linux/input-event-codes.h
const EV_FF: u16 = 0x15;
const FF_PERIODIC: u16 = 0x51;
const FF_CUSTOM: u16 = 0x5d;

/// The ticks play at this share of the drive the driver gives samples at in
/// full, whatever the slider says: the 17 Ultra's own system plays them at
/// 3527 mV of the 8500 mV its device tree gives.
const TICKS_STRENGTH: f32 = 0.415;
/// How long the ticks stay loaded once their samples have run out, as the
/// phone's own system leaves them: the motor comes to rest on its own
/// before taking them away brakes it.
const TICKS_REST: Duration = Duration::from_millis(40);
/// How long a timed-output motor runs for the screen-off ticks.
const TICKS_MILLIS: u64 = 40;

/// How long a Samsung timed-output click runs, from 20 ms at the lightest
/// to 80 ms at the strongest.
fn timed_millis(strength: &Strength, position: f32) -> u64 {
    let share = share(strength, position).clamp(0.0, 1.0);
    (20.0 + 60.0 * share).round() as u64
}

/// The vibration motor, played through the kernel's force-feedback
/// events. The driver fills its queue with a made click's samples as the
/// click is loaded, refilling it for no second play, and keeps the click
/// playing after its samples have run out, even when told to stop, until
/// the click is taken away. So each click is loaded as it is played, at the
/// strength the slider gives, and taken away once it has played out.
pub struct Haptics {
    /// The force-feedback motor, if this phone has one.
    dev: Option<File>,
    /// The Samsung timed-output switch, if this phone uses one.
    timed: Option<Timed>,
    click: Click,
    ticks: Click,
    strength: Strength,
    /// Whether the driver is given the strength in the samples it plays.
    scale_samples: bool,
    /// The click playing, by its slot and its count, until it is taken
    /// away; a click taken away early by the next is not taken away again.
    playing: Arc<Mutex<Option<(i16, u64)>>>,
    clicks: u64,
}

/// What a click is.
enum Click {
    /// A waveform the driver keeps, by its number. The driver says how long
    /// it plays as it loads it.
    Kept(i16),
    /// Samples made at the motor's resonant frequency, which the driver
    /// plays as they are, at `rate` a second.
    Samples { data: Vec<i8>, rate: u32 },
}

/// A Samsung motor reached through the timed-output class, or through the
/// older LED class TWRP also knows.
enum Timed {
    /// Writing the milliseconds to `enable` starts the motor.
    Enable(PathBuf),
    /// Writing the milliseconds to `duration`, then 1 to `activate`, starts
    /// it; the driver stops it by itself.
    Leds {
        duration: PathBuf,
        activate: PathBuf,
    },
}

impl Timed {
    fn describe(&self) -> String {
        match self {
            Timed::Enable(path) => path.display().to_string(),
            Timed::Leds { duration, activate } => {
                format!("{} + {}", duration.display(), activate.display())
            }
        }
    }
}

/// The timed-output switch the kernel exposes. The configured path is
/// tried first; the same class may be mounted under /sys/devices, and a
/// Samsung kernel may only expose the older /sys/class/leds/vibrator pair.
fn timed_motor(configured: &str) -> Option<Timed> {
    let candidates = [
        PathBuf::from(configured),
        PathBuf::from("/sys/class/timed_output/vibrator/enable"),
        PathBuf::from("/sys/devices/virtual/timed_output/vibrator/enable"),
    ];
    for path in candidates {
        if OpenOptions::new().write(true).open(&path).is_ok() {
            return Some(Timed::Enable(path));
        }
    }
    let duration = PathBuf::from("/sys/class/leds/vibrator/duration");
    let activate = PathBuf::from("/sys/class/leds/vibrator/activate");
    if OpenOptions::new().write(true).open(&duration).is_ok()
        && OpenOptions::new().write(true).open(&activate).is_ok()
    {
        return Some(Timed::Leds { duration, activate });
    }
    None
}

impl Haptics {
    /// The force-feedback device and the configured click. Loading a click
    /// fills the driver's queue with what it plays, so the click is loaded
    /// only as it is played.
    pub fn open(cfg: &skyward_config::Haptics) -> Result<Haptics> {
        // Samsung's Note10 keeps the motor behind timed_output, as TWRP
        // drives it: writing the milliseconds to run starts the motor and
        // the driver stops it by itself. It is not an evdev FF device.
        if let Some(configured) = &cfg.timed_output {
            // The configured node is the one TWRP uses, but a kernel may
            // expose the same switch under the virtual timed_output class.
            // Try both before falling back to the evdev motor; a missing
            // node must not keep recovery from starting.
            let timed = timed_motor(configured).unwrap_or_else(|| {
                // Keep the configured path even when it cannot be opened
                // now: a write later is best effort, and the recovery must
                // still start if the sysfs node is missing.
                eprintln!("haptics {configured}: no timed-output switch could be opened; writes will be tried");
                Timed::Enable(PathBuf::from(configured))
            });
            eprintln!(
                "haptics {}: Samsung timed output, {:.0}..{:.0} ms",
                timed.describe(),
                timed_millis(&cfg.strength, 0.0),
                timed_millis(&cfg.strength, 1.0)
            );
            return Ok(Haptics {
                dev: None,
                timed: Some(timed),
                click: Click::Kept(0),
                ticks: Click::Kept(0),
                strength: cfg.strength,
                scale_samples: false,
                playing: Arc::new(Mutex::new(None)),
                clicks: 0,
            });
        }
        let (path, dev) = motor()?;
        let hz = resonance(&cfg.resonance)?;
        let click = match cfg.click {
            Some(id) => {
                eprintln!(
                    "haptics {}: clicks with waveform {id}, ticks made for a motor swinging at {hz} Hz",
                    path.display()
                );
                Click::Kept(id)
            }
            None => {
                eprintln!(
                    "haptics {}: clicks and ticks made for a motor swinging at {hz} Hz",
                    path.display()
                );
                Click::Samples {
                    data: made(hz),
                    rate: RATE,
                }
            }
        };
        let ticks = Click::Samples {
            data: ticks(hz),
            rate: TICKS_RATE,
        };
        Ok(Haptics {
            dev: Some(dev),
            timed: None,
            click,
            ticks,
            strength: cfg.strength,
            scale_samples: cfg.scale_samples,
            playing: Arc::new(Mutex::new(None)),
            clicks: 0,
        })
    }

    /// One short click at the strength the slider's `position` gives, after
    /// taking away one still playing. Gives how long it plays.
    pub fn click(&mut self, position: f32) -> Result<Duration> {
        self.start(false, position, share(&self.strength, position))
    }

    /// The ticks of the screen going off, as strong as the phone's own
    /// system plays them whatever the slider says. Gives how long they play.
    pub fn ticks(&mut self) -> Result<Duration> {
        self.start(true, 0.0, TICKS_STRENGTH)
    }

    /// Play the ticks, or else the click, at `share` of its full strength,
    /// after taking away what still plays.
    fn start(&mut self, ticks: bool, position: f32, share: f32) -> Result<Duration> {
        // A timed-output motor takes a duration, not a waveform. The
        // strength slider becomes how long the motor runs: a click is
        // 20..80 ms, and the screen-off ticks are 40 ms, as TWRP's.
        if let Some(timed) = &self.timed {
            let millis = if ticks {
                TICKS_MILLIS
            } else {
                timed_millis(&self.strength, position)
            };
            match timed {
                Timed::Enable(path) => {
                    if let Err(e) = fs::write(path, format!("{millis}\n")) {
                        eprintln!("haptics {}: {e:#}", path.display());
                    }
                }
                Timed::Leds { duration, activate } => {
                    if let Err(e) = fs::write(duration, format!("{millis}\n")) {
                        eprintln!("haptics {}: {e:#}", duration.display());
                    }
                    if let Err(e) = fs::write(activate, "1\n") {
                        eprintln!("haptics {}: {e:#}", activate.display());
                    }
                }
            }
            return Ok(Duration::from_millis(millis));
        }
        let dev = self
            .dev
            .as_mut()
            .context("the motor is not a force-feedback device")?;
        let mut playing = self
            .playing
            .lock()
            .expect("no thread panics while it holds the click playing");
        if let Some((slot, _)) = playing.take() {
            erase(dev, slot).context("take away the click still playing")?;
        }
        let effect = if ticks { &self.ticks } else { &self.click };
        let loaded = upload(dev, effect, share, self.scale_samples).context("load the click")?;
        play(dev, loaded.slot).context("play the click")?;
        self.clicks += 1;
        let this = (loaded.slot, self.clicks);
        *playing = Some(this);
        drop(playing);
        let dev = dev.try_clone().context("share the motor")?;
        let length = loaded.length + if ticks { TICKS_REST } else { Duration::ZERO };
        // Timed from now: a thread may wait a while before it first runs.
        let until = Instant::now() + length;
        let playing = self.playing.clone();
        std::thread::spawn(move || {
            std::thread::sleep(until.saturating_duration_since(Instant::now()));
            let mut playing = playing
                .lock()
                .expect("no thread panics while it holds the click playing");
            if *playing == Some(this) {
                *playing = None;
                if let Err(e) = erase(&dev, this.0) {
                    eprintln!("take away the click: {e}");
                }
            }
        });
        Ok(length)
    }
}

/// Play the configured click once at the slider's `position`, or else the
/// ticks of the screen going off, saying how strongly and for how long, for
/// trying out a motor.
pub fn probe(cfg: &skyward_config::Haptics, position: f32, ticks: bool) -> Result<()> {
    let mut haptics = Haptics::open(cfg)?;
    let (what, strength, length) = if ticks {
        ("ticks", TICKS_STRENGTH, haptics.ticks()?)
    } else {
        (
            "click",
            share(&cfg.strength, position),
            haptics.click(position)?,
        )
    };
    // Once it has played out, what played goes with the device as the
    // command ends.
    std::thread::sleep(length);
    println!(
        "played the {what} at {strength:.3} of the full strength, {} ms long",
        length.as_millis()
    );
    Ok(())
}

/// The first input device under /dev/input that takes periodic
/// force-feedback effects, opened for writing.
fn motor() -> Result<(PathBuf, File)> {
    for (path, dev) in evdev::raw_stream::enumerate() {
        if takes_periodic(&dev) {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .with_context(|| format!("open {}", path.display()))?;
            return Ok((path, file));
        }
    }
    Err(anyhow!("no input device takes force-feedback effects"))
}

fn takes_periodic(dev: &RawDevice) -> bool {
    dev.supported_ff()
        .is_some_and(|ff| ff.contains(evdev::FFEffectCode::FF_PERIODIC))
}

/// The motor's resonant frequency in hertz, from the file the driver says
/// it in, in tenths of a hertz.
fn resonance(file: &str) -> Result<f32> {
    let text = fs::read_to_string(file).with_context(|| format!("read {file}"))?;
    let tenths: u32 = text
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .with_context(|| format!("{file} holds {text:?}"))?;
    ensure!(tenths > 0, "{file} says the motor swings at 0 Hz");
    Ok(tenths as f32 / 10.0)
}

/// A click as the driver loaded it: the slot the kernel keeps it in, and
/// how long it plays.
struct Loaded {
    slot: i16,
    length: Duration,
}

/// Samples handed to the driver to play as they are, as its
/// `custom_fifo_data` lays them out.
#[repr(C)]
struct Samples {
    /// Unused by the driver.
    index: u32,
    length: u32,
    rate: u32,
    data: *const i8,
}

/// Load `click` at `share` of its full strength as a custom periodic
/// effect in a slot of its own. The driver drives the motor at the click's
/// highest voltage times the magnitude; where it is given the strength in
/// the samples it plays, `scale_samples`, they are made that share of
/// themselves and the magnitude is the full one.
fn upload(dev: &File, click: &Click, share: f32, scale_samples: bool) -> Result<Loaded> {
    let share = share.clamp(0.0, 1.0);
    // Kept until the driver has copied what the effect points to.
    let lighter = match click {
        Click::Samples { data, .. } if scale_samples => Some(scaled(data, share)),
        _ => None,
    };
    // The driver tells the two kinds apart by the length in bytes of what
    // the effect points to, and loads nothing for any other length, though
    // the upload still succeeds. For a waveform it keeps it reads the
    // waveform's number from the first of three values and writes how long
    // it plays into the other two, in whole seconds and then milliseconds.
    let mut kept: [i16; 3] = [0; 3];
    let mut samples = Samples {
        index: 0,
        length: 0,
        rate: RATE,
        data: std::ptr::null(),
    };
    let (len, data) = match click {
        Click::Kept(id) => {
            kept[0] = *id;
            (std::mem::size_of_val(&kept), kept.as_mut_ptr())
        }
        Click::Samples { data, rate } => {
            samples.length = u32::try_from(data.len())?;
            samples.rate = *rate;
            samples.data = lighter.as_deref().unwrap_or(data).as_ptr();
            (
                std::mem::size_of::<Samples>(),
                (&mut samples as *mut Samples).cast::<i16>(),
            )
        }
    };
    let periodic = libc::ff_periodic_effect {
        waveform: FF_CUSTOM,
        period: 0,
        magnitude: if lighter.is_some() {
            i16::MAX
        } else {
            (share * f32::from(i16::MAX)).round() as i16
        },
        offset: 0,
        phase: 0,
        envelope: libc::ff_envelope {
            attack_length: 0,
            attack_level: 0,
            fade_length: 0,
            fade_level: 0,
        },
        custom_len: len as u32,
        custom_data: data,
    };
    let mut effect = libc::ff_effect {
        type_: FF_PERIODIC,
        id: -1,
        direction: 0,
        trigger: libc::ff_trigger {
            button: 0,
            interval: 0,
        },
        replay: libc::ff_replay {
            length: 0,
            delay: 0,
        },
        u: [0; 4],
    };
    // The union holds the periodic effect; it is exactly as large.
    const _: () =
        assert!(std::mem::size_of::<libc::ff_periodic_effect>() == std::mem::size_of::<[u64; 4]>());
    effect.u = unsafe { std::mem::transmute::<libc::ff_periodic_effect, [u64; 4]>(periodic) };
    // EVIOCSFF: _IOW('E', 0x80, struct ff_effect)
    let size = std::mem::size_of::<libc::ff_effect>() as u32;
    let request = (1u32 << 30) | (size << 16) | (u32::from(b'E') << 8) | 0x80;
    if unsafe { libc::ioctl(dev.as_raw_fd(), request as _, &mut effect) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let length = match click {
        Click::Kept(id) => {
            let [_, seconds, millis] = kept;
            let length = Duration::from_secs(u64::try_from(seconds)?)
                + Duration::from_millis(u64::try_from(millis)?);
            ensure!(
                !length.is_zero(),
                "the driver loaded waveform {id} without saying how long it plays"
            );
            length
        }
        // The queue is full before the samples start playing.
        Click::Samples { data, rate } => {
            Duration::from_secs_f64(data.len() as f64 / f64::from(*rate))
        }
    };
    Ok(Loaded {
        slot: effect.id,
        length,
    })
}

/// Start the loaded effect in slot `id`.
fn play(dev: &mut File, id: i16) -> io::Result<()> {
    let event = libc::input_event {
        time: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        type_: EV_FF,
        code: id as u16,
        value: 1,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&event as *const libc::input_event).cast::<u8>(),
            std::mem::size_of::<libc::input_event>(),
        )
    };
    dev.write_all(bytes)
}

/// Take the effect in slot `id` away, which stops it for good.
fn erase(dev: &File, id: i16) -> io::Result<()> {
    // EVIOCRMFF: _IOW('E', 0x81, int)
    let request = (1u32 << 30)
        | ((std::mem::size_of::<libc::c_int>() as u32) << 16)
        | (u32::from(b'E') << 8)
        | 0x81;
    if unsafe { libc::ioctl(dev.as_raw_fd(), request as _, libc::c_int::from(id)) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
