//! d1x's pages at the phone's own size, for looking at before a build is
//! flashed. This binary draws the pages with the same UI code the recovery
//! runs; it is not a mock.

use anyhow::Result;
use png::Encoder;
use skyward_config::DeviceConfig;
use skyward_info::{Battery, Boot, Charge, Cpu, DeviceInfo, PatchLevel, Storage};
use skyward_ui::app::{App, Data, MountDetails, MountRow, Screen};
use skyward_ui::canvas::Canvas;
use skyward_ui::pages::{self, Ctx};
use skyward_ui::{widgets, Fonts, Lang};
use skyward_vab::SnapshotState;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

const CLOCK: &str = "23:46";
const LISTED: i64 = 1_792_424_760;
const W: u32 = 1080;
const H: u32 = 2280;
const PPD: f32 = 2.625;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let out = PathBuf::from(args.get(1).map(String::as_str).unwrap_or("d1x-ui"));
    std::fs::create_dir_all(&out)?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fonts = Fonts::load(
        root.join("resources/fonts/MiSansVF.ttf"),
        0,
        root.join("resources/fonts/KirkMono-Regular.ttf"),
    )?;
    let cfg = DeviceConfig::load(root.join("devices/d1x.toml"))?;
    let info = d1x(&cfg);
    let mounts = d1x_mounts();
    let details = d1x_details();
    let data_at = mounts
        .iter()
        .position(|m| m.base == "data")
        .expect("data is in the table");

    // The home page, long enough to hold every entry the 0.5.12 build added.
    let mut app = base(Screen::Home);
    app.state.data = Data::Open;
    write_png(
        &out.join("01-home.png"),
        &whole_page(&mut app, &fonts, &info),
    )?;

    // The mount page, grouped as OrangeFox groups its manage-partitions page.
    let mut app = base(Screen::Mount);
    app.set_mounts(Ok(mounts.clone()));
    app.set_mount_details(details.clone());
    write_png(
        &out.join("02-mount.png"),
        &whole_page(&mut app, &fonts, &info),
    )?;

    // One partition's details: Data, with the format and filesystem entries.
    let mut app = base(Screen::MountDetail);
    app.set_mounts(Ok(mounts.clone()));
    app.set_mount_details(details.clone());
    app.state.mount_chosen = data_at;
    screen_png(&mut app, &fonts, &info, &out.join("03-mount-data.png"))?;
    write_png(
        &out.join("03b-mount-data-full.png"),
        &whole_page(&mut app, &fonts, &info),
    )?;

    // The wipe page, with the OrangeFox-style typed confirmation at its foot.
    let mut app = base(Screen::Wipe);
    app.state.cache_partition = true;
    app.state.wipe[0] = true;
    write_png(
        &out.join("04-wipe.png"),
        &whole_page(&mut app, &fonts, &info),
    )?;

    // Typing `yes` before Data is formatted.
    let mut app = base(Screen::WipeYes);
    app.state.wipe_yes = "yes".into();
    screen_png(&mut app, &fonts, &info, &out.join("05-wipe-yes.png"))?;

    // The five restart targets OrangeFox offers, and Bootloader besides.
    let mut app = base(Screen::Reboot);
    screen_png(&mut app, &fonts, &info, &out.join("06-reboot.png"))?;

    // ADB sideload, the way OrangeFox puts it on its ADB page.
    let mut app = base(Screen::Install);
    screen_png(&mut app, &fonts, &info, &out.join("07-adb.png"))?;

    // The three pages that stay Skyward rather than OrangeFox.
    let mut app = base(Screen::Settings);
    screen_png(&mut app, &fonts, &info, &out.join("08-settings.png"))?;

    let mut app = base(Screen::About);
    screen_png(&mut app, &fonts, &info, &out.join("09-about.png"))?;

    let mut app = base(Screen::Specs);
    screen_png(&mut app, &fonts, &info, &out.join("10-specs.png"))?;

    println!("wrote {}", out.display());
    Ok(())
}

fn base(screen: Screen) -> App {
    let mut app = App::new(screen, W, H, PPD);
    app.state.lang = Lang::Hans;
    app.state.data = Data::Open;
    app.set_now(LISTED);
    app
}

fn screen_png(app: &mut App, f: &Fonts, info: &DeviceInfo, path: &Path) -> Result<()> {
    app.tick(LISTED as u64);
    let mut c = Canvas::new(W, H);
    app.compose(&mut c, f, info, CLOCK, 0);
    write_png(path, &c)
}

fn write_png(path: &Path, canvas: &Canvas) -> Result<()> {
    let file = File::create(path)?;
    let mut enc = Encoder::new(BufWriter::new(file), canvas.w, canvas.h);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(&canvas.data)?;
    Ok(())
}

fn whole_page(app: &mut App, f: &Fonts, info: &DeviceInfo) -> Canvas {
    let t = app.theme();
    let (screen, state) = (app.screen(), app.state.clone());
    let frame = app.whole_frame(f, info);
    let mut c = Canvas::new(frame.canvas.w, frame.height(&t) as u32);
    c.clear(frame.bg);
    c.put(&frame.canvas, 0);
    if let Some(fold) = &frame.fold {
        fold.draw(
            &mut c,
            &t,
            &widgets::search_words(&t, f, fold.bar, fold.hint),
            0.0,
        );
    }
    if let Some(rows) = &frame.rows {
        let cx = Ctx {
            t: &t,
            f,
            info,
            state: &state,
            term: None,
            band: None,
        };
        for k in 0..rows.count() {
            let mut row = Canvas::new(c.w, (rows.edges[k + 1] - rows.edges[k]) as u32);
            pages::row(screen, &cx, k, &mut row);
            c.put(&row, rows.edges[k] as i32);
        }
    }
    if let Some(p) = &frame.pinned {
        c.put(&p.canvas, p.top.round() as i32);
    }
    if let Some(d) = &frame.dock {
        c.put(&d.canvas, (c.h - d.canvas.h) as i32);
    }
    widgets::status_bar(&mut c, &t, f, &app.bar(CLOCK, info), t.pal.status);
    c
}

fn d1x(cfg: &DeviceConfig) -> DeviceInfo {
    DeviceInfo {
        model: "Galaxy Note10 5G".into(),
        codename: "d1x".into(),
        soc: cfg.device.soc.clone(),
        cpu: Cpu {
            cores: 8,
            max_khz: Some(2_726_400),
        },
        ram_kib: 12 * 1024 * 1024,
        panel: Some((W, H)),
        screen: Some(6.7),
        os_version: Some("CP2A.260605.016".into()),
        android: Some("17".into()),
        locale: Some("zh-CN".into()),
        time_zone: Some("Asia/Shanghai".into()),
        security_patch: Some(PatchLevel {
            year: 2026,
            month: 11,
            day: 1,
        }),
        kernel: "4.14.190-30305025-abogki".into(),
        storage: Storage {
            total: 256_060_514_304,
            free: Some(196_060_514_304),
        },
        battery: Some(Battery {
            level: 62,
            charge: Charge::Discharging,
            temp: Some(300),
            health: Some("Good".into()),
            cycles: Some(412),
            design: Some(3_500_000),
            rated: Some(5_000_000),
            full: Some(4_780_000),
            voltage: Some(4_010_000),
            quick: false,
            plugged: false,
        }),
        slot: None,
        snapshot: SnapshotState::None,
        boot: Boot {
            unlocked: Some(true),
            verified: Some("orange".into()),
        },
    }
}

fn d1x_mounts() -> Vec<MountRow> {
    [
        ("system", "/mnt/system", true),
        ("system_ext", "/mnt/system_ext", true),
        ("vendor", "/vendor", true),
        ("product", "/mnt/product", true),
        ("odm", "/odm", true),
        ("cache", "/cache", false),
        ("efs", "/mnt/vendor/efs", true),
        ("keydata", "/keydata", false),
        ("keyrefuge", "/keyrefuge", false),
        ("sec_efs", "/sec_efs", false),
        ("sdcard1", "/sdcard1", false),
        ("usb_otg", "/usb_otg", false),
        ("metadata", "/metadata", true),
        ("data", "/data", true),
    ]
    .into_iter()
    .map(|(base, point, mounted)| MountRow {
        base: base.into(),
        point: point.into(),
        mounted,
        holders: Vec::new(),
    })
    .collect()
}

fn d1x_details() -> Vec<MountDetails> {
    let gb = 1_000_000_000;
    let d = |filesystem: &str,
             device: &str,
             dm: Option<&str>,
             size: u64,
             used: u64,
             read_only: Option<bool>,
             mountable: bool| MountDetails {
        filesystem: Some(filesystem.into()),
        device: device.into(),
        dm: dm.map(String::from),
        size,
        used,
        free: size.saturating_sub(used),
        read_only,
        mountable,
    };
    vec![
        d("ext4", "/dev/block/dm-0", Some("dm-0"), 5 * gb, 4 * gb, Some(true), true),
        d("ext4", "/dev/block/dm-1", Some("dm-1"), gb, 700_000_000, Some(true), true),
        d("ext4", "/dev/block/dm-2", Some("dm-2"), 3 * gb, 2 * gb, Some(true), true),
        d("ext4", "/dev/block/dm-3", Some("dm-3"), 3 * gb, 2 * gb, Some(true), true),
        d("ext4", "/dev/block/dm-4", Some("dm-4"), gb, 600_000_000, Some(true), true),
        d("ext4", "/dev/block/sda29", None, 64 * 1_000_000, 3 * 1_000_000, Some(false), true),
        d("ext4", "/dev/block/sda31", None, 20 * 1_000_000, 8 * 1_000_000, Some(false), true),
        d("ext4", "/dev/block/sda32", None, 32 * 1_000_000, 4 * 1_000_000, Some(false), true),
        d("ext4", "/dev/block/sda33", None, 32 * 1_000_000, 4 * 1_000_000, Some(false), true),
        d("ext4", "/dev/block/sda34", None, 32 * 1_000_000, 4 * 1_000_000, Some(false), true),
        MountDetails::default(),
        MountDetails::default(),
        d("ext4", "/dev/block/sda30", None, 64 * 1_000_000, 7 * 1_000_000, Some(true), true),
        d("ext4", "/dev/block/dm-5", Some("dm-5"), 256 * gb, 42 * gb, Some(false), true),
    ]
}
