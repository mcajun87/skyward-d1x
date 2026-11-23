//! The first picture the panel shows: the Skyward splash, held while the
//! pages and the touchscreen come up. It is laid on the panel twice because
//! the display driver may remap the scanout memory after the first present,
//! so the second lands on the mapping the panel is really reading.

use crate::art::SPLASH;
use crate::canvas::Canvas;
use crate::surface::Surface;
use std::thread::sleep;
use std::time::Duration;

/// Show the splash on `surface` for `hold`, then leave the panel as it
/// found it.
pub fn show(surface: &mut dyn Surface, picture: &[u8], hold: Duration) -> anyhow::Result<()> {
    let (w, h) = surface.size();
    let canvas = Canvas::from_png(picture, w, h)?;
    surface.present(&canvas)?;
    surface.settle()?;
    surface.present(&canvas)?;
    surface.settle()?;
    sleep(hold);
    Ok(())
}

/// The splash the recovery carries.
pub fn boot(surface: &mut dyn Surface, hold: Duration) -> anyhow::Result<()> {
    show(surface, SPLASH, hold)
}
