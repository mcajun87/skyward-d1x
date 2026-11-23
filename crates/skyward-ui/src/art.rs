//! Pictures the pages carry: the Skyward wordmark the About page lays over
//! its field, and the splash the panel shows before the pages come up.

/// The Skyward wordmark as coverage, 720 × 173: white letters on the
/// supplied mark become ink the About page can tint.
pub const WORDMARK: &[u8] = include_bytes!("../assets/wordmark.png");

/// The splash, 1080 × 2280: the wordmark over a dark field, named for this
/// phone.
pub const SPLASH: &[u8] = include_bytes!("../assets/splash.png");

#[cfg(test)]
mod tests {
    use crate::canvas::Canvas;
    use crate::sprite::Sprite;

    #[test]
    fn the_wordmark_is_coverage_with_ink_and_empty_edges() {
        let mark = Sprite::from_png(super::WORDMARK, 720, 173).expect("the wordmark decodes");
        assert_eq!((mark.w, mark.h), (720, 173));
        assert!(
            mark.cov.iter().any(|&v| v > 200),
            "the letters are solid ink"
        );
        assert_eq!(mark.cov[0], 0, "the picture's corner is empty");
    }

    #[test]
    fn the_splash_covers_the_phone_s_panel() {
        let splash = Canvas::from_png(super::SPLASH, 1080, 2280).expect("the splash decodes");
        assert_eq!((splash.w, splash.h), (1080, 2280));
        assert_eq!(splash.data.len(), 1080 * 2280 * 4);
        assert!(
            splash.data.iter().any(|&v| v > 0),
            "the splash is not blank"
        );
    }
}
