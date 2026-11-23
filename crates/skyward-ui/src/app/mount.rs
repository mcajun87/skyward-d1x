//! The mount page: every partition the phone can mount, each mounted or not.

use super::*;

/// A partition the mount page lists: its name, where it sits, and how it
/// shows now. The runtime fills these in; the page draws them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountRow {
    /// The partition's base name, such as `system` for a logical partition
    /// of super or `cache` for one of the phone's own: the row's title, and
    /// what the runtime acts on. `data` is the data partition, which opens
    /// through decryption rather than a raw mount.
    pub base: String,
    pub point: String,
    pub mounted: bool,
    /// The programs using it, which keep it from being unmounted.
    pub holders: Vec<String>,
}

/// What the mount page's detail page says of a partition beyond whether it
/// is mounted: what it holds, where it is, how much of it is used, and
/// whether it is writable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountDetails {
    /// The filesystem the partition holds, where one can be read; none on a
    /// partition that holds nothing known, or on data before it is opened.
    pub filesystem: Option<String>,
    /// The device the partition is, such as `/dev/block/sda30`, or for a
    /// view of a folder, `bind:/vendor/firmware`.
    pub device: String,
    /// The device-mapper node the partition is shown through, if it is one
    /// of super's logical partitions.
    pub dm: Option<String>,
    pub size: u64,
    pub used: u64,
    pub free: u64,
    /// Read-only where the mount says so; none while it is not mounted.
    pub read_only: Option<bool>,
    /// Whether mounting it can work at all: data opens through decryption,
    /// a partition holding no filesystem cannot be mounted, and a view of a
    /// folder needs the folder's own filesystem mounted.
    pub mountable: bool,
}

impl MountRow {
    /// What the page calls the partition: the name people know it by, which
    /// is not always the by-name link the table uses.
    pub fn label(&self) -> String {
        match self.base.as_str() {
            "omr" => "metadata".into(),
            "persistent" => "persist".into(),
            other => other.into(),
        }
    }
}

/// A mount or unmount the runtime could not carry out. The mount page says
/// so until the next try, or until it is left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountFailure {
    /// Mounting, rather than unmounting.
    pub mounting: bool,
    pub base: String,
    /// The error and its causes.
    pub detail: String,
}

impl App {
    /// Open the filesystem tools on the mount detail's partition alone:
    /// a partition that is not a super mapping and has a device of its own.
    /// `false` where the partition cannot be made afresh this way.
    pub(super) fn open_mount_format(&mut self, at: usize) -> bool {
        let rows = match &self.state.mounts {
            Ok(rows) if at < rows.len() => rows,
            _ => return false,
        };
        let row = &rows[at];
        let details = self
            .state
            .mount_details
            .get(at)
            .cloned()
            .unwrap_or_default();
        let data = row.base == DATA_PARTITION;
        if !data
            && (details.device.is_empty()
                || details.device.starts_with("bind:")
                || details.dm.is_some())
        {
            return false;
        }
        let current = details.filesystem.clone();
        // Both filesystems the recovery can make, including the one it
        // already holds, so a partition can be made afresh as itself.
        let others = vec!["ext4".to_string(), "f2fs".to_string()];
        let chosen = current
            .clone()
            .filter(|fs| others.iter().any(|other| other == fs))
            .unwrap_or_else(|| if data { "f2fs".into() } else { "ext4".into() });
        self.state.filesystems = Some(Ok(vec![FsRow {
            name: row.base.clone(),
            mount_point: row.point.clone(),
            filesystem: current,
            size: details.size,
            others,
        }]));
        self.state.fs_chosen = 0;
        self.state.fs_action = FsAction::Remake(chosen);
        self.open(Screen::Filesystem);
        true
    }

    /// The runtime read the mount table again, or could not: keep it and
    /// show it if it changed.
    pub fn set_mounts(&mut self, mounts: Result<Vec<MountRow>, String>) {
        if self.state.mounts != mounts {
            self.state.mounts = mounts;
            self.refresh();
        }
    }

    /// The runtime read what else the mount page's detail page shows.
    pub fn set_mount_details(&mut self, details: Vec<MountDetails>) {
        if self.state.mount_details != details {
            self.state.mount_details = details;
            self.refresh();
        }
    }

    /// The runtime could not mount or unmount a partition: the mount page
    /// says so, and why.
    pub fn mount_failed(&mut self, failure: MountFailure) {
        self.state.mount_failure = Some(failure);
        self.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testing::*;

    #[test]
    fn home_opens_the_mount_page() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Home, W, H, PPD);
        assert_eq!(
            tap(&mut app, &f, &i, Action::Open(Screen::Mount)),
            vec![Effect::ReadMounts],
            "the page shows the partitions as they are now"
        );
        assert_eq!(app.screen(), Screen::Mount);
    }

    #[test]
    fn an_unreadable_partition_table_leaves_nothing_to_toggle() {
        let (f, i) = (fonts(), info());
        let mut app = opened(Screen::Mount, &f, &i);
        app.set_mounts(Err(
            "read the metadata in super: Input/output error (os error 5)".into(),
        ));
        assert!(app.frame(&f, &i).hits.is_empty());
    }

    #[test]
    fn partitions_mount_while_an_update_waits_to_merge() {
        let (f, mut i) = (fonts(), info());
        i.snapshot = SnapshotState::Snapshotted;
        let mut app = opened(Screen::Mount, &f, &i);
        app.set_mounts(Ok(vec![
            MountRow {
                base: "vendor".into(),
                point: "/vendor".into(),
                mounted: false,
                holders: Vec::new(),
            },
            MountRow {
                base: "odm".into(),
                point: "/odm".into(),
                mounted: true,
                holders: Vec::new(),
            },
        ]));
        let frame = app.frame(&f, &i);
        let actions: Vec<Action> = frame.hits.iter().map(|h| h.action).collect();
        assert!(actions.contains(&Action::MountAll));
        assert!(actions.contains(&Action::UnmountAll));
        assert!(actions.contains(&Action::OpenMount(0)));
        assert!(actions.contains(&Action::OpenMount(1)));
        assert_eq!(
            app.act(Action::MountToggle(0), 0),
            vec![Effect::Mount("vendor".into())],
            "through its snapshot"
        );
    }

    #[test]
    fn the_mount_page_toggles_each_partition() {
        let (f, i) = (fonts(), info());
        let mut app = opened(Screen::Mount, &f, &i);
        app.set_mounts(Ok(vec![
            MountRow {
                base: "system".into(),
                point: "/mnt/system".into(),
                mounted: true,
                holders: Vec::new(),
            },
            MountRow {
                base: "vendor".into(),
                point: "/vendor".into(),
                mounted: false,
                holders: Vec::new(),
            },
        ]));
        let frame = app.frame(&f, &i);
        assert!(
            frame.hits.iter().any(|h| h.action == Action::OpenMount(0)),
            "the first partition opens"
        );
        assert!(
            frame.hits.iter().any(|h| h.action == Action::OpenMount(1)),
            "the second partition opens"
        );
        assert!(
            !frame
                .hits
                .iter()
                .any(|h| matches!(h.action, Action::Toggle(_))),
            "partitions mount read-only"
        );
        // A mounted partition unmounts, an unmounted one mounts.
        assert_eq!(
            app.act(Action::MountToggle(0), 0),
            vec![Effect::Unmount("system".into())]
        );
        assert_eq!(
            app.act(Action::MountToggle(1), 0),
            vec![Effect::Mount("vendor".into())]
        );
    }

    #[test]
    fn a_partition_in_use_cannot_be_unmounted() {
        let (f, i) = (fonts(), info());
        let mut app = opened(Screen::Mount, &f, &i);
        let held = vec!["touch_report".to_string(), "touchsensor".to_string()];
        app.set_mounts(Ok(vec![
            MountRow {
                base: "odm".into(),
                point: "/odm".into(),
                mounted: true,
                holders: held,
            },
            MountRow {
                base: "vendor".into(),
                point: "/vendor".into(),
                mounted: true,
                holders: Vec::new(),
            },
        ]));
        tap(&mut app, &f, &i, Action::OpenMount(0));
        assert_eq!(app.screen(), Screen::MountDetail);
        let frame = app.frame(&f, &i);
        assert!(
            matches!(frame.hits[0].action, Action::Unavailable(_)),
            "the programs using odm keep it"
        );
        let busy = frame.hits[0].action;
        assert!(tap(&mut app, &f, &i, busy).is_empty());
        app.tick(1000);
        assert_eq!(app.deadline(1000), Some(TOAST_MS), "it says why");
    }

    #[test]
    fn a_failed_mount_stays_on_the_page_until_the_next_try() {
        let (f, i) = (fonts(), info());
        let mut app = opened(Screen::Mount, &f, &i);
        app.set_mounts(Ok(vec![MountRow {
            base: "vendor".into(),
            point: "/vendor".into(),
            mounted: false,
            holders: Vec::new(),
        }]));
        let failure = MountFailure {
            mounting: true,
            base: "vendor".into(),
            detail: "mount vendor_b: no filesystem".into(),
        };
        app.mount_failed(failure.clone());
        assert_eq!(app.state.mount_failure, Some(failure.clone()));
        assert_eq!(
            app.act(Action::MountToggle(0), 0),
            vec![Effect::Mount("vendor".into())]
        );
        assert_eq!(app.state.mount_failure, None, "trying again clears it");
        app.mount_failed(failure);
        app.key(Key::Back, 0);
        assert_eq!(app.screen(), Screen::Home);
        assert_eq!(app.state.mount_failure, None, "leaving the page clears it");
    }

    #[test]
    fn the_mount_page_notes_when_there_is_nothing_to_mount() {
        let (f, i) = (fonts(), info());
        let mut app = opened(Screen::Mount, &f, &i);
        let frame = app.frame(&f, &i);
        assert!(
            frame.hits.is_empty(),
            "no partition rows, and nothing else to touch"
        );
    }

    #[test]
    fn a_control_that_cannot_work_explains_itself() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Mount, W, H, PPD);
        app.set_mounts(Ok(vec![MountRow {
            base: "odm".into(),
            point: "/odm".into(),
            mounted: true,
            holders: vec!["qseecomd".into()],
        }]));
        tap(&mut app, &f, &i, Action::OpenMount(0));
        tap(
            &mut app,
            &f,
            &i,
            Action::Unavailable("无法卸载正在使用的分区"),
        );
        assert_eq!(
            app.toast.as_ref().map(|t| t.0.as_str()),
            Some("无法卸载正在使用的分区")
        );
        // Once the row tapped has faded back, only the message waits.
        app.tick(1000);
        assert_eq!(app.deadline(1000), Some(TOAST_MS));
        app.tick(TOAST_MS);
        assert_eq!(app.deadline(TOAST_MS), app.idle_due());
    }
}
