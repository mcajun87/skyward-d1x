//! The phone's keymaster, of the kind that registers with the hardware
//! directory rather than the service directory: keymaster 4.0, which is
//! what d1x serves. The newer KeyMint interface in [`crate::keymint`] is
//! a different interface on a different driver, and a phone has one or the
//! other; this is the one whose method numbers include the HMAC-sharing
//! calls that 4.0 added before `begin`.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

#[allow(unused_imports)]
use anyhow::{Context, Result, bail};
#[allow(unused_imports)]
use skyward_binder::hidl::{Answer, Message};

/// The hardware service, as it registers with the hardware directory.
pub const HARDWARE_SERVICE: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
pub const INSTANCE: &str = "default";

/// Method numbers, in the order the 4.0 interface declares them. 4.0 puts
/// `getHmacSharingParameters`, `computeSharedHmac`, `verifyAuthorization`
/// and `addRngEntropy` before `generateKey`, so every operation after them
/// sits four places further along than it did in 3.0.
const GET_HARDWARE_INFO: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 9;
const EXPORT_KEY: u32 = 10;
const BEGIN: u32 = 16;
const UPDATE: u32 = 17;
const FINISH: u32 = 18;
const ABORT: u32 = 19;

const KEY_FORMAT_RAW: i32 = 3;

const PURPOSE_DECRYPT: i32 = 1;
const PURPOSE_ENCRYPT: i32 = 0;
const BLOCK_MODE_GCM: i32 = 32;
const PADDING_NONE: i32 = 1;

const TAG_PURPOSE: i32 = 536_870_913;
const TAG_ALGORITHM: i32 = 536_870_914;
const TAG_KEY_SIZE: i32 = 536_870_915;
const TAG_BLOCK_MODE: i32 = 536_870_916;
const TAG_PADDING: i32 = 536_870_918;
const TAG_MAC_LENGTH: i32 = 805_307_371;
const TAG_NO_AUTH_REQUIRED: i32 = 491;
const TAG_APPLICATION_ID: i32 = -1_879_047_591;
const TAG_NONCE: i32 = -1_879_047_191;

const ALGORITHM_AES: i32 = 32;

/// The two keys a hardware auth token carries in its MAC, and the length
/// the service expects. An empty token has no MAC and every number zero.
#[allow(dead_code)]
const AUTH_MAC_LENGTH: usize = 32;

/// What the service says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardware {
    pub security_level: i32,
    pub name: String,
    pub author: String,
}

/// The phone's keymaster 4.0, as this program talks to it.
#[cfg(target_os = "android")]
pub struct Keymaster<'a> {
    device: skyward_binder::driver::Handle<'a>,
}

#[cfg(target_os = "android")]
impl<'a> Keymaster<'a> {
    /// Reach the running service, or say that none is.
    pub fn open(hardware: &'a skyward_binder::driver::Binder) -> Result<Keymaster<'a>> {
        let device = skyward_binder::hidl::find(hardware, HARDWARE_SERVICE, INSTANCE)?.with_context(|| {
            format!("{HARDWARE_SERVICE} is not running; the phone's key service has to be started first")
        })?;
        Ok(Keymaster { device })
    }

    /// Ask the service what it is. It takes nothing and changes nothing,
    /// so it is what to call to see that the service answers at all.
    pub fn hardware(&self) -> Result<Hardware> {
        let what = "ask the key service about itself";
        let reply = self
            .device
            .transact(GET_HARDWARE_INFO, &Message::call(HARDWARE_SERVICE))
            .context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let security_level = read.i32().context("read where the keys are kept")?;
        let name = read.string().context("read the key service's name")?;
        let author = read.string().context("read who wrote the key service")?;
        Ok(Hardware {
            security_level,
            name,
            author,
        })
    }

    /// What the service says the key in `key_blob` may be used for.
    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.bytes(key_blob);
        call.bytes(app_id);
        call.bytes(&[]);
        let reply = self
            .device
            .transact(GET_KEY_CHARACTERISTICS, &call)
            .context("ask what the key may be used for")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("ask what the key may be used for")?;
        let error = read.i32().context("read whether the key was understood")?;
        if error != 0 {
            bail!("the key service refused the key with its code {error}");
        }
        // KeyCharacteristics is two vectors of parameters: the ones the
        // software enforces, then the ones the hardware enforces.
        let mut out = Vec::new();
        for _ in 0..2 {
            let parameters = read
                .vector()
                .context("read the authorizations that came back")?;
            for parameter in parameters.as_chunks::<32>().0 {
                let tag = i32::from_le_bytes(parameter[0..4].try_into().expect("four bytes"));
                let value = i32::from_le_bytes(parameter[8..12].try_into().expect("four bytes"));
                out.push((tag, value as i64));
            }
        }
        Ok(out)
    }

    /// Ask the secure world for the raw bytes of a symmetric key it holds.
    /// A keymaster 4.0 phone keeps the data partition's key as one of these
    /// blobs, and this is how the storage hardware is given the key itself.
    pub fn export_raw(
        &self,
        key_blob: &[u8],
        client_id: &[u8],
        app_data: &[u8],
    ) -> Result<Vec<u8>> {
        let what = "export the key's raw bytes";
        let mut call = Message::call(HARDWARE_SERVICE);
        call.i32(KEY_FORMAT_RAW);
        call.bytes(key_blob);
        call.bytes(client_id);
        call.bytes(app_data);
        let reply = self.device.transact(EXPORT_KEY, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let error = read.i32().context("read whether the key was exported")?;
        if error != 0 {
            bail!("the key service refused to export the key with its code {error}");
        }
        Ok(read
            .vector()
            .context("read the key the service exported")?
            .to_vec())
    }

    /// Undo an AES-GCM encryption the key service did with `key_blob`.
    pub fn gcm_decrypt(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        self.gcm_decrypt_with_token(key_blob, app_id, nonce, body, None)
    }

    /// The same, carrying the note the secure world wrote when a user
    /// answered their screen lock. A user's own key is bound to that note.
    pub fn gcm_decrypt_with_token(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
        note: Option<&crate::token::Token>,
    ) -> Result<Vec<u8>> {
        let handle = self.begin(key_blob, app_id, nonce, note)?;
        let mut out = self.update(handle, body)?;
        out.extend_from_slice(&self.finish(handle, &[])?);
        Ok(out)
    }

    fn begin(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        note: Option<&crate::token::Token>,
    ) -> Result<u64> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.i32(PURPOSE_DECRYPT);
        call.bytes(key_blob);
        let params = params(app_id, nonce);
        let pairs: Vec<_> = params.into_iter().map(Param::into_pair).collect();
        call.key_parameters(&pairs);
        auth_token(&mut call, note);

        let reply = self
            .device
            .transact(BEGIN, &call)
            .context("start a decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("start a decryption")?;
        let error = read.i32().context("read whether the decryption opened")?;
        if error != 0 {
            bail!("the key service refused to open the decryption with its code {error}");
        }
        // vec<KeyParameter> outParams, then the operation handle.
        let _params = read
            .vector()
            .context("read the parameters the decryption came back with")?;
        read.u64().context("read the decryption's handle")
    }

    fn update(&self, handle: u64, input: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(handle);
        call.bytes(&[]);
        call.bytes(input);
        empty_auth_token(&mut call);
        empty_verification_token(&mut call);
        let reply = self
            .device
            .transact(UPDATE, &call)
            .context("feed the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("feed the decryption")?;
        let error = read
            .i32()
            .context("read whether the decryption accepted the input")?;
        if error != 0 {
            bail!("the key service refused the input with its code {error}");
        }
        let _consumed = read
            .u32()
            .context("read how much the decryption consumed")?;
        let _params = read
            .vector()
            .context("read the parameters the decryption came back with")?;
        Ok(read
            .vector()
            .context("read what the decryption gave back")?
            .to_vec())
    }

    fn finish(&self, handle: u64, input: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(handle);
        call.bytes(&[]);
        call.bytes(input);
        call.bytes(&[]);
        empty_auth_token(&mut call);
        empty_verification_token(&mut call);
        let reply = self
            .device
            .transact(FINISH, &call)
            .context("close the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("close the decryption")?;
        let error = read.i32().context("read whether the decryption closed")?;
        if error != 0 {
            bail!("the key service refused to close the decryption with its code {error}");
        }
        let _params = read
            .vector()
            .context("read the parameters the decryption came back with")?;
        Ok(read
            .vector()
            .context("read what the decryption ended with")?
            .to_vec())
    }

    /// Send a begin with no key parameters, to tell a wrong method number
    /// from a malformed parameter vector. The service is expected to refuse
    /// the key, but the driver should still carry the call.
    pub fn probe_begin(&self, key_blob: &[u8]) -> Result<String> {
        let mut said = String::new();
        for code in [16u32, 6] {
            let mut call = Message::call(HARDWARE_SERVICE);
            call.i32(PURPOSE_DECRYPT);
            call.bytes(key_blob);
            call.bytes(&[]);
            empty_auth_token(&mut call);
            match self.device.transact(code, &call) {
                Ok(reply) => {
                    let raw = reply.bytes();
                    said.push_str(&format!(
                        "code {code}: reply {} bytes {}\n",
                        raw.len(),
                        raw.iter()
                            .take(12)
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join("")
                    ));
                }
                Err(e) => said.push_str(&format!("code {code}: {e:#}\n")),
            }
        }
        Ok(said)
    }

    /// Try the same begin with different `KeyParameter` vectors. The service
    /// rejecting the key is expected; what matters is whether the binder
    /// layer carries the vector at all, and at which point it stops.
    pub fn probe_layout(&self, key_blob: &[u8]) -> Result<String> {
        let nonce = [0u8; 12];
        let nonce_only = vec![(TAG_NONCE, 0, Some(nonce.to_vec()))];
        let enums = vec![
            Param::enum_value(TAG_BLOCK_MODE, BLOCK_MODE_GCM).into_pair(),
            Param::enum_value(TAG_PADDING, PADDING_NONE).into_pair(),
            Param::integer(TAG_MAC_LENGTH, 128).into_pair(),
            Param::enum_value(TAG_PURPOSE, PURPOSE_DECRYPT).into_pair(),
        ];
        let mut nonce_first = vec![(TAG_NONCE, 0, Some(nonce.to_vec()))];
        nonce_first.extend(enums.clone());
        let mut full = Vec::new();
        full.extend([
            Param::enum_value(TAG_BLOCK_MODE, BLOCK_MODE_GCM).into_pair(),
            Param::enum_value(TAG_PADDING, PADDING_NONE).into_pair(),
            Param::integer(TAG_MAC_LENGTH, 128).into_pair(),
            (TAG_NONCE, 0, Some(nonce.to_vec())),
            Param::enum_value(TAG_PURPOSE, PURPOSE_DECRYPT).into_pair(),
        ]);
        let mut nonce_last = enums.clone();
        nonce_last.push((TAG_NONCE, 0, Some(nonce.to_vec())));

        let variants = [
            ("empty", Vec::new()),
            ("nonce-only", nonce_only),
            ("enums-no-blob", enums),
            ("nonce-first", nonce_first),
            ("full", full),
            ("nonce-last", nonce_last),
        ];
        let mut said = String::new();
        for (name, pairs) in variants {
            let mut call = Message::call(HARDWARE_SERVICE);
            call.i32(PURPOSE_DECRYPT);
            call.bytes(key_blob);
            call.key_parameters(&pairs);
            empty_auth_token(&mut call);
            match self.device.transact(BEGIN, &call) {
                Ok(reply) => {
                    let raw = reply.bytes();
                    said.push_str(&format!(
                        "{name}: reply {} bytes {}\n",
                        raw.len(),
                        raw.iter()
                            .take(16)
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join("")
                    ));
                }
                Err(e) => said.push_str(&format!("{name}: {e:#}\n")),
            }
        }
        Ok(said)
    }

    /// Try the metadata blob as it sits on disk, without its magic, and
    /// without the hash the secure world appends, to find out which part
    /// of the file the service is refusing.
    pub fn probe_shapes(&self, key_blob: &[u8]) -> Result<String> {
        let mut shapes: Vec<(&str, &[u8])> = vec![("full", key_blob)];
        if let Some(rest) = key_blob.strip_prefix(b"pKMblob\0") {
            shapes.push(("no-magic", rest));
            if rest.len() >= 4 {
                let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
                let der_end = 4 + len;
                if der_end <= rest.len() {
                    shapes.push(("der", &rest[..der_end]));
                    shapes.push(("magic+der", &key_blob[..8 + der_end]));
                }
            }
        }
        let nonce = [0u8; 12];
        let pairs: Vec<_> = params(&[], &nonce)
            .into_iter()
            .map(Param::into_pair)
            .collect();
        let mut said = String::new();
        for (name, shape) in shapes {
            let mut call = Message::call(HARDWARE_SERVICE);
            call.i32(PURPOSE_DECRYPT);
            call.bytes(shape);
            call.key_parameters(&pairs);
            empty_auth_token(&mut call);
            match self.device.transact(BEGIN, &call) {
                Ok(reply) => {
                    let raw = reply.bytes();
                    let head = raw
                        .iter()
                        .take(12)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join("");
                    said.push_str(&format!(
                        "{name} ({} bytes): reply {} bytes {head}\n",
                        shape.len(),
                        raw.len()
                    ));
                }
                Err(e) => said.push_str(&format!("{name} ({} bytes): {e:#}\n", shape.len())),
            }
        }
        Ok(said)
    }

    /// Ask for the key's authorizations with each shape of the file, to see
    /// whether the key itself is refused or only the call that opens it.
    pub fn probe_auth_shapes(&self, key_blob: &[u8]) -> Result<String> {
        let mut shapes: Vec<(&str, &[u8])> = vec![("full", key_blob)];
        if let Some(rest) = key_blob.strip_prefix(b"pKMblob\0") {
            shapes.push(("no-magic", rest));
            if rest.len() >= 4 {
                let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
                let der_end = 4 + len;
                if der_end <= rest.len() {
                    shapes.push(("der", &rest[..der_end]));
                    shapes.push(("magic+der", &key_blob[..8 + der_end]));
                }
            }
        }
        let mut said = String::new();
        for (name, shape) in shapes {
            let mut call = Message::call(HARDWARE_SERVICE);
            call.bytes(shape);
            call.bytes(&[]);
            call.bytes(&[]);
            match self.device.transact(GET_KEY_CHARACTERISTICS, &call) {
                Ok(reply) => {
                    let raw = reply.bytes();
                    let mut read = Answer::new(raw);
                    let head = raw
                        .iter()
                        .take(8)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join("");
                    match read.status().and_then(|()| read.i32()) {
                        Ok(0) => {
                            let mut tags = 0;
                            let software = read.vector().unwrap_or(&[]);
                            tags += software.len() / 32;
                            let hardware = read.vector().unwrap_or(&[]);
                            tags += hardware.len() / 32;
                            said.push_str(&format!("{name}: accepted, {tags} tags, {head}\n"));
                        }
                        Ok(error) => said.push_str(&format!("{name}: error {error}, {head}\n")),
                        Err(e) => said.push_str(&format!("{name}: {e:#}, {head}\n")),
                    }
                }
                Err(e) => said.push_str(&format!("{name}: {e:#}\n")),
            }
        }
        Ok(said)
    }

    /// Make a throwaway AES key with the service and open a decryption with
    /// it. This tells a bad metadata blob apart from a service that cannot
    /// unwrap anything at all.
    pub fn probe_generate(&self) -> Result<String> {
        let spec = vec![
            Param::enum_value(TAG_ALGORITHM, ALGORITHM_AES).into_pair(),
            Param::integer(TAG_KEY_SIZE, 256).into_pair(),
            Param::enum_value(TAG_PURPOSE, PURPOSE_ENCRYPT).into_pair(),
            Param::enum_value(TAG_PURPOSE, PURPOSE_DECRYPT).into_pair(),
            Param::enum_value(TAG_BLOCK_MODE, BLOCK_MODE_GCM).into_pair(),
            Param::enum_value(TAG_PADDING, PADDING_NONE).into_pair(),
            Param::integer(TAG_MAC_LENGTH, 128).into_pair(),
            Param::integer(TAG_NO_AUTH_REQUIRED, 1).into_pair(),
        ];
        let mut call = Message::call(HARDWARE_SERVICE);
        call.key_parameters(&spec);
        call.bytes(&[]);
        call.i32(1); // SecurityLevel::TRUSTED_ENVIRONMENT
        empty_auth_token(&mut call);
        let reply = self.device.transact(6, &call).context("make a test key")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("make a test key")?;
        let error = read.i32().context("read whether the test key was made")?;
        if error != 0 {
            bail!("the key service refused to make a test key with its code {error}");
        }
        let blob = read.vector().context("read the test key's blob")?.to_vec();
        let _software = read
            .vector()
            .context("read the test key's software authorizations")?;
        let _hardware = read
            .vector()
            .context("read the test key's hardware authorizations")?;
        if blob.is_empty() {
            bail!("the key service made a test key but gave back no blob");
        }
        let nonce = [0x42u8; 12];
        let pairs: Vec<_> = params(&[], &nonce)
            .into_iter()
            .map(Param::into_pair)
            .collect();
        let mut open = Message::call(HARDWARE_SERVICE);
        open.i32(PURPOSE_ENCRYPT);
        open.bytes(&blob);
        open.key_parameters(&pairs);
        empty_auth_token(&mut open);
        let reply = self
            .device
            .transact(BEGIN, &open)
            .context("open the test key")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("open the test key")?;
        let error = read.i32().context("read whether the test key opened")?;
        if error != 0 {
            bail!(
                "the key service made a {} byte test key but refused to open it with its code {error}",
                blob.len()
            );
        }
        let _params = read
            .vector()
            .context("read the test key's opening parameters")?;
        let handle = read.u64().context("read the test key's handle")?;
        Ok(format!(
            "made a {} byte test key and opened it as handle {handle}",
            blob.len()
        ))
    }

    /// Ask for the key's authorizations with each candidate application id,
    /// since the secure world folds that id into the key's own check.
    pub fn probe_app_ids(&self, key_blob: &[u8], ids: &[(&str, &[u8])]) -> Result<String> {
        let mut said = String::new();
        for (name, id) in ids {
            let mut call = Message::call(HARDWARE_SERVICE);
            call.bytes(key_blob);
            call.bytes(id);
            call.bytes(&[]);
            match self.device.transact(GET_KEY_CHARACTERISTICS, &call) {
                Ok(reply) => {
                    let raw = reply.bytes();
                    let mut read = Answer::new(raw);
                    let head = raw
                        .iter()
                        .take(8)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join("");
                    match read.status().and_then(|()| read.i32()) {
                        Ok(0) => {
                            let software = read.vector().unwrap_or(&[]);
                            let hardware = read.vector().unwrap_or(&[]);
                            said.push_str(&format!(
                                "{name} ({} bytes): accepted, {} + {} tags, {head}\n",
                                id.len(),
                                software.len() / 32,
                                hardware.len() / 32
                            ));
                        }
                        Ok(error) => said.push_str(&format!(
                            "{name} ({} bytes): error {error}, {head}\n",
                            id.len()
                        )),
                        Err(e) => {
                            said.push_str(&format!("{name} ({} bytes): {e:#}, {head}\n", id.len()))
                        }
                    }
                }
                Err(e) => said.push_str(&format!("{name} ({} bytes): {e:#}\n", id.len())),
            }
        }
        Ok(said)
    }

    /// Ask keymaster 4.0 to upgrade a blob that a 4.1-era system wrote.
    /// The reply is printed raw because the point is to see whether the
    /// service accepts the old blob at all.
    pub fn probe_upgrade(&self, key_blob: &[u8]) -> Result<String> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.bytes(key_blob);
        call.key_parameters(&[]);
        match self.device.transact(12, &call) {
            Ok(reply) => {
                let raw = reply.bytes();
                Ok(format!(
                    "upgradeKey: reply {} bytes {}",
                    raw.len(),
                    raw.iter()
                        .take(80)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join("")
                ))
            }
            Err(e) => Ok(format!("upgradeKey: {e:#}")),
        }
    }

    /// Whether the secure world will unwrap the key at all: a decryption
    /// is opened under a nonce of nothing and dropped again.
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let handle = self.begin(key_blob, app_id, &[0; 12], None)?;
        self.abort(handle)
    }

    /// Drop an operation without using its handle again.
    pub fn abort(&self, handle: u64) -> Result<()> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(handle);
        let reply = self
            .device
            .transact(ABORT, &call)
            .context("drop the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("drop the decryption")
    }
}

/// One key parameter, in the shape keymaster 4.0's `KeyParameter` writes:
/// a 32-byte struct whose tag sits at 0, whose integer value sits at 8,
/// and whose blob vector sits at 16.
struct Param {
    tag: i32,
    value: i32,
    blob: Option<Vec<u8>>,
}

impl Param {
    fn enum_value(tag: i32, value: i32) -> Param {
        Param {
            tag,
            value,
            blob: None,
        }
    }

    fn integer(tag: i32, value: i32) -> Param {
        Param {
            tag,
            value,
            blob: None,
        }
    }

    fn blob(tag: i32, bytes: &[u8]) -> Param {
        Param {
            tag,
            value: 0,
            blob: Some(bytes.to_vec()),
        }
    }

    fn into_pair(self) -> (i32, i32, Option<Vec<u8>>) {
        (self.tag, self.value, self.blob)
    }
}

fn params(app_id: &[u8], nonce: &[u8]) -> Vec<Param> {
    let mut params = vec![
        Param::enum_value(TAG_ALGORITHM, ALGORITHM_AES),
        Param::integer(TAG_KEY_SIZE, 256),
        Param::enum_value(TAG_BLOCK_MODE, BLOCK_MODE_GCM),
        Param::enum_value(TAG_PADDING, PADDING_NONE),
        Param::integer(TAG_MAC_LENGTH, 128),
        Param::blob(TAG_NONCE, nonce),
    ];
    if !app_id.is_empty() {
        params.push(Param::blob(TAG_APPLICATION_ID, app_id));
    }
    params
}

#[allow(dead_code)]
fn empty_vec(p: &mut Message) {
    p.u64(0); // buffer
    p.u64(0); // size
}

fn auth_token(p: &mut Message, note: Option<&crate::token::Token>) {
    let mut head = Vec::new();
    let mut field = Message::default();
    field.u64(note.map_or(0, |n| n.challenge as u64));
    field.u64(note.map_or(0, |n| n.user as u64));
    field.u64(note.map_or(0, |n| n.authenticator as u64));
    field.u32(note.map_or(0, |n| n.kind as u32));
    field.u32(0); // padding before the 8-byte aligned timestamp
    field.u64(note.map_or(0, |n| n.when as u64));
    head.extend_from_slice(skyward_binder::parcel::Payload::values(&field));
    let mac = note.map_or(&[][..], |n| n.mac.as_slice());
    p.struct_with_tail_vec(&head, mac, 40); // mac at offset 40
}

fn empty_auth_token(p: &mut Message) {
    auth_token(p, None);
}

fn empty_verification_token(p: &mut Message) {
    let mut head = Vec::new();
    let mut field = Message::default();
    field.u64(0); // challenge
    field.u64(0); // timestamp
    field.i32(0); // security level
    field.u32(0); // padding before the 8-byte aligned vec
    head.extend_from_slice(skyward_binder::parcel::Payload::values(&field));
    p.struct_with_tail_vec(&head, &[], 24); // mac at offset 24
}

/// Let the wrapped-key reader use this service exactly as it uses the
/// newer one: what it needs is only AES-GCM unwrapping.
#[cfg(target_os = "android")]
impl crate::keystore::Decryptor for Keymaster<'_> {
    fn gcm_decrypt(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        Keymaster::gcm_decrypt(self, key_blob, app_id, nonce, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_numbers_are_the_order_the_4_0_interface_declares() {
        assert_eq!(GET_HARDWARE_INFO, 1);
        assert_eq!(GET_KEY_CHARACTERISTICS, 9);
        assert_eq!(BEGIN, 16);
        assert_eq!(UPDATE, 17);
        assert_eq!(FINISH, 18);
        assert_eq!(ABORT, 19);
    }

    #[test]
    fn an_auth_token_with_no_mac_is_all_zeroes_and_an_empty_vector() {
        let mut m = Message::default();
        empty_auth_token(&mut m);
        // The struct and its tail are each handed over as one address in
        // this layout; the fields themselves sit in the buffer the first
        // address names, not among the values.
        use skyward_binder::parcel::Payload;
        assert_eq!(m.values().len(), 40 + 40);
    }
}

