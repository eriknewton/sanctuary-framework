//! Private bounded wire client for the writer's systemd identity exchange.
use super::*;
use std::collections::BTreeMap;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const FIXED_HEADER: usize = 16; // D-Bus fixed header, before the a(yv) field body.
const ALIGNMENT: usize = 8; // D-Bus struct and message-body alignment.
const BUS_DAEMON: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const MANAGER: &str = "org.freedesktop.systemd1";
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Item {
    Byte(u8),
    Word(u32),
    Wide(u64),
    Text(String),
    List(Vec<Item>),
    Variant(String, Box<Item>),
}
impl Item {
    fn text(&self) -> Result<&str> {
        if let Self::Text(s) = self {
            Ok(s)
        } else {
            Err(Error::Signature)
        }
    }
    fn word(&self) -> Result<u32> {
        if let Self::Word(n) = self {
            Ok(*n)
        } else {
            Err(Error::Signature)
        }
    }
    fn list(&self) -> Result<&[Item]> {
        if let Self::List(v) = self {
            Ok(v)
        } else {
            Err(Error::Signature)
        }
    }
}
#[derive(Debug, Clone)]
enum Kind {
    Basic(u8),
    Array(Box<Kind>),
    Struct(Vec<Kind>),
    Variant,
}
impl Kind {
    fn align(&self) -> usize {
        match self {
            Self::Basic(b'y' | b'g') | Self::Variant => 1,
            Self::Basic(b'n' | b'q') => 2,
            Self::Basic(b'x' | b't' | b'd') | Self::Struct(_) => 8,
            _ => 4,
        }
    }
}
#[derive(Default, Debug, Clone)]
pub(super) struct Observer {
    pub fields: usize,
    pub depth: usize,
    pub bytes: usize,
    pub first_cap: Option<&'static str>,
}
fn cap(obs: &mut Observer, name: &'static str) -> Error {
    if obs.first_cap.is_none() {
        obs.first_cap = Some(name);
    }
    Error::Cap(name)
}
fn nesting(depth: usize, obs: &mut Observer) -> Result<()> {
    // Depth is bounded before signature or container work, including ignored credential members.
    if depth > BUS_NESTING_MAX {
        return Err(cap(obs, "nesting"));
    }
    obs.depth = obs.depth.max(depth);
    Ok(())
}
fn signature(bytes: &[u8], offset: &mut usize, depth: usize, obs: &mut Observer) -> Result<Kind> {
    let code = *bytes.get(*offset).ok_or(Error::Signature)?;
    *offset += 1;
    match code {
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g' => {
            Ok(Kind::Basic(code))
        }
        b'h' => Err(Error::Descriptors),
        b'v' => Ok(Kind::Variant),
        b'a' => {
            nesting(depth + 1, obs)?;
            Ok(Kind::Array(Box::new(signature(
                bytes,
                offset,
                depth + 1,
                obs,
            )?)))
        }
        b'(' | b'{' => {
            nesting(depth + 1, obs)?;
            let end = if code == b'(' { b')' } else { b'}' };
            let mut kinds = Vec::new();
            while bytes.get(*offset) != Some(&end) {
                kinds.push(signature(bytes, offset, depth + 1, obs)?);
            }
            *offset += 1;
            if kinds.is_empty()
                || (code == b'{'
                    && (kinds.len() != 2 || !matches!(kinds.first(), Some(Kind::Basic(_)))))
            {
                return Err(Error::Signature);
            }
            Ok(Kind::Struct(kinds))
        }
        _ => Err(Error::Signature),
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    end: usize,
}
impl<'a> Reader<'a> {
    fn align(&mut self, alignment: usize) -> Result<()> {
        let next = self.at.checked_add(alignment - 1).ok_or(Error::Framing)? & !(alignment - 1);
        if next > self.end || self.bytes[self.at..next].iter().any(|b| *b != 0) {
            return Err(Error::Framing);
        }
        self.at = next;
        Ok(())
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let next = self.at.checked_add(size).ok_or(Error::Framing)?;
        if next > self.end {
            return Err(Error::Framing);
        }
        let bytes = &self.bytes[self.at..next];
        self.at = next;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Framing)?,
        ))
    }
    fn text(&mut self, short: bool) -> Result<String> {
        let length = if short {
            self.take(1)?[0] as usize
        } else {
            self.u32()? as usize
        };
        let text = self.take(length)?;
        if text.contains(&0) || self.take(1)? != [0] {
            return Err(Error::Framing);
        }
        Ok(std::str::from_utf8(text)
            .map_err(|_| Error::Framing)?
            .to_owned())
    }
    fn item(
        &mut self,
        kind: &Kind,
        depth: usize,
        registry: bool,
        obs: &mut Observer,
    ) -> Result<Item> {
        self.align(kind.align())?;
        match kind {
            Kind::Basic(b'y') => Ok(Item::Byte(self.take(1)?[0])),
            Kind::Basic(b'n' | b'q') => Ok(Item::Word(u16::from_le_bytes(
                self.take(2)?.try_into().map_err(|_| Error::Framing)?,
            ) as u32)),
            Kind::Basic(b'b') => {
                let n = self.u32()?;
                if n > 1 {
                    return Err(Error::Framing);
                }
                Ok(Item::Word(n))
            }
            Kind::Basic(b'i' | b'u') => Ok(Item::Word(self.u32()?)),
            Kind::Basic(b'x' | b't' | b'd') => Ok(Item::Wide(u64::from_le_bytes(
                self.take(8)?.try_into().map_err(|_| Error::Framing)?,
            ))),
            Kind::Basic(b's' | b'o' | b'g') => {
                let text = self.text(matches!(kind, Kind::Basic(b'g')))?;
                if matches!(kind, Kind::Basic(b'o')) && !object_path(&text) {
                    return Err(Error::Framing);
                }
                Ok(Item::Text(text))
            }
            Kind::Array(element) => {
                nesting(depth + 1, obs)?;
                let size = self.u32()? as usize;
                self.align(element.align())?;
                let end = self.at.checked_add(size).ok_or(Error::Framing)?;
                if end > self.end {
                    return Err(Error::Framing);
                }
                let outer_end = self.end;
                self.end = end;
                let mut items = Vec::new();
                while self.at < end {
                    if registry && items.len() >= BUS_ARRAY_ELEMENTS_MAX {
                        return Err(cap(obs, "array"));
                    }
                    items.push(self.item(element, depth + 1, registry, obs)?);
                }
                self.end = outer_end;
                Ok(Item::List(items))
            }
            Kind::Struct(kinds) => {
                nesting(depth + 1, obs)?;
                let mut values = Vec::new();
                for kind in kinds {
                    values.push(self.item(kind, depth + 1, registry, obs)?);
                }
                Ok(Item::List(values))
            }
            Kind::Variant => {
                nesting(depth + 1, obs)?;
                let text = self.text(true)?;
                let mut at = 0;
                let kind = signature(text.as_bytes(), &mut at, depth + 1, obs)?;
                if at != text.len() {
                    return Err(Error::Signature);
                }
                Ok(Item::Variant(
                    text,
                    Box::new(self.item(&kind, depth + 1, registry, obs)?),
                ))
            }
            _ => Err(Error::Signature),
        }
    }
}
fn object_path(text: &str) -> bool {
    text == "/"
        || (text.starts_with('/')
            && text[1..].split('/').all(|s| {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }))
}
const NAME_MAX_BYTES: usize = u8::MAX as usize; // D-Bus names have the protocol's 255-byte limit.
fn member(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= NAME_MAX_BYTES
        && text
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}
fn interface(text: &str) -> bool {
    text.len() <= NAME_MAX_BYTES && text.contains('.') && text.split('.').all(member)
}
fn unique(text: &str) -> bool {
    text.len() <= NAME_MAX_BYTES
        && text.starts_with(':')
        && text[1..].contains('.')
        && text[1..].split('.').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
}
fn bus_name(text: &str) -> bool {
    unique(text)
        || (text.len() <= NAME_MAX_BYTES
            && text.contains('.')
            && text.split('.').all(|s| {
                !s.is_empty()
                    && s.bytes().enumerate().all(|(i, b)| {
                        b.is_ascii_alphabetic()
                            || matches!(b, b'_' | b'-')
                            || (i > 0 && b.is_ascii_digit())
                    })
            }))
}

#[derive(Debug)]
pub(super) struct Message {
    pub kind: u8,
    pub fields: BTreeMap<u8, Item>,
    pub body: Vec<Item>,
    pub signature: String,
}
pub(super) fn parse(bytes: &[u8], registry: bool, obs: &mut Observer) -> Result<Message> {
    if bytes.len() > BUS_MESSAGE_MAX_BYTES {
        return Err(cap(obs, "bytes"));
    }
    obs.bytes = obs.bytes.max(bytes.len());
    if bytes.len() < FIXED_HEADER || bytes[0] != b'l' || bytes[3] != 1 || bytes[2] & !7 != 0 {
        return Err(Error::Framing);
    }
    let mut reader = Reader {
        bytes,
        at: 4,
        end: bytes.len(),
    };
    let body_len = reader.u32()? as usize;
    if reader.u32()? == 0 {
        return Err(Error::Framing);
    }
    let fields_len = reader.u32()? as usize;
    let fields_end = FIXED_HEADER.checked_add(fields_len).ok_or(Error::Framing)?;
    if fields_end > bytes.len() {
        return Err(Error::Framing);
    }
    reader.end = fields_end;
    let mut fields = BTreeMap::new();
    let mut raw_fields = Vec::new();
    let mut count = 0;
    while reader.at < fields_end {
        // Header work is bounded even when a later duplicate or unknown field would also refuse.
        if count >= BUS_HEADER_FIELDS_MAX {
            return Err(cap(obs, "fields"));
        }
        count += 1;
        obs.fields = obs.fields.max(count);
        reader.align(ALIGNMENT)?;
        let code = reader.take(1)?[0];
        let item = reader.item(&Kind::Variant, 0, false, obs)?;
        raw_fields.push((code, item));
    }
    for (code, item) in raw_fields {
        let expected = match code {
            1 => "o",
            2 | 3 | 4 | 6 | 7 => "s",
            5 => "u",
            8 => "g",
            9 => return Err(Error::Descriptors),
            _ => return Err(Error::Header),
        };
        let Item::Variant(sig, item) = item else {
            return Err(Error::Header);
        };
        let valid_name = match code {
            2 | 4 => item.text().is_ok_and(interface),
            3 => item.text().is_ok_and(member),
            6 | 7 => item.text().is_ok_and(bus_name),
            _ => true,
        };
        if !valid_name || sig != expected || fields.insert(code, *item).is_some() {
            return Err(Error::Header);
        }
    }
    reader.end = bytes.len();
    reader.align(ALIGNMENT)?;
    if reader.at.checked_add(body_len) != Some(bytes.len()) {
        return Err(Error::Framing);
    }
    let sig = fields
        .get(&8)
        .map(Item::text)
        .transpose()?
        .unwrap_or("")
        .to_owned();
    let mut at = 0;
    let mut body = Vec::new();
    while at < sig.len() {
        let kind = signature(sig.as_bytes(), &mut at, 0, obs)?;
        body.push(reader.item(&kind, 0, registry, obs)?);
    }
    if reader.at != reader.end {
        return Err(Error::Signature);
    }
    Ok(Message {
        kind: bytes[1],
        fields,
        body,
        signature: sig,
    })
}
fn pad(bytes: &mut Vec<u8>, alignment: usize) {
    bytes.resize((bytes.len() + alignment - 1) & !(alignment - 1), 0);
}
fn string(bytes: &mut Vec<u8>, text: &str, short: bool) {
    if short {
        bytes.push(text.len() as u8);
    } else {
        pad(bytes, 4);
        bytes.extend_from_slice(&(text.len() as u32).to_le_bytes());
    }
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(0);
}
fn field(bytes: &mut Vec<u8>, code: u8, sig: &str, text: &str) {
    pad(bytes, ALIGNMENT);
    bytes.push(code);
    string(bytes, sig, true);
    string(bytes, text, sig == "g");
}
fn request(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    args: &[&str],
) -> Vec<u8> {
    let mut bytes = vec![0; FIXED_HEADER];
    field(&mut bytes, 1, "o", path);
    field(&mut bytes, 2, "s", interface);
    field(&mut bytes, 3, "s", member);
    field(&mut bytes, 6, "s", destination);
    if !args.is_empty() {
        field(&mut bytes, 8, "g", &"s".repeat(args.len()));
    }
    let fields_len = bytes.len() - FIXED_HEADER;
    pad(&mut bytes, ALIGNMENT);
    let body_start = bytes.len();
    for arg in args {
        string(&mut bytes, arg, false);
    }
    let body_len = bytes.len() - body_start;
    bytes[..4].copy_from_slice(&[b'l', 1, 0, 1]);
    bytes[4..8].copy_from_slice(&(body_len as u32).to_le_bytes());
    bytes[8..12].copy_from_slice(&serial.to_le_bytes());
    bytes[12..16].copy_from_slice(&(fields_len as u32).to_le_bytes());
    bytes
}
pub(super) fn response(
    message: &Message,
    serial: u32,
    sender: &str,
    destination: &str,
    sig: &str,
) -> Result<()> {
    // Only the authenticated owner's correlated return can supply unit authority.
    if message.kind != 2 {
        return Err(Error::MessageType);
    }
    if message.fields.get(&5).map(Item::word).transpose()? != Some(serial) {
        return Err(Error::Serial);
    }
    if message.fields.get(&7).map(Item::text).transpose()? != Some(sender) {
        return Err(Error::Sender);
    }
    if message.fields.get(&6).map(Item::text).transpose()? != Some(destination) {
        return Err(Error::Destination);
    }
    if message.signature != sig || !message.fields.contains_key(&8) {
        return Err(Error::Signature);
    }
    Ok(())
}
struct Connection {
    fd: OwnedFd,
    serial: u32,
    own: String,
    signals: usize,
    end: Deadline,
    obs: Observer,
}
impl Connection {
    fn open(target: &BusTarget, end: Deadline) -> Result<Self> {
        let held = held_socket(&target.socket, target.socket_owner_uid)?;
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(Error::Io);
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let path = format!("/proc/self/fd/{}", held.as_raw_fd());
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as _;
        if path.len() >= addr.sun_path.len() {
            return Err(Error::Io);
        }
        for (to, from) in addr.sun_path.iter_mut().zip(path.bytes()) {
            *to = from as _;
        }
        if unsafe { libc::connect(raw, &addr as *const _ as _, mem::size_of_val(&addr) as _) } != 0
        {
            return Err(Error::Io);
        }
        let mut connection = Self {
            fd,
            serial: 0,
            own: String::new(),
            signals: 0,
            end,
            obs: Observer::default(),
        };
        let uid = unsafe { libc::geteuid() }.to_string();
        connection
            .write(format!("\0AUTH EXTERNAL {}\r\n", hex::encode(uid.as_bytes())).as_bytes())?;
        let mut line = Vec::new();
        loop {
            if line.len() >= BUS_LINE_MAX_BYTES {
                return Err(Error::Sasl);
            }
            let mut byte = [0];
            connection.read(&mut byte)?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&line).map_err(|_| Error::Sasl)?;
        let guid = text
            .strip_prefix("OK ")
            .and_then(|s| s.strip_suffix("\r\n"))
            .ok_or(Error::Sasl)?;
        if guid.len() != 32 || !guid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Sasl);
        }
        connection.write(b"BEGIN\r\n")?;
        Ok(connection)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let mut at = 0;
        while at < bytes.len() {
            self.end.check()?;
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    bytes[at..].as_ptr() as _,
                    bytes.len() - at,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n > 0 {
                at += n as usize;
            } else if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                self.wait(libc::POLLOUT)?;
            } else {
                return Err(Error::Io);
            }
        }
        self.end.check()
    }
    fn wait(&self, events: i16) -> Result<()> {
        self.end.check()?;
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, super::WATCHDOG_TICK_MS) };
        if result < 0 || poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::Io);
        }
        self.end.check()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut at = 0;
        while at < bytes.len() {
            self.end.check()?;
            let mut control = [0usize; super::signer_peer::ANCILLARY_WORDS];
            let mut iov = libc::iovec {
                iov_base: bytes[at..].as_mut_ptr() as _,
                iov_len: bytes.len() - at,
            };
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as _;
            msg.msg_controllen = mem::size_of_val(&control) as _;
            let n = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &mut msg,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
                )
            };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                self.wait(libc::POLLIN)?;
                continue;
            }
            if n <= 0 {
                return Err(Error::Io);
            }
            if msg.msg_controllen != 0 || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            {
                // Unexpected descriptors are closed even though negotiation never authorized their use.
                unsafe {
                    let mut h = libc::CMSG_FIRSTHDR(&msg);
                    while !h.is_null() {
                        if (*h).cmsg_level == libc::SOL_SOCKET && (*h).cmsg_type == libc::SCM_RIGHTS
                        {
                            let len: usize = (*h).cmsg_len as _;
                            for i in 0..len.saturating_sub(libc::CMSG_LEN(0) as usize)
                                / mem::size_of::<i32>()
                            {
                                libc::close(*(libc::CMSG_DATA(h) as *const i32).add(i));
                            }
                        }
                        h = libc::CMSG_NXTHDR(&msg, h);
                    }
                }
                return Err(Error::Descriptors);
            }
            at += n as usize;
        }
        self.end.check()
    }
    fn message(&mut self, registry: bool) -> Result<Message> {
        let mut bytes = vec![0; FIXED_HEADER];
        self.read(&mut bytes)?;
        if bytes[0] != b'l' {
            return Err(Error::Framing);
        }
        let fields =
            u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| Error::Framing)?) as usize;
        let body = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::Framing)?) as usize;
        let header = FIXED_HEADER
            .checked_add(fields)
            .and_then(|n| n.checked_add(ALIGNMENT - 1))
            .ok_or(Error::Framing)?
            & !(ALIGNMENT - 1);
        let length = header.checked_add(body).ok_or(Error::Framing)?;
        if length > BUS_MESSAGE_MAX_BYTES {
            return Err(cap(&mut self.obs, "bytes"));
        }
        bytes.resize(length, 0);
        self.read(&mut bytes[FIXED_HEADER..])?;
        parse(&bytes, registry, &mut self.obs)
    }
    // Destination, object, interface, method and expected reply remain separately visible authority checks.
    #[allow(clippy::too_many_arguments)]
    fn call(
        &mut self,
        dest: &str,
        path: &str,
        interface: &str,
        member: &str,
        args: &[&str],
        sig: &str,
        registry: bool,
    ) -> Result<Vec<Item>> {
        self.serial = self.serial.checked_add(1).ok_or(Error::Serial)?;
        self.write(&request(self.serial, dest, path, interface, member, args))?;
        loop {
            let message = self.message(registry)?;
            if message.kind == 4 {
                if ![1, 2, 3, 7].iter().all(|k| message.fields.contains_key(k))
                    || message.fields.contains_key(&5)
                {
                    return Err(Error::Header);
                }
                if self.signals >= BUS_UNSOLICITED_MAX {
                    return Err(Error::Signals);
                }
                self.signals += 1;
                continue;
            }
            if self.own.is_empty() {
                let own = message.body.first().ok_or(Error::Destination)?.text()?;
                if !unique(own) {
                    return Err(Error::Destination);
                }
                self.own = own.to_owned();
            }
            response(&message, self.serial, dest, &self.own, sig)?;
            return Ok(message.body);
        }
    }
    fn daemon(&mut self, member: &str, args: &[&str], sig: &str) -> Result<Vec<Item>> {
        self.call(BUS_DAEMON, BUS_PATH, BUS_DAEMON, member, args, sig, false)
    }
    fn owner(&mut self, target: &BusTarget) -> Result<String> {
        let owner = self
            .daemon("GetNameOwner", &[MANAGER], "s")?
            .first()
            .ok_or(Error::Owner)?
            .text()?
            .to_owned();
        if !unique(&owner) {
            return Err(Error::Owner);
        }
        let credentials = self.daemon("GetConnectionCredentials", &[&owner], "a{sv}")?;
        let mut uid = None;
        let mut pid = None;
        for item in credentials.first().ok_or(Error::Owner)?.list()? {
            let pair = item.list()?;
            let [name, Item::Variant(sig, value)] = pair else {
                return Err(Error::Owner);
            };
            let slot = match name.text()? {
                "UnixUserID" => &mut uid,
                "ProcessID" => &mut pid,
                _ => continue,
            };
            if sig != "u" || slot.replace(value.word()?).is_some() {
                return Err(Error::Owner);
            }
        }
        // the manager's identity is read from the bus daemon's own credential record for the systemd1 owner; the wall unit's MainPID is trusted only because that owner is PID 1 running as uid 0.
        if uid != Some(target.expected_manager_uid) || pid != Some(target.expected_manager_pid) {
            return Err(Error::Owner);
        }
        Ok(owner)
    }
}
pub(super) fn exchange(target: &BusTarget, end: Deadline) -> Result<UnitSnapshot> {
    let mut c = Connection::open(target, end)?;
    c.daemon("Hello", &[], "s")?;
    let owner = c.owner(target)?;
    let path = c
        .call(
            &owner,
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "GetUnit",
            &[&target.wall_unit],
            "o",
            false,
        )?
        .first()
        .ok_or(Error::Unit)?
        .text()?
        .to_owned();
    let mut values = BTreeMap::new();
    for field in PROPERTY_REGISTRY {
        let reply = c.call(
            &owner,
            &path,
            field.interface,
            "Get",
            &[field.subject, field.member],
            "v",
            true,
        )?;
        let [Item::Variant(sig, value)] = reply.as_slice() else {
            return Err(Error::Signature);
        };
        if sig != field.signature {
            return Err(Error::Signature);
        }
        values.insert(field.member, (**value).clone());
    }
    if c.owner(target)? != owner {
        return Err(Error::Owner);
    }
    c.end.check()?;
    let text = |key| {
        values
            .get(key)
            .ok_or(Error::Unit)?
            .text()
            .map(str::to_owned)
    };
    let invocation = values
        .get("InvocationID")
        .ok_or(Error::Unit)?
        .list()?
        .iter()
        .map(|v| {
            if let Item::Byte(n) = v {
                Ok(*n)
            } else {
                Err(Error::Unit)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let dropins = values
        .get("DropInPaths")
        .ok_or(Error::Unit)?
        .list()?
        .iter()
        .map(|v| v.text().map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    let entries = values.get("ExecStart").ok_or(Error::Unit)?.list()?;
    let [entry] = entries else {
        return Err(Error::Exec);
    };
    let entry = entry.list()?;
    // The registered systemd execution tuple has ten fields, including the path and complete argv.
    if entry.len() != 10 {
        return Err(Error::Exec);
    }
    let argv = entry[1]
        .list()?
        .iter()
        .map(|v| v.text().map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    Ok(UnitSnapshot {
        owner,
        id: text("Id")?,
        load: text("LoadState")?,
        active: text("ActiveState")?,
        sub: text("SubState")?,
        invocation,
        fragment: text("FragmentPath")?,
        dropins,
        cgroup: text("ControlGroup")?,
        pid: values.get("MainPID").ok_or(Error::Unit)?.word()?,
        exec: entry[0].text()?.to_owned(),
        argv,
    })
}
