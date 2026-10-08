use super::{VendorDevice, text};

pub(super) fn be16(data: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(..2)?.try_into().ok()?))
}
pub(super) fn mac(data: &[u8]) -> Option<String> {
    let bytes: [u8; 6] = data.try_into().ok()?;
    if bytes == [0; 6] || bytes[0] & 1 != 0 {
        return None;
    }
    Some(crate::network::format_mac(bytes))
}

pub(super) fn parse_mndp(data: &[u8]) -> Option<VendorDevice> {
    if data.len() > 16_384 {
        return None;
    }
    let mut remaining = data.get(4..)?;
    let mut device = VendorDevice::default();
    let mut count = 0;
    while !remaining.is_empty() {
        count += 1;
        if count > 128 {
            return None;
        }
        let kind = be16(remaining)?;
        let len = usize::from(be16(remaining.get(2..)?)?);
        let value = remaining.get(4..4 + len)?;
        remaining = &remaining[4 + len..];
        match kind {
            1 => device.mac = mac(value)?,
            5 => device.name = text(value),
            7 => device.firmware = text(value),
            8 => device.platform = text(value),
            12 => device.model = text(value),
            16 => device.interface = text(value),
            _ => {}
        }
    }
    (!device.mac.is_empty()).then_some(device)
}

pub(super) fn parse_ubiquiti(data: &[u8]) -> Option<VendorDevice> {
    if data.len() > 16_384 || data.len() < 4 {
        return None;
    }
    if !matches!((data[0], data[1]), (1, 0) | (2, 6) | (2, 9) | (2, 11))
        || usize::from(be16(&data[2..])?) + 4 != data.len()
    {
        return None;
    }
    let mut remaining = &data[4..];
    let mut device = VendorDevice::default();
    let mut count = 0;
    while !remaining.is_empty() {
        count += 1;
        if count > 128 {
            return None;
        }
        let kind = *remaining.first()?;
        let len = usize::from(be16(remaining.get(1..)?)?);
        let value = remaining.get(3..3 + len)?;
        remaining = &remaining[3 + len..];
        match kind {
            1 => device.mac = mac(value)?,
            2 if value.len() == 10 => {
                if device.mac.is_empty() {
                    device.mac = mac(&value[..6])?;
                }
            }
            3 => device.firmware = text(value),
            11 => device.name = text(value),
            12 => device.platform = text(value),
            20 | 21 => device.model = text(value),
            _ => {}
        }
    }
    (!device.mac.is_empty() || !device.model.is_empty() || !device.platform.is_empty())
        .then_some(device)
}
