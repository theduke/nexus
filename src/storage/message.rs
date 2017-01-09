use std::io::Write;
use byteorder::{BigEndian, ByteOrder};
// use memmap::{Protection, Mmap, MmapView};
use crc::crc32;

#[derive(Debug)]
pub enum MessageError {
    SizeMismatch,
    ChecksumMismatch,
}

/// Size of a message with empty key and empty data.
pub const MINIMUM_MESSAGE_SIZE: i32 = 4 + 1 + 1 + 8 + 4 + 4;

pub fn calculate_message_size(key_size: i32, value_size: i32) -> i32 {
    MINIMUM_MESSAGE_SIZE + key_size + value_size
}

/// RawMessage represents message in raw binary format.
///
/// This format is used both for on disk storage and network transmission.
/// Bytes are always in network order (big endian).
///
/// Format:
///   crc            : 4 bytes (u32)
///   format_version : 1 byte
///   attributes     : 1 byte  (bitmap of several message modifiers)
///   timestamp      : 8 bytes (i64) (UNIX epoch time in milliseconds)
///   key length     : 4 bytes (i32)
///   key            : K bytes
///   value length   : 4 bytes (i32)
///   value          : V bytes
///
///   Length of a message therefore is: 4 + 1 + 1 + 8 + 4 + K + 4 + V.
///
///   Implementors MUST ensure that non of the read_* methods can panic.
///   Due to the interface, that means that at least the size integrity must be
///   checked: this means verifying that key_length and value_length are
///   consistent with the overall data length.
///
///   This can be ensured by using the verify_size_integrity method
///   that is present as a default implementation on the trait.
///   See RefRawMessage::new as an example.
///
///   Checksum integrity can be verified with the verify_checksum() method.
pub trait RawMessage {
    fn data(&self) -> &[u8];

    fn length(&self) -> usize {
        self.data().len()
    }

    fn read_checksum(&self) -> u32 {
        BigEndian::read_u32(self.data())
    }

    fn read_format_version(&self) -> i8 {
        self.data()[4] as i8
    }

    fn read_attributes(&self) -> u8 {
        self.data()[5]
    }

    fn read_timestamp(&self) -> i64 {
        BigEndian::read_i64(&self.data()[6..14])
    }

    fn read_key_length(&self) -> i32 {
        BigEndian::read_i32(&self.data()[14..18])
    }

    fn read_key(&self) -> &[u8] {
        let key_length = self.read_key_length() as usize;
        &self.data()[18..(18 + key_length)]
    }

    fn read_value_length(&self) -> i32 {
        let start_index = 18 + self.read_key_length() as usize;
        BigEndian::read_i32(&self.data()[start_index..(start_index + 4)])
    }

    /// Get the message value.
    fn read_value(&self) -> &[u8] {
        let start_index = 18 + self.read_key_length() as usize + 4;
        &self.data()[start_index..]
    }

    fn verify_size_integrity(&self) -> Result<(), MessageError> {
        let actual_size = self.length();
        // Both key and value can be empty, so minimum size is size of all
        // required fields.
        // Check struct comments for format.
        let mut min_size = 4 + 1 + 1 + 8 + 4 + 4;
        if actual_size < min_size {
            // Data shorter than minimum size.
            return Err(MessageError::ChecksumMismatch);
        }
        // Data is long enough to contain key length, so reading it is safe.
        min_size += self.read_key_length() as usize;
        if actual_size < min_size {
            // Data too short to contain value_length field.
            return Err(MessageError::ChecksumMismatch);
        }
        // Can read value_length now.
        min_size += self.read_value_length() as usize;
        // If sizes match, at least the length is valid and all fields are safe
        // to read.
        if actual_size == min_size {
            Ok(())
        } else {
            return Err(MessageError::SizeMismatch);
        }
    }

    /// Re-calculate the message checksum.
    fn calculate_checksum(&self) -> u32 {
        crc32::checksum_ieee(&self.data()[4..])
    }

    /// Re-calculates the crc32 checksum for the message, and compares it to
    /// the one in the message body.
    /// If false, data corruption must have occurred on network or disk.
    fn verify_checksum(&self) -> Result<(), MessageError> {
        if self.read_checksum() == self.calculate_checksum() {
            Ok(())
        } else {
            Err(MessageError::ChecksumMismatch)
        }
    }
}

trait RawMessageEntry {
    fn data(&self) -> &[u8];

    /// Read the offset.
    ///
    /// This represents a binary offset within the data stream for a specific
    /// partition in a topic.
    ///
    /// Note that this occurs a conversion cost on little-endian architectures.
    fn read_offset(&self) -> i64 {
        BigEndian::read_i64(self.data())
    }

    /// Read the message length.
    ///
    /// Note that this occurs a conversion cost on little-endian architectures.
    fn read_length(&self) -> i32 {
        BigEndian::read_i32(&self.data()[8..])
    }
}


pub struct RefRawMessage<'a> {
    data: &'a [u8],
}

impl<'a> RawMessage for RefRawMessage<'a> {
    #[inline(always)]
    fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> RefRawMessage<'a> {
    /// Create a new message.
    ///
    /// If the data length does not match the expected format, a
    /// MessageError::SizeMismatch error is returned.
    ///
    ///  If verify_checksum is true, the checksum is also verified, and a
    ///  MessageError::ChecksumMismatch is returned on error.
    pub fn new<'x>(data: &'x [u8],
                   verify_checksum: bool)
                   -> Result<RefRawMessage<'x>, MessageError> {
        let m = RefRawMessage { data: data };
        m.verify_size_integrity()?;
        if verify_checksum {
            m.verify_checksum()?;
        }
        Ok(m)
    }
}

pub struct RefRawMessageEntry<'a> {
    data: &'a [u8],
    message: RefRawMessage<'a>,
}

impl<'a> RawMessageEntry for RefRawMessageEntry<'a> {
    #[inline(always)]
    fn data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> RefRawMessageEntry<'a> {
    /// Create a new message entry.
    ///
    ///  If the data length does not match the expected format, a
    ///  MessageError::SizeMismatch error is returned.
    ///
    ///  If verify_checksum is true, the checksum is also verified, and a
    ///  MessageError::ChecksumMismatch is returned on error.
    pub fn new<'x>(data: &'x [u8],
                   verify_checksum: bool)
                   -> Result<RefRawMessageEntry<'x>, MessageError> {
        // Must verify data size before the Message struct can be created.
        // Data must be at least 12 (offset + length) + 22 (minimum message
        // length) bytes long.
        if data.len() < 12 + 22 {
            return Err(MessageError::SizeMismatch);
        }
        let e = RefRawMessageEntry {
            data: data,
            message: RefRawMessage::new(&data[12..], verify_checksum)?,
        };
        Ok(e)
    }

    pub fn message(&self) -> &RefRawMessage<'a> {
        &self.message
    }
}

pub struct OwnedRawMessage {
    pub data: Vec<u8>,
}

impl OwnedRawMessage {
    pub fn new(data: Vec<u8>, verify_checksum: bool) -> Result<Self, MessageError> {
        let msg = OwnedRawMessage { data: data };
        msg.verify_size_integrity()?;
        if verify_checksum {
            msg.verify_checksum()?;
        }
        Ok(msg)
    }

    /// Create a new instance without data.
    /// NEVER MAKE THIS PUBLIC.
    /// Used by MessageBuilder.
    fn new_empty(capacity: i32) -> Self {
        OwnedRawMessage { data: Vec::with_capacity(capacity as usize) }
    }

    /// Update the message with a new key and value.
    /// This also udpates key_length, value_length and the checksum.
    /// NEVER MAKE THIS PUBLIC.
    /// Used by MessageBuilder.
    fn set_key_value(&mut self, key: &[u8], value: &[u8]) {
        let key_len = key.len() as i32;
        let value_len = value.len() as i32;
        // Ensure vector is large enough for key and data.
        let new_total_size = calculate_message_size(key_len, value_len) as usize;
        let cur_capacity = self.data.capacity();
        if cur_capacity < new_total_size {
            self.data.reserve(new_total_size - cur_capacity);
        } else {
            self.data.truncate(new_total_size);
        }
        // Need to unsafe set_len, because mutably indexing into the vec will
        // panic otherwise.
        unsafe {
            self.data.set_len(new_total_size);
        }
        BigEndian::write_i32(&mut self.data[14..18], key.len() as i32);
        // Write key.
        (&mut self.data[18..18 + key_len as usize]).write(key).unwrap();
        // Write value length.
        let value_len_start = 18 + key_len as usize;
        let value_start = value_len_start + 4;
        BigEndian::write_i32(&mut self.data[value_len_start..value_start],
                             value.len() as i32);
        let value_start = value_len_start + 4;
        (&mut self.data[value_start..value_start + value_len as usize])
            .write(value)
            .unwrap();

        // Update checksum.
        let checksum = self.calculate_checksum();
        BigEndian::write_u32(&mut self.data[0..4], checksum);
    }
}

impl RawMessage for OwnedRawMessage {
    #[inline(always)]
    fn data(&self) -> &[u8] {
        &self.data
    }
}

pub struct MessageBuilder<'a> {
    key: &'a [u8],
    value: &'a [u8],
}

impl<'a> MessageBuilder<'a> {
    pub fn new<'b>(key: &'b [u8], value: &'b [u8]) -> MessageBuilder<'b> {
        MessageBuilder {
            key: key,
            value: value,
        }
    }

    pub fn build(self) -> OwnedRawMessage {
        let mut msg = OwnedRawMessage::new_empty(calculate_message_size(self.key.len() as i32,
                                                                        self.value.len() as i32));
        msg.set_key_value(self.key, self.value);
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // message with:
    //   key of length 2 with value 1
    //   value with length of 6 with value 111
    //   total length: 30
    const VALID_MESSAGE_1: &'static [u8] = &[// crc: 2967706954
                                             // 10110000 11100011 10011101 01001010
                                             0b10110000,
                                             0b11100011,
                                             0b10011101,
                                             0b01001010,
                                             // format_version
                                             0,
                                             // attributes
                                             0,
                                             // timestamp
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             // key_length: 2
                                             0,
                                             0,
                                             0,
                                             2,
                                             // key: 1
                                             0,
                                             1,
                                             // value_length: 6
                                             0,
                                             0,
                                             0,
                                             6,
                                             // value: 111
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             111];

    #[test]
    fn test_construct_raw_message_with_empty_data() {
        let data = &[];
        let res = RefRawMessage::new(data, true);
        assert!(res.is_err());
    }

    #[test]
    fn test_raw_message() {
        let msg = RefRawMessage::new(VALID_MESSAGE_1, true).unwrap();
        assert_eq!(msg.read_key(), &[0, 1]);
        assert_eq!(msg.read_value(), &[0, 0, 0, 0, 0, 111]);
    }

    #[test]
    fn test_message_builder() {
        let msg = MessageBuilder::new(&[0, 1], &[0, 0, 0, 0, 0, 111]).build();
        msg.verify_size_integrity().unwrap();
        assert_eq!(msg.read_checksum(), 2967706954);
        assert_eq!(msg.read_key(), &[0, 1]);
        assert_eq!(msg.read_value(), &[0, 0, 0, 0, 0, 111]);
        msg.verify_checksum().unwrap();
    }
}
