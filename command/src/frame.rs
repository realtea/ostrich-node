use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc::{Crc, CRC_64_ECMA_182};

const CRC: Crc<u64> = Crc::<u64>::new(&CRC_64_ECMA_182);
pub enum Frame {
    CreateUserRequest = 0x0000,
    CreateUserResponse = 0x0001,
    DeleteUserRequest = 0x0010,
    DeleteUserResponse = 0x0011,
    UnKnown = 0x16
}

impl From<u16> for Frame {
    fn from(item: u16) -> Self {
        let frame = match item {
            0x0000 => Frame::CreateUserRequest,
            0x0001 => Frame::CreateUserResponse,
            0x0010 => Frame::DeleteUserRequest,
            0x0011=> Frame::DeleteUserResponse,
            _ => Frame::UnKnown
        };
        frame
    }
}
impl From<Frame> for u16 {
    fn from(item: Frame) -> u16 {
        let u8_frame = match item {
            Frame::CreateUserRequest => 0x0000,
            Frame::CreateUserResponse => 0x0001,
            Frame::DeleteUserRequest => 0x0010,
            Frame::DeleteUserResponse => 0x0011,
            Frame::UnKnown => 0x16
        };
        u8_frame
    }
}
impl From<&Frame> for u16 {
    fn from(item: &Frame) -> u16 {
        let u8_frame = match *item {
            Frame::CreateUserRequest => 0x0000,
            Frame::CreateUserResponse => 0x0001,
            Frame::DeleteUserRequest => 0x0010,
            Frame::DeleteUserResponse => 0x0011,
            Frame::UnKnown => 0x16
        };
        u8_frame
    }
}

impl Frame {
    pub fn get_frame_type<B>(data: B) -> Self
    where B: AsRef<[u8]> {
        let mut data_ref = data.as_ref().clone();
        data_ref.advance(4 + 8);
        let frame = BigEndian::read_u16(data_ref.as_ref());
        frame.into()
    }

    //    impl<T: BufMut + ?Sized> BufMut for &mut T {
    //
    //    }

    pub fn pack_msg_frame(&self, data: &[u8]) -> Bytes
//    where
    //        B: Buf + BufMut,
    {
        let mut packet = BytesMut::new();
        let sum = CRC.checksum(data.as_ref());
        //        packet.reserve(data.as_ref().len() + std::mem::size_of_val(&sum) + 2 + 1);
        packet.reserve(data.as_ref().len() + std::mem::size_of_val(&sum) + 4 + 2 /*fame type*/);
        packet.put_u32(data.len() as u32);
        packet.put_u64(sum);
        packet.put_u16(self.into());
        packet.put(data.as_ref());
        packet.freeze()
    }

    // pub fn unpack_msg_frame<B>(data: &mut [u8]) -> anyhow::Result<()>
    // where
    //     B: AsRef<Bytes>,
    pub fn unpack_msg_frame(data: &mut BytesMut) -> anyhow::Result<()> {
        // let mut data_ref = data.as_ref().clone();

        let size = {
            if data.len() < 4 {
                return Err(anyhow::anyhow!("msg does not has enough 'length' byte!"))
            }
            BigEndian::read_u32(data.as_ref()) as u32
        };
        // TODO test( size + std::mem::size_of_val(size))
        if data.len() <= (size + 4) as usize {
            return Err(anyhow::anyhow!("msg is too short!"))
        }

        data.advance(std::mem::size_of_val(&size));
        let sum = BigEndian::read_u64(data.as_ref()) as u64;
        data.advance(std::mem::size_of_val(&sum));
        //        let data = data.to_vec();
        data.advance(2);//frame type

        let check = CRC.checksum(data.as_ref());
        //        dbg!(sum == check);
        println!("sum:{:?} check:{}", sum, check);
        if sum != check {
            return Err(anyhow::anyhow!("msg mismatch sum"))
        }
        Ok(())
    }
}
