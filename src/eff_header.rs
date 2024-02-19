
use binrw::{
    BinRead,
    BinWrite,
    NullString
};
use std::convert::TryFrom;

#[derive(BinRead, BinWrite, Debug)]
#[brw(magic = b"EFFN")]
#[brw(little)]
pub struct EffHeader {
    pub version: u32,
    pub effect_count: u16,
    pub external_model_count: u16,
    pub multipart_effects: u16,
    pub header_chunk_align: u16,
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub struct EffVariantData {
    pub unk: u16,
    pub vfxb_entry: u16
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub struct EffHeaderEntry {
    pub kind: u16,
    pub unk: u16,
    pub vfxb_entry_id: u32,
    pub external_model_idx: u32,
    pub variant_start_idx: u16,
    pub variant_count: u16,
}

#[derive(Debug)]
#[derive(BinRead, BinWrite)]
#[brw(little)]
pub struct EffFile {
    pub header: EffHeader,
    #[br(count = header.effect_count)]
    pub entries: Vec<EffHeaderEntry>,
    #[br(count = header.multipart_effects)]
    pub effect_variants: Vec<EffVariantData>,
    #[br(count = header.external_model_count)]
    pub external_model_info: Vec<u8>, 
    #[br(count = header.effect_count)]
    pub entry_names: Vec<NullString>,
    #[br(count = header.external_model_count)]
    pub external_model_names: Vec<NullString>,
    #[br(count = header.multipart_effects)]
    pub external_bone_names: Vec<NullString>,
}

impl EffFile {
    pub fn get_required_chunk_align(&self) -> usize {
        let mut size = 0x10usize; // start with the size of the header
        size += self.entries.len() * 0x10;
        size += self.effect_variants.len() * 0x4;
        size += self.external_model_info.len();
        for str in self.entry_names.iter() {
            size += str.len() + 1;
        }
        for str in self.external_model_names.iter() {
            size += str.len() + 1;
        }
        for str in self.external_bone_names.iter() {
            size += str.len() + 1;
        }
        (size + 0x1000) & !0xFFF
    }

    pub fn set_for_slot(&mut self, slot_number: usize) {
        for str in self.entry_names.iter_mut() {
            str.0.extend_from_slice(format!("_C{:02}", slot_number).as_bytes());
        }
    }
}