#![feature(proc_macro_hygiene)]
#![feature(label_break_value)]
#![feature(let_else)]
mod eff_header;
mod nx;

use binrw::{BinRead, BinReaderExt, BinWriterExt};
use once_cell::sync::Lazy;
use parking_lot::lock_api::RwLockUpgradableReadGuard;
use parking_lot::RwLock;
use smash::{app::lua_bind::*, lib::lua_const::*};

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use smash_arc::{Hash40, PathListEntry};

macro_rules! hash40_fmt {
    ($($arg:tt)*) => {{
        smash_arc::Hash40::from(format!($($arg)*).as_str())
    }}
}

/// Struct with flags for each of the one-slottable things
struct OneSlotInfo {
    has_effect: bool,
    has_trail: bool,
}

/// Data structure to maintain cached state about one-slot effects and trails so that it doesn't
/// have to be requeried each time
struct SlotCache(RwLock<HashMap<&'static str, HashMap<usize, OneSlotInfo>>>);

/// Optional file with effect names 
const labels: &str = "sd:/ultimate/EffectLabels.txt";

impl SlotCache {
    /// Creates a new cache entry by querying the `mods:/` filesystem hosted by ARCropolis
    fn create_cache_entry(
        map: &mut HashMap<&'static str, HashMap<usize, OneSlotInfo>>,
        fighter_name: &'static str,
        slot: usize,
    ) {
        let root_path = Path::new("mods:/effect/fighter").join(fighter_name);
        let has_effect = root_path
            .join(&format!("ef_{}_c{:02}.eff", fighter_name, slot))
            .exists();
        let has_trail = root_path.join(&format!("trail_c{:02}", slot)).exists();
        if let Some(sub_map) = map.get_mut(fighter_name) {
            sub_map.insert(
                slot,
                OneSlotInfo {
                    has_effect,
                    has_trail,
                },
            );
        } else {
            let mut sub_map = HashMap::new();
            sub_map.insert(
                slot,
                OneSlotInfo {
                    has_effect,
                    has_trail,
                },
            );
            map.insert(fighter_name, sub_map);
        }
    }

    /// Creates a new, empty [`SlotCache`]
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    /// Checks whether a fighter has a unique effect for that slot
    ///
    /// If the query has been done before, grabs the cached information, otherwise it queries
    /// the `mods:/` filesystem.
    pub fn has_one_slot_effect(&self, fighter: &'static str, slot: usize) -> bool {
        // Acquire an upgradeable read so that when we have the lock we can upgrade if
        let lock = self.0.upgradable_read();

        // this block exists so that there isn't any nested `if let Some` and allows us to upgrade if we pass by it
        'assume_exists: {
            let Some(map) = lock.get(fighter) else { break 'assume_exists; };
            let Some(info) = map.get(&slot) else { break 'assume_exists; };
            return info.has_effect;
        }

        // upgrade the lock so that we can make a new entry
        let mut lock = RwLockUpgradableReadGuard::upgrade(lock);

        // make a new entry, there is no way for the lookups to fail after this so just unwrap
        Self::create_cache_entry(&mut lock, fighter, slot);
        let map = lock.get(fighter).unwrap();
        let info = map.get(&slot).unwrap();
        info.has_effect
    }

    /// Checks whether a fighter has a unique trail for that slot
    ///
    /// If the query has been done before, grabs the cached information, otherwise it queries
    /// the `mods:/` filesystem.
    pub fn has_one_slot_trail(&self, fighter: &'static str, slot: usize) -> bool {
        // Acquire an upgradeable read so that when we have the lock we can upgrade if
        let lock = self.0.upgradable_read();

        // this block exists so that there isn't any nested `if let Some` and allows us to upgrade if we pass by it
        'assume_exists: {
            let Some(map) = lock.get(fighter) else { break 'assume_exists; };
            let Some(info) = map.get(&slot) else { break 'assume_exists; };
            return info.has_trail;
        }

        // upgrade the lock so that we can make a new entry
        let mut lock = RwLockUpgradableReadGuard::upgrade(lock);

        // make a new entry, there is no way for the lookups to fail after this so just unwrap
        Self::create_cache_entry(&mut lock, fighter, slot);
        let map = lock.get(fighter).unwrap();
        let info = map.get(&slot).unwrap();
        info.has_trail
    }
}

struct HashCache(RwLock<HashMap<Hash40, HashMap<usize, Hash40>>>);

impl HashCache {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    pub fn get_one_slotted_effect(&self, eff_hash: Hash40, slot: usize) -> Option<Hash40> {
        let lock = self.0.read();

        let eff_map = lock.get(&eff_hash)?;
        eff_map.get(&slot).map(|new_hash| *new_hash)
    }

    pub fn push_one_slotted_effect(&self, real: Hash40, slot: usize, new_hash: Hash40) {
        let mut lock = self.0.write();

        'assume_exists: {
            let Some(eff_map) = lock.get_mut(&real) else { break 'assume_exists };
            let _ = eff_map.insert(slot, new_hash);
            return;
        }

        let mut new_map = HashMap::new();
        new_map.insert(slot, new_hash);
        lock.insert(real, new_map);
    }
}

struct FighterEffectCache(RwLock<HashMap<usize, HashSet<Hash40>>>);

impl FighterEffectCache {
    pub fn new() -> Self {
        Self(RwLock::new(HashMap::new()))
    }

    pub fn is_effect_for_fighter(&self, kind: usize, eff_hash: Hash40) -> bool {
        let lock = self.0.read();

        let Some(hashes) = lock.get(&kind) else { return false };

        hashes.contains(&eff_hash)
    }

    pub fn set_effect_for_fighter(&self, kind: usize, eff_hash: Hash40) {
        let mut lock = self.0.write();

        'assume_exists: {
            let Some(hashes) = lock.get_mut(&kind) else { break 'assume_exists };
            let _ = hashes.insert(eff_hash);
            return;
        }

        let mut new_set = HashSet::new();
        let _ = new_set.insert(eff_hash);
        let _ = lock.insert(kind, new_set);
    }
}

/// The instruction for NOP on the armv8 architecture
const AARCh264_NOP: u32 = 0xD503201F;

/// The current fighter's name when loading effects
static mut EFF_FIGHTER_NAME: Option<&'static str> = None;

/// The current one-slot effect slot for a fighter when loading effects
static mut EFF_FIGHTER_SLOT: Option<usize> = None;

/// The current one-slot trail slot for a fighter when loading effect trails
static mut EFF_FIGHTER_TRAIL_SLOT: Option<usize> = None;

static mut EFF_FIGHTER_KIND: Option<usize> = None;

/// The number of fighter names located in static memory
const FIGHTER_STRING_COUNT: usize = 0x75;

/// The array of [`FIGHTER_STRING_COUNT`] fighter names
static FIGHTER_NAMES: Lazy<Vec<&'static str>> = Lazy::new(|| unsafe {
    let array = std::slice::from_raw_parts(
        (0x4f81e20 + skyline::hooks::getRegionAddress(skyline::hooks::Region::Text) as u64)
            as *const *const u8,
        FIGHTER_STRING_COUNT,
    );

    array
        .iter()
        .map(|ptr| {
            let length = skyline::libc::strlen(*ptr);
            std::str::from_utf8(std::slice::from_raw_parts(*ptr, length)).unwrap()
        })
        .collect()
});

static FIGHTER_ONE_SLOT_EFFS: Lazy<SlotCache> = Lazy::new(SlotCache::new);

static EFF_HASH_LOOKUP: Lazy<HashCache> = Lazy::new(HashCache::new);

static FIGHTER_EFFECT_NAMES: Lazy<FighterEffectCache> = Lazy::new(FighterEffectCache::new);

/// Gets the fighter name for the specified index. This pulls from [`FIGHTER_NAMES`] but does an index check
/// before getting the name
fn get_fighter_name(index: usize) -> &'static str {
    if index >= 0x76 {
        return "none";
    }

    FIGHTER_NAMES[index]
}

/// This hook is run first, and is used to get the fighter kind and the costume slot
/// for the fighter which is loading it's effect.
///
/// When this function is called, it is about to lookup a fighter file, and the following registers
/// are being used as arguments to that function:
/// * `out_path_index: *mut u32` (`x0`) - The output PathEntryIndex that matches the specified args
/// * `player_info: *mut u8` (`x1`) - The player information for this fighter, it includes the costume slot
/// * `fighter_kind` (`w2`)
/// * `what` (`w3`) - The kind of file to lookup
///
/// We aren't setting any of the registers, we are only observing, so there are no post conditions for us.
///
/// We will only be looking at anything passed with `0x14` as the `what` argumet, since that
/// is the one that returns the path index for the effect folds
#[skyline::hook(offset = 0x60bf3c, inline)]
unsafe fn fighter_lookup_effect_folder(ctx: &skyline::hooks::InlineCtx) {
    assert_eq!(*ctx.registers[3].w.as_ref(), 0x14); // ensure that we are looking up an effect

    // get the costume slot
    let costume_slot = *(*ctx.registers[1].x.as_ref() as *const u8).add(100) as usize;

    MOVIE_SLOT = costume_slot;

    // get the fighter kind as a usize because we are going to lookup the fighter string
    let fighter_kind = *ctx.registers[2].w.as_ref() as usize;

    // get the fighter name from the fighter kind
    let fighter_name = get_fighter_name(fighter_kind);

    // if there is a one slot effect then we want to set the one-slot effect global
    if FIGHTER_ONE_SLOT_EFFS.has_one_slot_effect(fighter_name, costume_slot) {
        EFF_FIGHTER_SLOT = Some(costume_slot);
    }

    // if there is a one slot trail then we want ot set the one-slot trail global
    if FIGHTER_ONE_SLOT_EFFS.has_one_slot_trail(fighter_name, costume_slot) {
        EFF_FIGHTER_TRAIL_SLOT = Some(costume_slot);
    }

    EFF_FIGHTER_NAME = Some(fighter_name);
    EFF_FIGHTER_KIND = Some(fighter_kind);
}

/// This hook is used to further qualify how the game selects which file to load for effect data.
///
/// When the EFF initialization function is called, it is passed three parameters:
/// * `EffectManager::instance_`
/// * `key` - The key to a hashmap for the effect information to be stored. If it's already in the hashamp then it is
///             ignored.
/// * `dir_path_index` - The index used to find the `PathListEntry` for the effect's parent directory (this is passed instead
///                         of a filepath index because the game also searches for trails)
///
/// When searching through the directory provided by the `dir_path_index`, it searches for the first file that
/// uses an `eff` extension, which is fine in vanilla, but if we want to add more we have to add some discriminating factors:
/// 1. If it is a fighter, and we don't have a one-slot effect, we need to make sure the file name is `ef_<fighter name>.eff`
/// 2. If it is a fighter, and we don't have a one-slot effect, we need to make sure the file name is `ef_<fighter name>_c<slot>.eff`
/// 3. If it is not a fighter, we just perform regular behavior
///
/// Pre Conditions:
/// * `x8`: The pointer to the `PathListEntry`
/// * `x26`: The hashmap key (useful for quickly checking if we are a fighter or not)
///
/// Post Conditions:
/// * `x8`: 0 if we want to accept the `PathListEntry`, non-zero if we want to reject it
/// * `x9`: the `Hash40` for "eff"
#[skyline::hook(offset = 0x35602ec, inline)]
unsafe fn check_extension_eff_inline_hook(ctx: &mut skyline::hooks::InlineCtx) {
    let eff_hash = Hash40::from("eff");

    // get the path list entry from x8
    let path_list_entry: &PathListEntry = &*(*ctx.registers[8].x.as_ref() as *const PathListEntry);

    // satisfy post conditions before doing fighter only block
    *ctx.registers[8].x.as_mut() = if path_list_entry.ext.hash40() == eff_hash {
        0
    } else {
        1
    };
    *ctx.registers[9].x.as_mut() = eff_hash.as_u64();

    // Don't bother checking if the extension is not eff
    if *ctx.registers[8].x.as_ref() != 0 {
        return;
    }

    // Get the hashmap key and if mask it for the fighter set
    if *ctx.registers[26].w.as_ref() & 0xF00 != 0x300 {
        return;
    }

    // Check if we have a name, otherwise this is not an actual fighter.
    // Some effects loaded with the fighter key set are common effects.
    let Some(name) = EFF_FIGHTER_NAME.as_ref() else { return };

    // Get the right file name depending on if we have a one-slot effect
    let hash = if let Some(slot) = EFF_FIGHTER_SLOT.as_ref() {
        hash40_fmt!("ef_{}_c{:02}.eff", name, slot)
    } else {
        hash40_fmt!("ef_{}.eff", name)
    };

    // Based on the file name hash accept or reject the `PathListEntry`
    *ctx.registers[8].x.as_mut() = if path_list_entry.file_name.hash40() == hash {
        0
    } else {
        1
    };
}

/// This function is run immediately after the Fighter object's call to the EFF loading function.
///
/// We want to invalidate all of our global data so that the next time an effect is loaded it
/// doesn't assume to be part of a fighter
#[skyline::hook(offset = 0x60bfdc, inline)]
unsafe fn one_slot_cleanup(_: &skyline::hooks::InlineCtx) {
    EFF_FIGHTER_NAME = None;
    EFF_FIGHTER_SLOT = None;
    EFF_FIGHTER_TRAIL_SLOT = None;
}

#[skyline::hook(offset = 0x355fe74, inline)]
unsafe fn get_trail_folder_hash(ctx: &mut skyline::hooks::InlineCtx) {
    // Pre conditions:
    // x8: The already processed CRC32 hash (inverted)
    // x9: The new length of the CRC32 hash
    // x26: the hashmap key
    // Post conditions:
    // x8: The crc32 to search for (but inverted)
    // x10: The length of the hash

    if *ctx.registers[26].w.as_ref() & 0xF00 != 0x300 {
        *ctx.registers[10].w.as_mut() = *ctx.registers[9].w.as_ref();
        return;
    }

    if let Some(fighter_name) = EFF_FIGHTER_NAME.as_ref() {
        if let Some(costume_slot) = EFF_FIGHTER_TRAIL_SLOT.as_ref() {
            let hash = Hash40::from(
                format!("effect/fighter/{}/trail_c{:02}", fighter_name, costume_slot).as_str(),
            );
            *ctx.registers[10].w.as_mut() = hash.len() as u32;
            *ctx.registers[8].w.as_mut() = !hash.crc32();
        } else {
            *ctx.registers[10].w.as_mut() = *ctx.registers[9].w.as_ref();
        }
    } else {
        *ctx.registers[10].w.as_mut() = *ctx.registers[9].w.as_ref();
    }
}

#[skyline::hook(offset = 0x3560b80, inline)]
unsafe fn get_raw_nutexb_data(ctx: &mut skyline::hooks::InlineCtx) {
    let Some(slot) = EFF_FIGHTER_TRAIL_SLOT.as_ref() else { return };
    let slot = *slot;

    let raw_data = *ctx.registers[1].x.as_ref() as *mut u8;
    let size = *ctx.registers[2].x.as_ref() as usize;

    if raw_data.is_null() {
        panic!("Trail nutexb data is unloaded for slot c{:02} (fighter unknown), please make sure your config.json files are correct", slot);
    }

    let footer = std::slice::from_raw_parts(raw_data.add(size - 0x70), 0x70);

    let mut reader = std::io::Cursor::new(footer);
    
    let mut footer: nutexb::NutexbFooter = reader.read_le().unwrap();
    let current_name = footer.string.to_string();
    let new_name = format!("{}_C{:02}", current_name, slot);
    // println!("{} -> {}", current_name, new_name);
    footer.string = binrw::NullString::from(new_name.clone());

    let mut footer_data = std::slice::from_raw_parts_mut(raw_data.add(size - 0x70), 0x70);

    let current_hash = Hash40::from(current_name.to_lowercase().as_str());
    let new_hash = Hash40::from(new_name.to_lowercase().as_str());
    if let Some(kind) = EFF_FIGHTER_KIND.as_ref() {
        // println!("setting fighter eff name: {:#x} {:#x}", *kind, current_hash.as_u64());
        FIGHTER_EFFECT_NAMES.set_effect_for_fighter(*kind, current_hash);
    }
    EFF_HASH_LOOKUP.push_one_slotted_effect(current_hash, slot, new_hash);

    let mut writer = std::io::Cursor::new(footer_data);
    writer.write_le(&footer).unwrap();
}

#[skyline::hook(offset = 0x3560640, inline)]
unsafe fn get_raw_eff_data(ctx: &mut skyline::hooks::InlineCtx) {
    let Some(slot) = EFF_FIGHTER_SLOT.as_ref() else { return };
    let Some(name) = EFF_FIGHTER_NAME.as_ref() else { return };
    let Some(kind) = EFF_FIGHTER_KIND.as_ref() else { return };
    let slot = *slot;
    let fighter_name = *name;
    let kind = *kind;

    let mut raw_eff_data = *(*ctx.registers[8].x.as_ref() as *const *const u8);
    if raw_eff_data.is_null() {
        panic!("The effect data for {} slot c{:02} is unloaded, please make sure your config.json is correct!", fighter_name, slot);
    }
    let header_size = (*(raw_eff_data.add(0xE) as *const u16) as usize) * 0x1000;
    let mut reader = std::io::Cursor::new(std::slice::from_raw_parts(raw_eff_data, header_size));
    let mut header: eff_header::EffFile = reader.read_le().unwrap();

    for str in header.entry_names.iter() {
        let name = str.to_string().to_lowercase();
        FIGHTER_EFFECT_NAMES.set_effect_for_fighter(kind, Hash40::from(name.as_str()));
        EFF_HASH_LOOKUP.push_one_slotted_effect(
            Hash40::from(name.as_str()),
            slot,
            hash40_fmt!("{}_c{:02}", name, slot),
        );
    }
    header.set_for_slot(slot);

    let mut empty_vec = Vec::new();
    std::mem::swap(&mut empty_vec, &mut header.external_model_names);

    header.external_model_names = empty_vec
        .into_iter()
        .map(|name| {
            let one_slot_folder_name = name.to_string().to_lowercase();
            let one_slot_folder_name = format!("{}_c{:02}", one_slot_folder_name, slot);
            print!(
                "checking for {} ({}): ",
                one_slot_folder_name,
                name.to_string()
            );
            if Path::new("mods:/effect/fighter/")
                .join(fighter_name)
                .join("model")
                .join(one_slot_folder_name.as_str())
                .exists()
            {
                println!("exists!");
                binrw::NullString::from(one_slot_folder_name)
            } else {
                println!("does not exist!");
                name
            }
        })
        .collect();

    let new_size = header.get_required_chunk_align();

    if header_size != new_size {
        println!("making new header");
        let vfxb_size = *(raw_eff_data.add(header_size + 0x1C) as *const u32) as usize;

        let new_memory = skyline::libc::memalign(0x1000, new_size + vfxb_size) as *mut u8;
        std::ptr::copy_nonoverlapping(
            raw_eff_data.add(header_size),
            new_memory.add(new_size),
            vfxb_size,
        );
        *(*ctx.registers[8].x.as_ref() as *mut *mut u8) = new_memory;
        let old_memory = raw_eff_data as *mut u8;
        raw_eff_data = new_memory;
        skyline::libc::free(old_memory as _);
        header.header.header_chunk_align = (new_size / 0x1000) as u16;
    }
    let mut writer = std::io::Cursor::new(std::slice::from_raw_parts_mut(
        raw_eff_data as *mut u8,
        new_size,
    ));
    writer.write_le(&header).unwrap();
}

#[skyline::from_offset(0x3ac560)]
unsafe fn battle_object_from_id(id: u32) -> *mut u32;

#[skyline::hook(offset = 0x60bfd8, inline)]
unsafe fn tmp(ctx: &mut skyline::hooks::InlineCtx) {
    let Some(slot) = EFF_FIGHTER_SLOT.as_ref() else { return };
    let slot = 1 + *slot as u32;
    *ctx.registers[1].w.as_mut() += slot * 0x1000;
}

static mut CURRENT_EXECUTING_OBJECT: u32 = 0x50000000u32;

static SET_OFFSETS: &[usize] = &[
    0x3ac7fc, 0x3ac8f8, 0x3ac9a8, 0x3aca54, 0x3acb24, 0x3acbc0, 0x3acc6c, 0x3adf98, 0x3ae030,
    0x3adb88, 0x3adc38, 0x3adcdc, 0x3ad240, 0x3ad2f0, 0x3ad394, 0x3acda0, 0x3ace50, 0x3acef4,
    0x3ad930, 0x3ad9e0, 0x3ada84, 0x3acff0, 0x3ad0a0, 0x3ad144, 0x3ad490, 0x3ad540, 0x3ad5e4,
    0x3ad6e0, 0x3ad784, 0x3ad834, 0x6573ec, // this is on agent init
];

static UNSET_OFFSETS: &[usize] = &[
    0x3acc9c, 0x3ad870, 0x3ae06c, 0x3ade44, 0x3ad3cc, 0x3acf2c, 0x3adabc, 0x3ad178, 0x3ad61c,
];

static mut OFFSET: usize = 0usize;

#[skyline::hook(offset = OFFSET, inline)]
unsafe fn set_current_exe_obj(ctx: &skyline::hooks::InlineCtx) {
    CURRENT_EXECUTING_OBJECT = *(*ctx.registers[0].x.as_ref() as *const u32).add(2);
}

#[skyline::hook(offset = OFFSET, inline)]
unsafe fn unset_current_exe_obj(_: &skyline::hooks::InlineCtx) {
    CURRENT_EXECUTING_OBJECT = 0x50000000u32;
}

unsafe fn get_new_effect_name(object_id: u32, current_name: Hash40) -> Option<Hash40> {
    if object_id == 0x50000000u32 {
        println!(
            "Object ID is invalid for effect {}",
            current_name.global_label().unwrap_or(format!("{:#x}", current_name.0))
        );
        return None;
    }

    let category = object_id >> 0x1C;
    let parent_object = match category {
        0x0 => battle_object_from_id(object_id) as *mut smash::app::BattleObject, // fighters
        0x1 => {
            // weapons
            let weapon = battle_object_from_id(object_id) as *mut smash::app::BattleObject;
            let new_id = WorkModule::get_int(
                (*weapon).module_accessor,
                *WEAPON_INSTANCE_WORK_ID_INT_LINK_OWNER,
            ) as u32;
            return get_new_effect_name(new_id, current_name);
        }
        0x4 => {
            // weapons & items
            let item = battle_object_from_id(object_id) as *mut smash::app::BattleObject;
            if LinkModule::is_link((*item).module_accessor, *LINK_NO_ARTICLE) {
                return get_new_effect_name(
                    LinkModule::get_parent_id((*item).module_accessor, *LINK_NO_ARTICLE, false)
                        as u32,
                    current_name,
                );
            }
            return None;
        }
        _ => {
            // println!("unhandled");
            return None; // unhandled as of yet
        }
    };

    let parent_object = &mut *parent_object;

    let mut kind = parent_object.kind as usize;
    if kind == *FIGHTER_KIND_NANA as usize {
        kind = *FIGHTER_KIND_POPO as usize;
    }

    if !FIGHTER_EFFECT_NAMES.is_effect_for_fighter(kind, current_name) {
        if kind == *FIGHTER_KIND_KIRBY as usize {
            let chara_kind = WorkModule::get_int(
                parent_object.module_accessor,
                *FIGHTER_KIRBY_INSTANCE_WORK_ID_INT_COPY_CHARA,
            );
            if chara_kind != -1 {
                let chara_kind = chara_kind as usize;
                let slot =
                    (WorkModule::get_int(parent_object.module_accessor, 0x100000fd) - 1) as usize;
                if FIGHTER_EFFECT_NAMES.is_effect_for_fighter(chara_kind, current_name) {
                    return EFF_HASH_LOOKUP.get_one_slotted_effect(current_name, slot);
                }
            }
        }
        // println!("Effect {:#x} not for fighter kind {}", current_name.as_u64(), kind);
        return None;
    }

    let slot = WorkModule::get_int(
        parent_object.module_accessor,
        *FIGHTER_INSTANCE_WORK_ID_INT_COLOR,
    ) as usize;
    let Some(new) = EFF_HASH_LOOKUP.get_one_slotted_effect(current_name, slot) else { return None };
    // println!("Changed effect {:#x} to {:#x}", current_name.as_u64(), new.as_u64());
    Some(new)
}

#[skyline::hook(offset = 0x355b550, inline)]
unsafe fn get_handle_by_hash(ctx: &mut skyline::hooks::InlineCtx) {
    let current_hash = Hash40::from(*ctx.registers[1].x.as_ref());
    *ctx.registers[1].x.as_mut() = get_new_effect_name(CURRENT_EXECUTING_OBJECT, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

#[skyline::hook(offset = 0x35630d0, inline)]
unsafe fn make_effect(ctx: &mut skyline::hooks::InlineCtx) {
    let Some(new_effect) = get_new_effect_name(CURRENT_EXECUTING_OBJECT, Hash40::from(*ctx.registers[1].x.as_ref())) else { return };

    *ctx.registers[1].x.as_mut() = new_effect.as_u64();
}

#[skyline::hook(offset = 0x3567330, inline)]
unsafe fn make_after_image(ctx: &skyline::hooks::InlineCtx) {
    let ptr = *ctx.registers[0].x.as_ref() as *mut Hash40;
    let first_hash = *ptr.add(4);
    let second_hash = *ptr.add(5);

    *ptr.add(4) = get_new_effect_name(CURRENT_EXECUTING_OBJECT, first_hash).unwrap_or(first_hash);
    *ptr.add(5) = get_new_effect_name(CURRENT_EXECUTING_OBJECT, second_hash).unwrap_or(second_hash);
}

#[skyline::hook(offset = 0x3563ad0, inline)]
unsafe fn detach_effect(ctx: &mut skyline::hooks::InlineCtx) {
    let current_hash = Hash40::from(*ctx.registers[3].x.as_ref());
    *ctx.registers[3].x.as_mut() = get_new_effect_name(CURRENT_EXECUTING_OBJECT, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

#[skyline::hook(offset = 0x3563bd0, inline)]
unsafe fn kill_effect(ctx: &mut skyline::hooks::InlineCtx) {
    let current_hash = Hash40::from(*ctx.registers[5].x.as_ref());
    *ctx.registers[5].x.as_mut() = get_new_effect_name(CURRENT_EXECUTING_OBJECT, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

static MOVIE_CACHE: Lazy<HashCache> = Lazy::new(|| {
    let jack_path = Path::new("mods:/prebuilt;/movie/fighter/jack");
    let pickel_path = Path::new("mods:/prebuilt;/movie/fighter/pickel");
    let brave_path = Path::new("mods:/prebuilt;/movie/fighter/brave");
    let edge_path = Path::new("mods:/prebuilt;/movie/fighter/edge");

    let cache = HashCache::new();

    let mut counter = 0;
    loop {
        if jack_path
            .join(&format!("c{:02}", counter))
            .join("final_00.h264")
            .exists()
        {
            cache.push_one_slotted_effect(
                hash40_fmt!("prebuilt:/movie/fighter/jack/c00/final_00.h264"),
                counter,
                hash40_fmt!("prebuilt:/movie/fighter/jack/c{:02}/final_00.h264", counter),
            );
        } else if counter < 8 {
            continue;
        } else {
            break;
        }

        if jack_path
            .join(&format!("c{:02}", counter))
            .join("final_01.h264")
            .exists()
        {
            cache.push_one_slotted_effect(
                hash40_fmt!("prebuilt:/movie/fighter/jack/c00/final_01.h264"),
                counter,
                hash40_fmt!("prebuilt:/movie/fighter/jack/c{:02}/final_01.h264", counter),
            );
        } else if counter < 8 {
            continue;
        } else {
            break;
        }

        counter += 1;
    }

    let mut counter = 0;
    loop {
        if pickel_path
            .join(&format!("c{:02}", counter))
            .join("final_00.h264")
            .exists()
        {
            cache.push_one_slotted_effect(
                hash40_fmt!("prebuilt:/movie/fighter/pickel/c00/final_00.h264"),
                counter,
                hash40_fmt!(
                    "prebuilt:/movie/fighter/pickel/c{:02}/final_00.h264",
                    counter
                ),
            );
        } else if counter < 8 {
            continue;
        } else {
            break;
        }
        counter += 1;
    }

    let mut counter = 0;
    loop {
        if brave_path
            .join(&format!("c{:02}", counter))
            .join("final_00.h264")
            .exists()
        {
            cache.push_one_slotted_effect(
                hash40_fmt!("prebuilt:/movie/fighter/brave/c00/final_00.h264"),
                counter,
                hash40_fmt!(
                    "prebuilt:/movie/fighter/brave/c{:02}/final_00.h264",
                    counter
                ),
            );
        } else if counter > 7 {
            break;
        }
        counter += 1;
    }

    let mut counter = 0;
    loop {
        if edge_path
            .join(&format!("c{:02}", counter))
            .join("final_00.h264")
            .exists()
        {
            cache.push_one_slotted_effect(
                hash40_fmt!("prebuilt:/movie/fighter/edge/c00/final_00.h264"),
                counter,
                hash40_fmt!("prebuilt:/movie/fighter/edge/c{:02}/final_00.h264", counter),
            );
        } else if counter > 7 {
            break;
        }
        counter += 1;
    }

    cache
});

static mut MOVIE_SLOT: usize = 0;

static MOVIE_OFFSETS: &[usize] = &[0xf02bb8, 0xb2fadc, 0xb2fba0, 0x9da1b4, 0x850400];

#[skyline::hook(offset = OFFSET, inline)]
unsafe fn one_slot_movies2(ctx: &mut skyline::hooks::InlineCtx) {
    // let parent_object = *ctx.registers[19].x.as_ref() as *mut smash::app::BattleObject;
    // let slot = WorkModule::get_int((*parent_object).module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_COLOR) as usize;

    if let Some(hash) =
        MOVIE_CACHE.get_one_slotted_effect(Hash40::from(*ctx.registers[1].x.as_ref()), MOVIE_SLOT)
    {
        *ctx.registers[1].x.as_mut() = hash.0;
    }
}

#[skyline::hook(offset = 0x67f460, inline)]
unsafe fn one_slot_movies(ctx: &mut skyline::hooks::InlineCtx) {
    let object_id = CURRENT_EXECUTING_OBJECT;
    if object_id == 0x50000000u32 {
        println!(
            "Object ID is invalid for effect {:#x}",
            *ctx.registers[1].x.as_ref()
        );
        return;
    }

    let category = object_id >> 0x1C;
    let parent_object = match category {
        0x0 => battle_object_from_id(object_id) as *mut smash::app::BattleObject, // fighters
        _ => return,
    };

    let slot = WorkModule::get_int(
        (*parent_object).module_accessor,
        *FIGHTER_INSTANCE_WORK_ID_INT_COLOR,
    ) as usize;

    if let Some(hash) =
        MOVIE_CACHE.get_one_slotted_effect(Hash40::from(*ctx.registers[1].x.as_ref()), slot)
    {
        *ctx.registers[1].x.as_mut() = hash.0;
    }
}

#[skyline::hook(offset = 0x2359948, inline)]
unsafe fn main_menu_create(_: &skyline::hooks::InlineCtx) {
    Lazy::force(&MOVIE_CACHE);
}

#[skyline::hook(offset = 0x60bf78, inline)]
unsafe fn fix_object_ptr(ctx: &mut skyline::hooks::InlineCtx) {
    *ctx.registers[8].x.as_mut() += 0xC;
}

#[skyline::main(name = "one-slot-eff")]
pub fn main() {

    if Path::new(labels).is_file() {
        Hash40::set_global_labels_file(labels).unwrap();
    }

    std::panic::set_hook(Box::new(|info| {
        let location = info.location().unwrap();

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<Any>",
            },
        };

        let err_msg = format!("thread has panicked at '{}', {}", msg, location);
        skyline::error::show_error(
            69,
            "Skyline plugin as panicked! Please open the details and send a screenshot to the developer, then close the game.\n",
            err_msg.as_str()
        );
    }));
    unsafe {
        // nop all of the following instructions because we are replacing them with a hook of our own
        let _ = skyline::patching::patch_data(
            0x35602ec,
            &[
                AARCh264_NOP,
                AARCh264_NOP,
                AARCh264_NOP,
                AARCh264_NOP,
                AARCh264_NOP,
                AARCh264_NOP,
            ],
        );
        let _ = skyline::patching::nop_data(0x355fe74);
        let _ = skyline::patching::patch_data(0x60bf78, &0x52800009u32);
    }
    skyline::install_hooks!(
        get_raw_eff_data,
        check_extension_eff_inline_hook,
        get_trail_folder_hash,
        fighter_lookup_effect_folder,
        one_slot_cleanup,
        tmp,
        make_effect,
        get_raw_nutexb_data,
        make_after_image,
        detach_effect,
        kill_effect,
        get_handle_by_hash,
        // one_slot_movies,
        // main_menu_create,
        fix_object_ptr
    );

    unsafe {
        for offset in SET_OFFSETS.iter() {
            OFFSET = *offset;
            skyline::install_hook!(set_current_exe_obj);
        }
        for offset in UNSET_OFFSETS.iter() {
            OFFSET = *offset;
            skyline::install_hook!(unset_current_exe_obj);
        }
        // for offset in MOVIE_OFFSETS.iter() {
        //     OFFSET = *offset;
        //     skyline::install_hook!(one_slot_movies2);
        // }
    }
}
