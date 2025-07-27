#![feature(proc_macro_hygiene)]
#![feature(label_break_value)]
#![feature(let_else)]
#![allow(unused)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(stable_features)]
#![allow(improper_ctypes_definitions)]
#![allow(static_mut_refs)]

mod eff_header;
mod nx;
mod eff_hashes;

use binrw::{BinRead, BinReaderExt, BinWriterExt};
use once_cell::sync::Lazy;
use parking_lot::lock_api::RwLockUpgradableReadGuard;
use parking_lot::RwLock;
use smash::{
    app::{
        lua_bind::*,
        *,
        Fighter
    },
    lib::{
        lua_const::*, 
        L2CValue, 
        L2CAgent
    }
};

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use smash_arc::{Hash40, HashLabels, PathListEntry};

use eff_hashes::*;

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

impl SlotCache {
    /// Creates a new cache entry by querying the `mods:/` filesystem hosted by ARCropolis
    fn create_cache_entry(
        map: &mut HashMap<&'static str, HashMap<usize, OneSlotInfo>>,
        fighter_name: &'static str,
        slot: usize,
    ) {
        // println!("creating SlotCache entry for slot {}", slot as i32);
        let root_path = Path::new("mods:/effect/fighter").join(fighter_name);
        let has_effect = root_path
            .join(&format!("ef_{}_c{:02}.eff", fighter_name, slot))
            .exists();
        let has_trail = root_path.join(&format!("trail_c{:02}", slot)).exists();
        if let Some(sub_map) = map.get_mut(fighter_name) {
            // println!("insterting sub-map for slot {} into {}'s existing hash map", slot as i32, fighter_name);
            sub_map.insert(
                slot,
                OneSlotInfo {
                    has_effect,
                    has_trail,
                },
            );
        } else {
            // println!("inserting sub-map for slot {} into a new hash map for {}", slot as i32, fighter_name);
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
        if info.has_effect { println!("{} slot {} has unique effects", fighter, slot as i32)} 
        else {println!("{} slot {} uses base effects", fighter, slot as i32)};
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
        if info.has_trail { println!("{} slot {} has unique trails", fighter, slot as i32)} 
        else {println!("{} slot {} uses base trails", fighter, slot as i32)};
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
        // println!("caching effect {:#x}. current cache size is {}", eff_hash.as_u64(), lock.len() as i32);

        'assume_exists: {
            let Some(hashes) = lock.get_mut(&kind) else { break 'assume_exists };
            let _ = hashes.insert(eff_hash);
            return;
        }
        
        println!("making new effect cache set for fighter kind {}", kind as i32);
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
        (0x4f80e20 + skyline::hooks::getRegionAddress(skyline::hooks::Region::Text) as u64)
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

    // if there is a one slot trail then we want to set the one-slot trail global
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
/// 2. If it is a fighter, and we do have a one-slot effect, we need to make sure the file name is `ef_<fighter name>_c<slot>.eff`
/// 3. If it is not a fighter, we just perform regular behavior
///
/// Pre Conditions:
/// * `x8`: The pointer to the `PathListEntry`
/// * `x26`: The hashmap key (useful for quickly checking if we are a fighter or not)
///
/// Post Conditions:
/// * `x8`: 0 if we want to accept the `PathListEntry`, non-zero if we want to reject it
/// * `x9`: the `Hash40` for "eff"
#[skyline::hook(offset = 0x356009c, inline)]
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
        // if let Some(slot) =  EFF_FIGHTER_SLOT.as_ref() {
        //     println!("accepting PathListEntry for slot {}'s eff", *slot as i32);
        // } else { 
        //     println!("accepting PathListEntry for base eff file");
        // };
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

#[skyline::hook(offset = 0x355fc24, inline)]
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

#[skyline::hook(offset = 0x3560930, inline)]
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

#[skyline::hook(offset = 0x35603f0, inline)]
unsafe fn get_raw_eff_data(ctx: &mut skyline::hooks::InlineCtx) {
    let Some(name) = EFF_FIGHTER_NAME.as_ref() else { return };
    let Some(kind) = EFF_FIGHTER_KIND.as_ref() else { return };
    let Some(slot) = EFF_FIGHTER_SLOT.as_ref() else { 
        println!("fighter eff data is not one-slotted. continuing as normal.");
        return
    };
    let fighter_name = *name;
    let kind = *kind;
    let slot = *slot;

    let mut raw_eff_data = *(*ctx.registers[8].x.as_ref() as *const *const u8);
    if raw_eff_data.is_null() {
        panic!("The effect data for {} slot c{:02} is unloaded, please make sure your config.json is correct!", fighter_name, slot);
    }
    let header_size = (*(raw_eff_data.add(0xE) as *const u16) as usize) * 0x1000;
    let mut reader = std::io::Cursor::new(std::slice::from_raw_parts(raw_eff_data, header_size));
    let mut header: eff_header::EffFile = reader.read_le().unwrap();

    println!("adding eff data for slot c{:02} to {}'s cache", slot, fighter_name);
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

// this hook was previously ran on 0x60bfd8. it is moved up 0x4 so that it runs before that same offset used in smashline
// this in turn allows smashline's transplanted effects to still work without affecting one slot effects
// otherwise, if they share the offset, OSE cannot properly cache effects beyond the first file loaded for any given fighter
#[skyline::hook(offset = 0x60bfd4, inline)]
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

static mut DITTO_BUFFER: bool = false;

unsafe fn get_new_effect_name(object_id: u32, current_name: Hash40) -> Option<Hash40> {
    let effect_name = current_name.global_label().unwrap_or(format!("{:#x}", current_name.0));
    if object_id == 0x50000000u32 {
        // println!("Object ID is invalid for effect {effect_name}");
        return None;
    }

    // uses labels to bypass running any additional logic if the effect is a common 'sys_' effect
    if effect_name.starts_with("sys_")
    || effect_name.starts_with("pickel_rail") { // make an exception for minecart rails. these get called a LOT and will lag the game if we don't bypass them
        // println!("bypassing effect ({})", effect_name);
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
            // let owner_boma = sv_battle_object::module_accessor(new_id);
            // let owner_kind = utility::get_kind(&mut *owner_boma);
            // println!("weapon call. running function again with owner of kind {}", owner_kind);
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
            else if LinkModule::is_link((*item).module_accessor, *ITEM_LINK_NO_CREATEOWNER) {
                return get_new_effect_name(
                    LinkModule::get_parent_id((*item).module_accessor, *ITEM_LINK_NO_CREATEOWNER, false)
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

    // println!("checking fighter kind {} for effect {}", parent_object.kind, effect_name);
    let mut kind = parent_object.kind as usize;
    if kind == *FIGHTER_KIND_NANA as usize {
        kind = *FIGHTER_KIND_POPO as usize;
    }

    // process unique hit effects specifically for dittos, so that effects match the attacker rather than the defender
    let handle_ditto_effs = 
        (effect_name.starts_with("bayonetta_hit") && kind == *FIGHTER_KIND_BAYONETTA as usize)
        || (effect_name.starts_with("jack_gun_hit") && kind == *FIGHTER_KIND_JACK as usize)
        || (effect_name.starts_with("demon_hit") && kind == *FIGHTER_KIND_DEMON as usize)
        || (effect_name.starts_with("trail_hit") && kind == *FIGHTER_KIND_TRAIL as usize);
    if handle_ditto_effs && !DITTO_BUFFER {
        println!("handling ditto!");
        DITTO_BUFFER = true; // enable a buffer so this doesnt get caught in an infinite loop
        let defender_entry_id = WorkModule::get_int(parent_object.module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_ENTRY_ID);
        for i in 0..8 {
            if i == defender_entry_id { continue };
            let opponent_boma = sv_battle_object::module_accessor(Fighter::get_id_from_entry_id(i));
            let opponent_kind = utility::get_kind(&mut *opponent_boma);
            if opponent_kind == -1 { continue };
            let opponent_slot = (WorkModule::get_int(opponent_boma, *FIGHTER_INSTANCE_WORK_ID_INT_COLOR) - 1);
            if FIGHTER_EFFECT_NAMES.is_effect_for_fighter(opponent_kind as usize, current_name) {
                let new_id = Fighter::get_id_from_entry_id(i);
                return get_new_effect_name(new_id as u32, current_name); // this check will turn the buffer back off
            }
        }
    } else {
        DITTO_BUFFER = false;
    }

    if !FIGHTER_EFFECT_NAMES.is_effect_for_fighter(kind, current_name) {
        // with common effects and weapons ruled out, we can assume if we are in this block that there is
        // most likely a fighter trying to call effects from a different fighter

        // run an additional check for pocket, inhale, and copy abilities
        let pocket_charas: [usize;4] = [
            *FIGHTER_KIND_MURABITO as usize,
            *FIGHTER_KIND_SHIZUE as usize,
            *FIGHTER_KIND_KIRBY as usize,
            *FIGHTER_KIND_DEDEDE as usize
        ];

        // make an exception for certain hit effects, since they actually get called by the opponent rather than the fighter themself
        let is_uniq_hit_effect = 
            effect_name.starts_with("bayonetta_")
            || effect_name.starts_with("jack_")
            || effect_name.starts_with("trail_") 
            || effect_name.starts_with("demon_");

        if (pocket_charas).contains(&kind)
        || is_uniq_hit_effect {
            // checks each active player to see if any of them own the effect we are trying to call
            for i in 0..8 {
                let opponent_boma = sv_battle_object::module_accessor(Fighter::get_id_from_entry_id(i));
                let opponent_kind = utility::get_kind(&mut *opponent_boma);
                if opponent_kind == -1 { continue };
                let opponent_slot = (WorkModule::get_int(opponent_boma, *FIGHTER_INSTANCE_WORK_ID_INT_COLOR) - 1);
                // println!("checking opponent kind {}", opponent_kind);
                // check if the current fighter we are checking matches the attempted effect hash
                if FIGHTER_EFFECT_NAMES.is_effect_for_fighter(opponent_kind as usize, current_name) {
                    // println!("found a match on {}, borrowing effect from opponent slot {}", i, opponent_slot);
                    // grab the id of the effect's owner so we can actually call it
                    let new_id = Fighter::get_id_from_entry_id(i);

                    // re-queries this function with the discovered owner
                    return get_new_effect_name(new_id as u32, current_name);
                }
            }
        }

        // certain effects that are costume-specific are called with a unique id
        // we can derive the base effect's hash from this and instead requery with the correct emitter name
        let arg11_effects: [&str; 9] = [
            "duckhunt_feather",
            "duckhunt_feather_long",
            "fox_tail_attack_01",
            "samusd_gbeam_flash_01",
            "sonic_runtrace",
            "sonic_appealruntrace",
            "yoshi_entry_01",
            "yoshi_gorogorotamago_01",
            "yoshi_tamago_kakera_01"
        ];
        let costume = WorkModule::get_int(parent_object.module_accessor, *FIGHTER_INSTANCE_WORK_ID_INT_COLOR) as u64;
        let mut base_id = format!("{:#x}", current_name.as_u64()).replace(format!("{:#x}", costume).as_str(), "0x");
        if base_id.starts_with("0x0") { base_id = base_id.replace("0x0", "0x") };
        for effect in arg11_effects {
            let hex_string = format!("{:#x}", Hash40::from(effect).as_u64());
            if hex_string == base_id.as_str() && costume != 0 {
                let fixed_name = 
                    if effect.contains("_01") {
                        [effect.replace("_01", ""), format!("{:02}", costume + 1)].join("_")
                    }
                    else {
                        [effect, format!("{:02}", costume).as_str()].join("_")
                    };
                // println!("corrected effect label: {}", fixed_name);

                return get_new_effect_name(object_id, Hash40::from(fixed_name.as_str()));
            }
        }

        // println!("effect is not assigned to fighter {}'s costume slot", kind);

        return None;
    }

    let slot = WorkModule::get_int(
        parent_object.module_accessor,
        *FIGHTER_INSTANCE_WORK_ID_INT_COLOR,
    ) as usize;
    let Some(new) = EFF_HASH_LOOKUP.get_one_slotted_effect(current_name, slot) else { return None };
    // println!("Changed effect {} to {}", effect_name, new.global_label().unwrap_or(format!("{:#x}", new.0)));
    Some(new)
}

#[skyline::hook(offset = 0x355b300, inline)]
unsafe fn get_handle_by_hash(ctx: &mut skyline::hooks::InlineCtx) {
    let current_hash = Hash40::from(*ctx.registers[1].x.as_ref());
    *ctx.registers[1].x.as_mut() = get_new_effect_name(CURRENT_EXECUTING_OBJECT, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

#[skyline::hook(offset = 0x3562e80, inline)]
unsafe fn make_effect(ctx: &mut skyline::hooks::InlineCtx) {
    let Some(new_effect) = get_new_effect_name(CURRENT_EXECUTING_OBJECT, Hash40::from(*ctx.registers[1].x.as_ref())) else { return };

    *ctx.registers[1].x.as_mut() = new_effect.as_u64();
}

#[skyline::hook(offset = 0x35670e0, inline)]
unsafe fn make_after_image(ctx: &skyline::hooks::InlineCtx) {
    let ptr = *ctx.registers[0].x.as_ref() as *mut Hash40;
    let first_hash = *ptr.add(4);
    let second_hash = *ptr.add(5);

    *ptr.add(4) = get_new_effect_name(CURRENT_EXECUTING_OBJECT, first_hash).unwrap_or(first_hash);
    *ptr.add(5) = get_new_effect_name(CURRENT_EXECUTING_OBJECT, second_hash).unwrap_or(second_hash);
}

#[skyline::hook(offset = 0x3563880, inline)]
unsafe fn detach_effect(ctx: &mut skyline::hooks::InlineCtx) {
    let current_hash = Hash40::from(*ctx.registers[3].x.as_ref());
    *ctx.registers[3].x.as_mut() = get_new_effect_name(CURRENT_EXECUTING_OBJECT, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

#[skyline::hook(offset = 0x3563980, inline)]
unsafe fn kill_effect(ctx: &mut skyline::hooks::InlineCtx) {
    let current_hash = Hash40::from(*ctx.registers[5].x.as_ref());
    *ctx.registers[5].x.as_mut() = get_new_effect_name(CURRENT_EXECUTING_OBJECT, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

// EffectModule::detach_kind
#[skyline::hook(offset = 0x20178d0, inline)]
unsafe fn detach_kind(ctx: &mut skyline::hooks::InlineCtx) {
    let boma = *ctx.registers[0].x.as_ref() as *mut BattleObjectModuleAccessor;
    let current_hash = Hash40::from(*ctx.registers[1].x.as_ref());
    *ctx.registers[1].x.as_mut() = get_new_effect_name((&mut *boma).battle_object_id, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

// EffectModule::end_kind
#[skyline::hook(offset = 0x20178f0, inline)]
unsafe fn end_kind(ctx: &mut skyline::hooks::InlineCtx) {
    let boma = *ctx.registers[0].x.as_ref() as *mut BattleObjectModuleAccessor;
    let current_hash = Hash40::from(*ctx.registers[1].x.as_ref());
    *ctx.registers[1].x.as_mut() = get_new_effect_name((&mut *boma).battle_object_id, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

// EffectModule::kill_kind
#[skyline::hook(offset = 0x2017860, inline)]
unsafe fn kill_kind(ctx: &mut skyline::hooks::InlineCtx) {
    let boma = *ctx.registers[0].x.as_ref() as *mut BattleObjectModuleAccessor;
    let current_hash = Hash40::from(*ctx.registers[1].x.as_ref());
    *ctx.registers[1].x.as_mut() = get_new_effect_name((&mut *boma).battle_object_id, current_hash)
        .unwrap_or(current_hash)
        .as_u64();
}

// sv_animcmd::EFFECT_DETACH_KIND
#[skyline::hook(offset = 0x22a5780, inline)]
unsafe fn effect_detach_hook(ctx: &mut skyline::hooks::InlineCtx) {
    let lua_state = *ctx.registers[0].x.as_ref();
    let mut agent: L2CAgent = L2CAgent::new(lua_state.clone());
    let mut params: [L2CValue ; 16] = [
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), 
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), 
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), 
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void()
    ];
    for i in 0..16 { params[i as usize] = agent.pop_lua_stack(i + 1) };

    agent.clear_lua_stack();
    for i in 0..16 {
        if i == 0 { // effect hash index
            let mut effect_name = params[i as usize].get_u64();
            let mut hash = Hash40::from(effect_name);
            let new = get_new_effect_name(CURRENT_EXECUTING_OBJECT, hash).unwrap_or(hash);
            agent.push_lua_stack(&mut L2CValue::new_hash(new.as_u64()));
        } else {
            agent.push_lua_stack(&mut params[i as usize]);
        }
    }
}

// sv_animcmd::EFFECT_GLOBAL_BACK_GROUND
#[skyline::hook(offset = 0x228f460, inline)]
unsafe fn global_back_ground_hook(ctx: &mut skyline::hooks::InlineCtx) {
    let lua_state = *ctx.registers[0].x.as_ref();
    let mut agent: L2CAgent = L2CAgent::new(lua_state.clone());
    let mut params: [L2CValue ; 16] = [
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), 
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), 
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), 
        L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void(), L2CValue::new_void()
    ];
    for i in 0..16 { params[i as usize] = agent.pop_lua_stack(i + 1) };

    agent.clear_lua_stack();
    for i in 0..16 {
        if i == 0 { // effect hash index
            let mut effect_name = params[i as usize].get_u64();
            let mut hash = Hash40::from(effect_name);
            for i in 0..8 {
                // since these backgrounds are called on a common level, we will manually check each entry id to find any fighter-specific background effects
                let id = Fighter::get_id_from_entry_id(i);
                if let Some(new) = get_new_effect_name(id as u32, hash) {
                    hash = new;
                    break;
                } else {
                    continue;
                };
            }
            agent.push_lua_stack(&mut L2CValue::new_hash(hash.as_u64()));
        } else {
            agent.push_lua_stack(&mut params[i as usize]);
        }
    }
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

#[skyline::hook(offset = 0x2359968, inline)]
unsafe fn main_menu_create(_: &skyline::hooks::InlineCtx) {
    Lazy::force(&MOVIE_CACHE);
}

#[skyline::hook(offset = 0x60bf78, inline)]
unsafe fn fix_object_ptr(ctx: &mut skyline::hooks::InlineCtx) {
    *ctx.registers[8].x.as_mut() += 0xC;
}

#[skyline::main(name = "one-slot-eff")]
pub fn main() {
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

    Hash40::set_global_labels(HashLabels::from_string(HASH_LABELS));

    unsafe {
        // nop all of the following instructions because we are replacing them with a hook of our own
        skyline::patching::Patch::in_text(0x356009c).data([
            AARCh264_NOP,
            AARCh264_NOP,
            AARCh264_NOP,
            AARCh264_NOP,
            AARCh264_NOP,
            AARCh264_NOP,
        ]);
        skyline::patching::Patch::in_text(0x355fc24).nop();
        skyline::patching::Patch::in_text(0x60bf78).data(0x52800009u32);
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
        detach_kind,
        end_kind,
        kill_kind,
        effect_detach_hook,
        global_back_ground_hook,
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
