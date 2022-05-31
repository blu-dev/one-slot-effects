#![feature(proc_macro_hygiene)]
#![feature(label_break_value)]
#![feature(let_else)]
mod eff_header;
mod nx;

use binrw::{
    BinRead, BinReaderExt, BinWriterExt
};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use parking_lot::lock_api::RwLockUpgradableReadGuard;

use std::{path::{PathBuf, Path}, collections::HashMap};

use smash_arc::{Hash40, PathListEntry};

macro_rules! hash40_fmt {
    ($($arg:tt)*) => {{
        smash_arc::Hash40::from(format!($($arg)*).as_str())
    }}
}

/// Struct with flags for each of the one-slottable things
struct OneSlotInfo {
    has_effect: bool,
    has_trail: bool
}

/// Data structure to maintain cached state about one-slot effects and trails so that it doesn't
/// have to be requeried each time
struct SlotCache(
    RwLock<HashMap<&'static str, HashMap<usize, OneSlotInfo>>>
);

impl SlotCache {
    /// Creates a new cache entry by querying the `mods:/` filesystem hosted by ARCropolis
    fn create_cache_entry(map: &mut HashMap<&'static str, HashMap<usize, OneSlotInfo>>, fighter_name: &'static str, slot: usize) {
        let root_path = Path::new("mods:/effect/fighter").join(fighter_name);
        let has_effect = root_path.join(&format!("ef_{}_c{:02}.eff", fighter_name, slot)).exists();
        let has_trail  = root_path.join(&format!("trail_c{:02}", slot)).exists();
        if let Some(sub_map) = map.get_mut(fighter_name) {
            sub_map.insert(slot, OneSlotInfo {
                has_effect,
                has_trail
            });
        } else {
            let mut sub_map = HashMap::new();
            sub_map.insert(slot, OneSlotInfo {
                has_effect,
                has_trail
            });
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
            return info.has_effect
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
            return info.has_trail
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

/// The instruction for NOP on the armv8 architecture
const AARCH64_NOP: u32 = 0xD503201F;

/// The current fighter's name when loading effects
static mut EFF_FIGHTER_NAME: Option<&'static str> = None;

/// The current one-slot effect slot for a fighter when loading effects
static mut EFF_FIGHTER_SLOT: Option<usize> = None;

/// The current one-slot trail slot for a fighter when loading effect trails
static mut EFF_FIGHTER_TRAIL_SLOT: Option<usize> = None;

/// The number of fighter names located in static memory
const FIGHTER_STRING_COUNT: usize = 0x75;

/// The array of [`FIGHTER_STRING_COUNT`] fighter names
static FIGHTER_NAMES: Lazy<Vec<&'static str>> = Lazy::new(|| unsafe {
    let array = std::slice::from_raw_parts(
        (0x4f7fe20 + skyline::hooks::getRegionAddress(skyline::hooks::Region::Text) as u64) as *const *const u8,
        FIGHTER_STRING_COUNT
    );

    array
        .iter()
        .map(|ptr| {
            let length = skyline::libc::strlen(*ptr);
            std::str::from_utf8(std::slice::from_raw_parts(
                *ptr,
                length
            )).unwrap()
        })
        .collect()
});

static FIGHTER_ONE_SLOT_EFFS: Lazy<SlotCache> = Lazy::new(SlotCache::new);

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
#[skyline::hook(offset = 0x60bf1c, inline)]
unsafe fn fighter_lookup_effect_folder(ctx: &skyline::hooks::InlineCtx) {
    assert_eq!(*ctx.registers[3].w.as_ref(), 0x14); // ensure that we are looking up an effect
    
    // get the costume slot
    let costume_slot = *(*ctx.registers[1].x.as_ref() as *const u8).add(100) as usize;
    
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
#[skyline::hook(offset = 0x355f66c, inline)]
unsafe fn check_extension_eff_inline_hook(ctx: &mut skyline::hooks::InlineCtx) {
    let eff_hash = Hash40::from("eff");

    // get the path list entry from x8
    let path_list_entry: &PathListEntry = &*(*ctx.registers[8].x.as_ref() as *const PathListEntry);
    
    // satisfy post conditions before doing fighter only block
    *ctx.registers[8].x.as_mut() = if path_list_entry.ext.hash40() == eff_hash { 0 } else { 1 };
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
    *ctx.registers[8].x.as_mut() = if path_list_entry.file_name.hash40() == hash { 0 } else { 1 };
}

/// This function is run immediately after the Fighter object's call to the EFF loading function.
/// 
/// We want to invalidate all of our global data so that the next time an effect is loaded it
/// doesn't assume to be part of a fighter
#[skyline::hook(offset = 0x60bfbc, inline)]
unsafe fn one_slot_cleanup(_: &skyline::hooks::InlineCtx) {
    EFF_FIGHTER_NAME = None;
    EFF_FIGHTER_SLOT = None;
    EFF_FIGHTER_TRAIL_SLOT = None;
}

#[skyline::hook(offset = 0x355f1f4, inline)]
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
        if let Some(costume_slot) = EFF_FIGHTER_TRAIL_SLOT.take() {
            let hash = Hash40::from(format!("effect/fighter/{}/trail_c{:02}", fighter_name, costume_slot).as_str());
            *ctx.registers[10].w.as_mut() = hash.len() as u32;
            *ctx.registers[8].w.as_mut() = !hash.crc32();
        } else {
            *ctx.registers[10].w.as_mut() = *ctx.registers[9].w.as_ref();
        }
    } else {
        *ctx.registers[10].w.as_mut() = *ctx.registers[9].w.as_ref();
    }
}

#[skyline::hook(offset = 0x355f9c0, inline)]
unsafe fn get_raw_eff_data(ctx: &mut skyline::hooks::InlineCtx) {
    let slot = if let Some(slot) = EFF_FIGHTER_SLOT.as_ref() {
        *slot
    } else {
        return;
    };

    let raw_eff_data = *(*ctx.registers[8].x.as_ref() as *const *const u8);
    let header_size = (*(raw_eff_data.add(0xE) as *const u16) as usize) * 0x1000;
    let mut reader = std::io::Cursor::new(std::slice::from_raw_parts(raw_eff_data, header_size));
    let mut header: eff_header::EffFile = reader.read_le().unwrap();
    header.set_for_slot(slot);
    let new_size = header.get_required_chunk_align();
    let mut writer = std::io::Cursor::new(std::slice::from_raw_parts_mut(raw_eff_data as *mut u8, header_size));
    writer.write_le(&header).unwrap();
}

static mut HOOK_OFFSET: usize = 0x44e074;

#[skyline::from_offset(0x3ac540)]
unsafe fn battle_object_from_id(id: u32) -> *mut u32;

#[skyline::hook(offset = HOOK_OFFSET, inline)]
unsafe fn quick_change_hash(ctx: &mut skyline::hooks::InlineCtx) {
    let effect_module = *ctx.registers[19].x.as_ref();
    let boma = *(effect_module as *mut u64).add(1) as *mut smash::app::BattleObjectModuleAccessor;
    let battle_object_id = *(boma as *mut u32).add(2);
    let object = battle_object_from_id(battle_object_id);
    let kind = *object.add(3);
    // if kind == 0x14 && (*boma).work().get_int(smash::app::work_ids::fighter::instance::COLOR) == 0 {
        *ctx.registers[1].x.as_mut() = smash::phx::Hash40::new_raw(*ctx.registers[1].x.as_ref()).concat("_c00").as_u64();
    // }
}

#[skyline::main(name = "one-slot-eff")]
pub fn main() {
    unsafe {
        // nop all of the following instructions because we are replacing them with a hook of our own
        let _ = skyline::patching::patch_data(0x355f66c, &[AARCH64_NOP, AARCH64_NOP, AARCH64_NOP, AARCH64_NOP, AARCH64_NOP, AARCH64_NOP]);
        // let _ = skyline::patching::nop_data(0x355f1f4);
    }
    skyline::install_hooks!(
        // get_raw_eff_data,
        check_extension_eff_inline_hook,
        // get_trail_folder_hash,
        fighter_lookup_effect_folder,
        one_slot_cleanup
    );
}
