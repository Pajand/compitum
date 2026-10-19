//! Where the software is going.
//!
//! # Why this module exists
//!
//! A routing decision is only meaningful relative to a destination. The same binary can be
//! native on one target, translatable on another and impossible on a third, and until this
//! module existed COMPITUM had exactly **one** destination built into its logic: the machine it
//! happened to be running on, with whatever compatibity layer was installed there.
//!
//! That is not migration analysis. Migration analysis answers "will this run *there*?", and a
//! product that answers "will this run *here*" cannot serve it — which was the substance of a
//! fair criticism levelled at this design: the tool was measuring Wine compatibility and calling
//! it a migration platform.
//!
//! # What changes between targets
//!
//! The differences are not cosmetic. Measured against Microsoft's published behaviour for
//! Windows 11 on Arm:
//!
//! | Image | Windows 11 on Arm | Linux with Wine |
//! |---|---|---|
//! | pure ARM64 | native, no layer | native code, but needs Wine for NT syscalls |
//! | **ARM64EC** | **native** — it is Microsoft's own ABI | hybrid: AArch64 native, x86-64 via FEX |
//! | ARM64X | native slice selected | native slice selected |
//! | x86-64 | Prism emulation, built into the OS | Box64 or FEX, a separate install |
//! | x86 (32-bit) | WOW64 + Prism, built into the OS | Box86, a separate install |
//! | **kernel driver** | **must be ARM64; x86 drivers cannot load** | **cannot load at all** |
//! | managed (.NET) | JIT-compiled to ARM64 by the CLR | JIT-compiled, needs Wine's CLR |
//!
//! Two rows are worth pausing on, because both contradict what this router said before.
//!
//! **ARM64EC is native on Windows.** It is the ABI Microsoft designed precisely so that x86-64
//! and AArch64 code can share a process on Windows on Arm. Reporting it as "hybrid, FEX
//! required, 70-90% of native" was correct for Linux and wrong for the platform the customer is
//! migrating to — and it understated the product's own best case by 10-30%.
//!
//! **A kernel driver cannot be emulated anywhere.** Microsoft states that emulation supports
//! user-mode code only and that kernel components must be compiled as Arm64. On Linux it cannot
//! load at all. Either way the answer is not a route but a rewrite, and a tool that reported a
//! driver as a cheap native port would send a migration down the wrong path.
//!
//! # Why the default is unchanged
//!
//! [`MigrationTarget::LinuxWithWine`] is the default, so every existing caller keeps the
//! behaviour it already relies on and nothing regresses silently. A target is a fact the caller
//! must state, and stating nothing should not silently mean "Windows".
//!
//! # What this does not require
//!
//! Nothing here inspects a host or runs anything. The target is a parameter, which is why the
//! analysis stays pure and reproducible: given the same image and the same declared target, the
//! same plan comes out.

use crate::route::Route;

/// The platform the software is being migrated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrationTarget {
    /// Windows 11 on Arm: the destination a migration usually has in mind.
    ///
    /// The operating system supplies the NT syscall layer, an x86/x64 emulator (Prism) and full
    /// support for ARM64EC, so none of those is a prerequisite the customer must install.
    WindowsOnArm,
    /// Linux running Wine, which is what this router assumed before targets existed.
    ///
    /// The default, so existing behaviour is preserved exactly.
    #[default]
    LinuxWithWine,
}

impl MigrationTarget {
    /// A stable identifier, for JSON and for the Oracle record.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            MigrationTarget::WindowsOnArm => "windows-on-arm",
            MigrationTarget::LinuxWithWine => "linux-wine",
        }
    }

    /// Parses an identifier, for the command line.
    ///
    /// Accepts the same spellings a person would reasonably type, and rejects anything else
    /// rather than falling back to a default: a mistyped `--target` that silently produced an
    /// analysis of the wrong platform would be the worst possible failure for this product.
    #[must_use]
    pub fn from_id(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "windows-on-arm" | "windows" | "win" | "woa" => Some(MigrationTarget::WindowsOnArm),
            "linux-wine" | "linux" | "wine" => Some(MigrationTarget::LinuxWithWine),
            _ => None,
        }
    }

    /// A sentence describing the destination, for a report.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            MigrationTarget::WindowsOnArm => {
                "Windows 11 on Arm, where the operating system supplies the NT layer and \
                 emulates x86 and x86-64 itself"
            }
            MigrationTarget::LinuxWithWine => {
                "Linux with Wine, where the NT layer is a separate package and any x86 \
                 translation must be installed alongside it"
            }
        }
    }

    /// Returns `true` when the destination supplies its own NT system-call layer.
    ///
    /// On Windows this is the operating system; on Linux it is Wine, which is a dependency the
    /// operator has to provide. The distinction decides whether [`crate::reason::ReasonCode::SyscallLayerAbsent`]
    /// is a blocker or meaningless.
    #[must_use]
    pub fn supplies_syscall_layer(self) -> bool {
        matches!(self, MigrationTarget::WindowsOnArm)
    }

    /// Returns `true` when the destination emulates x86-64 without an extra install.
    ///
    /// Windows 11 on Arm includes Prism and emulates x86-64 with no additional component. On
    /// Linux the equivalent (Box64 or FEX) is a separate package, so its presence has to be
    /// measured rather than assumed.
    #[must_use]
    pub fn emulates_x86_64_natively(self) -> bool {
        matches!(self, MigrationTarget::WindowsOnArm)
    }

    /// Returns `true` when the destination can load a kernel driver of this architecture.
    ///
    /// # A correction, because the first reading of this was wrong
    ///
    /// Microsoft states that emulation covers user-mode code only and that kernel components
    /// must be compiled as Arm64. Read quickly, that sounds like "no drivers anywhere", and it
    /// was implemented that way first. It is not what the sentence says.
    ///
    /// The rule is about **emulation**: an *emulated* kernel driver is impossible, and a kernel
    /// component has to be built for Arm64. An Arm64 driver on Windows on Arm is therefore
    /// ordinary native kernel code and loads normally. What cannot load is an x86 or x86-64
    /// driver, on either destination.
    ///
    /// On Linux the answer is different again: a Windows driver cannot load at all, because
    /// there is no Windows kernel to load it into.
    ///
    /// `is_arm64` is the architecture of the driver, not of the destination.
    #[must_use]
    pub fn loads_kernel_drivers(self, is_arm64: bool) -> bool {
        match self {
            // Only an Arm64 driver, and only on the operating system that has a Windows kernel.
            MigrationTarget::WindowsOnArm => is_arm64,
            // A Windows driver cannot load on Linux regardless of its architecture, because
            // there is no kernel that would accept it.
            MigrationTarget::LinuxWithWine => false,
        }
    }

    /// The route an ARM64EC image takes on this target.
    ///
    /// On Windows it is [`Route::Native`]: ARM64EC is Microsoft's own ABI for mixing AArch64 and
    /// x86-64 in one process, and the operating system implements the boundary. On Linux it is
    /// [`Route::FexPartial`], because there the coexistence has to be provided by FEX.
    ///
    /// This is the single most consequential difference between the two targets, and getting it
    /// wrong understated the product's best case on the platform migrations actually target.
    #[must_use]
    pub fn arm64ec_route(self) -> Route {
        match self {
            MigrationTarget::WindowsOnArm => Route::Native,
            MigrationTarget::LinuxWithWine => Route::FexPartial,
        }
    }
}

impl std::fmt::Display for MigrationTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_target_preserves_existing_behaviour() {
        // A target is a fact the caller must state. Defaulting to Windows would silently change
        // every existing verdict, so the default is the platform this router already assumed.
        assert_eq!(MigrationTarget::default(), MigrationTarget::LinuxWithWine);
    }

    #[test]
    fn an_identifier_round_trips() {
        for target in [
            MigrationTarget::WindowsOnArm,
            MigrationTarget::LinuxWithWine,
        ] {
            assert_eq!(
                MigrationTarget::from_id(target.id()),
                Some(target),
                "{}",
                target.id()
            );
        }
    }

    #[test]
    fn reasonable_spellings_are_accepted() {
        for text in ["windows", "WIN", "woa", "Windows-On-Arm"] {
            assert_eq!(
                MigrationTarget::from_id(text),
                Some(MigrationTarget::WindowsOnArm),
                "{text}"
            );
        }
        for text in ["linux", "wine", "LINUX-WINE"] {
            assert_eq!(
                MigrationTarget::from_id(text),
                Some(MigrationTarget::LinuxWithWine),
                "{text}"
            );
        }
    }

    #[test]
    fn an_unknown_identifier_is_rejected_rather_than_defaulted() {
        // The worst failure this product could have: a mistyped target silently analysed the
        // wrong platform and produced a confident, wrong report.
        for text in ["", "android", "windows-on-x86", "macos", "arm64"] {
            assert_eq!(MigrationTarget::from_id(text), None, "{text:?}");
        }
    }

    #[test]
    fn windows_supplies_what_linux_requires_an_install_for() {
        assert!(MigrationTarget::WindowsOnArm.supplies_syscall_layer());
        assert!(!MigrationTarget::LinuxWithWine.supplies_syscall_layer());

        assert!(MigrationTarget::WindowsOnArm.emulates_x86_64_natively());
        assert!(!MigrationTarget::LinuxWithWine.emulates_x86_64_natively());
    }

    #[test]
    fn an_emulated_kernel_driver_cannot_load_but_a_native_one_can() {
        // THE CORRECTION. Microsoft's rule is about emulation, not about drivers in general:
        // an emulated kernel driver is impossible and a kernel component must be built for
        // Arm64 — which means an Arm64 driver on Windows on Arm is ordinary native kernel code
        // and loads normally.
        //
        // The first implementation of this method returned `false` for every target, which
        // would have told a customer their working Arm64 driver needed a rewrite.
        assert!(
            MigrationTarget::WindowsOnArm.loads_kernel_drivers(true),
            "an Arm64 driver is native kernel code on Windows on Arm"
        );
        assert!(
            !MigrationTarget::WindowsOnArm.loads_kernel_drivers(false),
            "an emulated kernel driver is impossible anywhere"
        );
        assert!(
            !MigrationTarget::LinuxWithWine.loads_kernel_drivers(true),
            "there is no Windows kernel on Linux for any driver to load into"
        );
        assert!(!MigrationTarget::LinuxWithWine.loads_kernel_drivers(false));
    }

    #[test]
    fn arm64ec_is_native_on_windows_and_hybrid_on_linux() {
        // The correction this module exists for. ARM64EC is Microsoft's own ABI, so on Windows
        // there is no translator involved and the throughput is native rather than 70-90%.
        assert!(MigrationTarget::WindowsOnArm
            .arm64ec_route()
            .is_fully_native());
        assert_eq!(MigrationTarget::WindowsOnArm.arm64ec_route(), Route::Native);
        assert_eq!(
            MigrationTarget::LinuxWithWine.arm64ec_route(),
            Route::FexPartial
        );
        assert!(MigrationTarget::LinuxWithWine.arm64ec_route().is_hybrid());
    }

    #[test]
    fn every_target_has_a_description_and_an_id() {
        for target in [
            MigrationTarget::WindowsOnArm,
            MigrationTarget::LinuxWithWine,
        ] {
            assert!(!target.id().is_empty());
            assert!(target.description().len() > 30, "{}", target.id());
        }
    }
}
