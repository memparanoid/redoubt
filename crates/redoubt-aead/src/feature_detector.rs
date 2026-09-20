// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[derive(Default)]
pub(crate) enum FeatureDetectorBehaviour {
    #[default]
    None,
    /// Only where the assembly was built, so that no test can name a machine
    /// that cannot exist: forcing this on a target with no AEGIS would hand out
    /// an `Aead` whose assembly was never compiled.
    #[cfg(all(test, aes_asm))]
    ForceAesTrue,
    #[cfg(test)]
    ForceAesFalse,
}

#[derive(Default)]
pub(crate) struct FeatureDetector {
    behaviour: FeatureDetectorBehaviour,
}

impl FeatureDetector {
    /// Where the assembly was never built there is nothing to ask about, and
    /// `cpufeatures` is not a dependency of every target this compiles for.
    #[cfg(not(aes_asm))]
    pub(crate) fn platform_supports_aes(&self) -> bool {
        false
    }

    #[cfg(aes_asm)]
    pub(crate) fn platform_supports_aes(&self) -> bool {
        cpufeatures::new!(aes_detection, "aes");

        aes_detection::get()
    }

    pub(crate) fn supports_aes(&self) -> bool {
        match self.behaviour {
            FeatureDetectorBehaviour::None => self.platform_supports_aes(),
            #[cfg(all(test, aes_asm))]
            FeatureDetectorBehaviour::ForceAesTrue => true,
            #[cfg(test)]
            FeatureDetectorBehaviour::ForceAesFalse => false,
        }
    }

    #[cfg(test)]
    pub fn with_behaviour(mut self, behaviour: FeatureDetectorBehaviour) -> Self {
        self.behaviour = behaviour;
        self
    }
}
