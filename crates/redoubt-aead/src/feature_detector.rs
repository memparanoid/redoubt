// Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only
// See LICENSE in the repository root for full license text.

#[cfg(test)]
pub enum FeatureDetectorBehaviour {
    None,
    ForceAesTrue,
    ForceAesFalse,
}

pub struct FeatureDetector {
    #[cfg(test)]
    behaviour: FeatureDetectorBehaviour,
}

impl FeatureDetector {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            #[cfg(test)]
            behaviour: FeatureDetectorBehaviour::None,
        }
    }

    // Platform-level AES detection (no test override)
    #[inline(always)]
    pub fn platform_has_aes(&self) -> bool {
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "loongarch64"
        ))]
        {
            cpufeatures::new!(aes_detection, "aes");
            aes_detection::get()
        }

        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "loongarch64"
        )))]
        false
    }

    #[inline(always)]
    pub fn has_aes(&self) -> bool {
        #[cfg(test)]
        {
            match self.behaviour {
                FeatureDetectorBehaviour::None => self.platform_has_aes(),
                FeatureDetectorBehaviour::ForceAesTrue => true,
                FeatureDetectorBehaviour::ForceAesFalse => false,
            }
        }

        #[cfg(not(test))]
        self.platform_has_aes()
    }

    #[cfg(test)]
    pub fn change_behaviour(&mut self, behaviour: FeatureDetectorBehaviour) {
        self.behaviour = behaviour;
    }
}
