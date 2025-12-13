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

    #[inline(always)]
    #[cfg(any(test, not(target_family = "wasm")))]
    pub fn has_aes(&self) -> bool {
        cpufeatures::new!(aes_detection, "aes");

        #[cfg(test)]
        match self.behaviour {
            FeatureDetectorBehaviour::None => aes_detection::get(),
            FeatureDetectorBehaviour::ForceAesTrue => true,
            FeatureDetectorBehaviour::ForceAesFalse => false,
        }

        #[cfg(not(test))]
        aes_detection::get()
    }

    #[cfg(test)]
    pub fn change_behaviour(&mut self, behaviour: FeatureDetectorBehaviour) {
        self.behaviour = behaviour;
    }
}
