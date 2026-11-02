// Copyright (C) 2026 Yamato Security
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Terminal colors. The palette is the one Hayabusa and Suzaku use, so a user of the sibling
//! tools reads the same colors the same way: level colors for rows, green for labels, red for
//! errors, orange for warnings.

use termcolor::Color;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IwatobiColor {
    Red,
    Orange,
    Yellow,
    Green,
    Cyan,
    White,
}

impl IwatobiColor {
    /// The termcolor color, or `None` when colors are disabled or the color is the default white.
    pub fn rdg(&self, no_color: bool) -> Option<Color> {
        if no_color {
            return None;
        }
        match self {
            IwatobiColor::Red => Some(Color::Rgb(255, 0, 0)),
            IwatobiColor::Orange => Some(Color::Rgb(255, 175, 0)),
            IwatobiColor::Yellow => Some(Color::Rgb(255, 255, 0)),
            IwatobiColor::Green => Some(Color::Rgb(0, 255, 0)),
            IwatobiColor::Cyan => Some(Color::Rgb(0, 255, 255)),
            IwatobiColor::White => None,
        }
    }

    /// Color of a Sigma level: critical red, high orange, medium yellow, low green, the rest default.
    pub fn for_level(level: &str) -> IwatobiColor {
        match level.to_ascii_lowercase().as_str() {
            "critical" | "crit" => IwatobiColor::Red,
            "high" => IwatobiColor::Orange,
            "medium" | "med" => IwatobiColor::Yellow,
            "low" => IwatobiColor::Green,
            _ => IwatobiColor::White,
        }
    }

    /// The same color for comfy-table cells.
    pub fn table_color(&self) -> comfy_table::Color {
        match self {
            IwatobiColor::Red => comfy_table::Color::Rgb { r: 255, g: 0, b: 0 },
            IwatobiColor::Orange => comfy_table::Color::Rgb {
                r: 255,
                g: 175,
                b: 0,
            },
            IwatobiColor::Yellow => comfy_table::Color::Rgb {
                r: 255,
                g: 255,
                b: 0,
            },
            IwatobiColor::Green => comfy_table::Color::Rgb { r: 0, g: 255, b: 0 },
            IwatobiColor::Cyan => comfy_table::Color::Rgb {
                r: 0,
                g: 255,
                b: 255,
            },
            IwatobiColor::White => comfy_table::Color::Rgb {
                r: 255,
                g: 255,
                b: 255,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_colors_follow_the_sibling_palette() {
        assert_eq!(IwatobiColor::for_level("critical"), IwatobiColor::Red);
        assert_eq!(IwatobiColor::for_level("HIGH"), IwatobiColor::Orange);
        assert_eq!(IwatobiColor::for_level("medium"), IwatobiColor::Yellow);
        assert_eq!(IwatobiColor::for_level("low"), IwatobiColor::Green);
        assert_eq!(
            IwatobiColor::for_level("informational"),
            IwatobiColor::White
        );
        assert_eq!(IwatobiColor::Red.rdg(true), None);
        assert_eq!(IwatobiColor::Green.rdg(false), Some(Color::Rgb(0, 255, 0)));
    }
}
