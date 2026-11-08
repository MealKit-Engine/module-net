# MealKit-Net

> **Beta.** MealKit is in beta: interfaces may still change between minor versions.

MealKit engine module `net` (`module.txt`, `type engine`). The engine repository vendors a locked copy in `modules/<name>/` (`modules.lock`, `tools\modules.ps1`); a game adds it to its own `modules/` with the engine's `tools\module.ps1 add <name>[@version]`.

Working on it: clone it beside `MealKit` and build the engine with `tools\modules.ps1 local` (MEALKIT_LOCAL_MODULES), then tag a version and `tools\modules.ps1 bump`. MIT license.
