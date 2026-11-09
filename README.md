# module-net

> **Beta.** MealKit is in beta: interfaces may still change between minor versions.

MealKit engine module `net` (`module.txt`, `type engine`). The engine repository vendors a locked copy in `modules/<name>/` (`modules.lock`, `tools\module.ps1 engine`); a game adds it to its own `modules/` with the engine's `tools\module.ps1 add <name>[@version]`.

Working on it: clone it beside `MealKit` and build the engine with `tools\module.ps1 engine local on <name>`, then tag a version and `tools\module.ps1 engine bump`. MIT license.
