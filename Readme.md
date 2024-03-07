# GSAT (Ghidra-based Static Analysis Toolkit)

A toolkit for conducting multiple static binary analysis based on Ghidra. 

You may use this toolkit for:
1. learning how to work with Ghidra APIs. 
2. building or learning the [Semantics-Oriented Graph](https://github.com/NSSL-SJTU/HermesSim) (SOG). 
3. performing a trivial taint analysis on binaries with Ghidra. 
4. finding the loading address of bare-metal firmware binaries or unstripping some binary functions. 


## Introduction

This repo contains the following tools (See `src\main\java\com\gsat\tools`):
- *build*: build a ghidra project with a specified binary. 
- *find-base*: find the loading address of a firmware. This tool is a refactored and enhanced version of the [SFuzz-FindBase](https://github.com/NSSL-SJTU/SFuzz/tree/main/static_analysis/findbase). 
- *unstrip*: recover the symbols of some specific library functions in stripped binary. Mainly relying on emulating. This tool is a refactored and enhanced version of the [SFuzz-Unstrip](https://github.com/NSSL-SJTU/SFuzz/tree/main/static_analysis/unstrip). 
- *unstrip-from-log*: recover the symbols of functions in stripped binary by analyzing the log functions. This tool is a refactored version of the [SFuzz-UnstripFromLog](https://github.com/NSSL-SJTU/SFuzz/tree/main/static_analysis/unstrip). 
- *taint-analysis*: perform taint-analysis on the input binary and generate potentially vulnerable traces. 
- *pcode-extractor-v2*: lift selected binary functions into various Pcode based representation (e.g. ACFG, ISCG, TSCG, SOG). Used by [HermesSim](https://github.com/NSSL-SJTU/HermesSim). 
    - There is also a useful script to visualize SOG (`script\show_graph.py`). 


## Build

Prerequisites:
1. Prepare Java17 and [Gradle](https://gradle.org/). 
2. The *pcode-extractor-v2* tool requires an invasive modification of Ghidra. You can get a modified jar (with source map) on the [release](https://github.com/sgfvamll/gsat/releases) page. For the building of other tools, you can refer the following instructions to get a office release of ghidra:
    - Get a release of [Ghidra](https://github.com/NationalSecurityAgency/ghidra) (Tested on 10.2.3). 
    - Enter `$GHIDRA_ROOT/support` and run `buildGhidraJar` or `buildGhidraJar.bat`. 
    - And place the obtained `ghidra.jar` file under the `lib` folder of this project. 


Then, you can build a jar file with `gradle build`. 


## Usgae

Please refer files under the `src\main\java\com\gsat\tools` folder for usage. 

For the usage of the *pcode-extractor-v2* tool, you can also refer scripts published at [HermesSim](https://github.com/NSSL-SJTU/HermesSim). 


## LICENSE

```
Copyright (c) 2023 SGFvamll

Code in this repo is released under GPL-3.0 license. 

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
```
