# detours-example
API hooking example project using Detours
# Table ofContents
+ [Install](#Install)
+ [Usage](#Usage)
+ [License](#License)
# Install
1. Run git bash
```bash
git clone https://github.com/zxc010613/detours-example.git
cd detours-example
git submodule init
git submodule update
```
2. Run `Developer Command Prompt for VS 2019(or 2017)
```bash
cd Detours
nmake
cd ..
devenv detours-example.sln /build  "release|x86"
```
# Usage
1. Run detours-example.exe
2. Run dll-injector.exe(Run as administrator)

# License
[MIT License](./LICENSE)
