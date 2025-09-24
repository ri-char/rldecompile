# RlDecompile

RlDecompile: Enhancing Llm-Based Decompilation via Reinforcement Learning With a Multi-Faceted Reward Function

# Setup

## Download dependence
```shell
pacman -S clang make uv direnv cmake llvm nlohmann-json
paru -S ghidra-git-bin
# setup direnv by https://direnv.net/docs/hook.html
```

## Configuare Python Environment
```shell
uv sync
cat > .envrc <<EOF
export SILICONFLOW_API="sk-xxxxx"
export MONGODB="mongodb://xxxx:27017?connectTimeoutMS=2000"
export RL_SERVER_KEY="your_password"
export PYTHONPATH=\$(pwd)
source ./.venv/bin/activate
EOF
direnv allow
```

## Compile clang-function-range-plugin

```shell
cd clang-function-range-plugin/
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Compile clib

Run in project root directory.
```shell
git clone https://github.com/jordiae/exebench.git
cd exebench/exebench/clib/
clang -Wall synthesizer.c -c -o synthesizer.o
clang fft_synth/lib.c -c -o fft_synth_lib.o
ar crv libclib.a synthesizer.o fft_synth_lib.o
```

## Configuare Ghidra Environment

Run in project root directory.
```shell
cd ghidra_exporter/
export JAVA_HOME=/usr/lib/jvm/default
./gradlew libJar

PLUGIN_DIR=/opt/ghidra/Ghidra/Extensions/ghidra-exporter-plugin
mkdir -p "$PLUGIN_DIR"/lib
pushd "$PLUGIN_DIR"
cat > extension.properties <<EOF
name=Exporter
version=11.3.2
EOF
touch Module.manifest
popd
cp build/libs/ghidra_exporter-1.0-SNAPSHOT-libs.jar "$PLUGIN_DIR"/lib/
```
