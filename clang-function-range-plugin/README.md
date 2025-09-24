# clang dump function range

## 编译方法

```bash
docker build .
```
结果位于`build/libFunctionRange.so`

## 使用方法
```bash
clang -Xclang -load -Xclang ./libFunctionRange.so -Xclang -plugin -Xclang FunctionRange -Xclang -plugin-arg-FunctionRange -Xclang $OUTPUT_DIR ./tests/a.cpp -c
```
