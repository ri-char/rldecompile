FROM debian:bullseye

RUN \
  apt update &&\
  apt -y install gnupg2 curl &&\
  echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" > /etc/apt/sources.list.d/llvm.list &&\
  echo "deb-src http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" >> /etc/apt/sources.list.d/llvm.list &&\
  curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - &&\
  apt update &&\
  apt -y install wget clang-14 llvm-14 llvm-14-dev cmake ninja-build libclang-14-dev &&\
  find /usr/bin/ -name "*-14" -exec bash -c "f={};ln -sf \$f \${f%-14}" \;

RUN --mount=type=bind,source=.,target=/app,rw \
  cd /app/;\
  rm -rf build || true;\
  mkdir build &&\
  cd build &&\
  cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang -G Ninja .. &&\
  ninja
