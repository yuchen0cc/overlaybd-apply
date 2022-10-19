# Overlaybd-apply

## Requirements

```bash
yum install e2fsprogs-devel
```

## Build

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j
cp output/overlaybd-apply /opt/overlaybd/bin/
```
