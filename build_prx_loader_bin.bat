ppu-lv2-gcc -c prx_loader_fixed.S -o prx_loader_fixed.o
ppu-lv2-objcopy -O binary -j .text prx_loader_fixed.o prx_loader_fixed.bin
