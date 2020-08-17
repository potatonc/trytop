#!/bin/bash

# auth
clear

# hapus script lama
cd /usr/bin
rm -f menu
rm -f usernew
rm -f trial
rm -f member
rm -f delete
rm -f cek
rm -f restart
rm -f speedtest
rm -f info
rm -f about
rm -f userlimit
rm -f onkill
rm -f offkill
rm -f live
rm -f perpanjang
rm -f berhasil
rm -f cekmemory
rm -f onstat
rm -f offstat
rm -f customport
rm -f cekport
rm -f limit

# download script menu
cd /usr/bin
wget -O menu "https://github.com/potatonc/trytop/raw/master/menu/menu"
wget -O usernew "https://github.com/potatonc/trytop/raw/master/menu/usernew"
wget -O trial "https://github.com/potatonc/trytop/raw/master/menu/trial"
wget -O member "https://github.com/potatonc/trytop/raw/master/menu/member"
wget -O delete "https://github.com/potatonc/trytop/raw/master/menu/delete"
wget -O cek "https://github.com/potatonc/trytop/raw/master/menu/cek"
wget -O restart "https://github.com/potatonc/trytop/raw/master/menu/restart"
wget -O speedtest "https://github.com/potatonc/trytop/raw/master/menu/speedtest"
wget -O info "https://github.com/potatonc/trytop/raw/master/menu/info"
wget -O about "https://github.com/potatonc/trytop/raw/master/menu/about"
wget -O userlimit "https://github.com/potatonc/trytop/raw/master/menu/userlimit"
wget -O live "https://github.com/potatonc/trytop/raw/master/menu/live"
wget -O berhasil "https://github.com/potatonc/trytop/raw/master/menu/berhasil"
wget -O perpanjang "https://github.com/potatonc/trytop/raw/master/menu/perpanjang"
wget -O cekmemory "https://github.com/potatonc/trytop/raw/master/menu/cekmemory"
wget -O onstat "https://github.com/potatonc/trytop/raw/master/menu/onstat"
wget -O offstat "https://github.com/potatonc/trytop/raw/master/menu/offstat"
wget -O customport "https://github.com/potatonc/trytop/raw/master/menu/customport"
wget -O cekport "https://github.com/potatonc/trytop/raw/master/menu/cekport"
wget -O limit "https://github.com/potatonc/trytop/raw/master/menu/limit"


chmod +x menu
chmod +x usernew
chmod +x trial
chmod +x member
chmod +x delete
chmod +x cek
chmod +x restart
chmod +x speedtest
chmod +x info
chmod +x about
chmod +x userlimit
chmod +x live
chmod +x berhasil
chmod +x perpanjang
chmod +x cekmemory
chmod +x onstat
chmod +x offstat
chmod +x customport
chmod +x cekport
chmod +x limit

# root
cd
rm -f update.sh

echo ""
echo " Update Fitur Berhasil..."
echo ""
echo ""
          echo -e "---------------------------------------"
          echo -e "    Terimakasih sudah menggunakan-"
          echo -e "      Script Modified by Potato"
          echo -e "---------------------------------------"
          echo -e ""
