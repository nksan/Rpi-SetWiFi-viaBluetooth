#!/bin/bash

cat my_logger.py wifiwpa.py btwifi.py > btwifiset.py
sed -i '/my_logger/d' ./btwifiset.py
sed -i '/import wifiwpa/d' ./btwifiset.py
sed -i 's/Log\./mLOG\./g' ./btwifiset.py
sed -i 's/wifi\.//' ./btwifiset.py