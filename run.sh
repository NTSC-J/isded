#!/bin/bash

make
sudo pkill app
cd bin
sudo spawn-fcgi -u www-data -s /tmp/test-fcgi.sock ./app

