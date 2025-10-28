#!/bin/bash

scp -P $2 -r *.* core_topo_gen nginx webapp scripts corevm@$1:/home/corevm/Documents/core-topo-gen/

