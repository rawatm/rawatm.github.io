---
layout: post
title:  "Resolving some common issues while installing CBGP simulator"
date:   2016-12-05 11:07:12 +0530
categories: bgp simulator
---


C-BGP is a BGP solver developed by [Bruno Quoitin][BQ-link]. It can be downloaded from cbgp sourceforge [page][cbgp-download-link]. 
Although the [tutorial][cbgp-tutorial-link] that comes along with C-BGP is quite helpful while installing, there are some issues which can come up easily while installation. Below are some steps I followed to troubleshoot installation

1. Always download the latest version from sourceforge download links. The version mentioned in tutorial has some issues while running the './configure ' command.
2. Install 'libz-dev' before trying to install libgds for CBGP. For ubuntu can be installed using 'sudo apt-get install libz-dev'. Else I was receiving 'ld not found' error.
3. Confirm whether 'libgds' is installed. In Ubuntu default installation location is '/usr/local/include'.
4. Further while installing CBGP you may get error 'libgds.. needs to be installed'. If libgds was installed correctly and you still get this error you may need to export path to CBGP in  'LIBGDS_CFLAGS' and 'LIBGDS_LIBS' flags. It can be done simply exporting it eg. 'export LIBGDS_CFLAGS =/usr/local/lib'

There were other issues I faced during installation, but most of them could be easily resolved by following tutorial properly or a simple google search.

[BQ-link]:http://staff.umh.ac.be/Quoitin.Bruno
[cbgp-download-link]:http://c-bgp.sourceforge.net/downloads.php
[cbgp-tutorial-link]: http://c-bgp.sourceforge.net/tutorial.php