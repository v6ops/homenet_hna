/* homenet_hna homenet_dm

* Copyright (c) 2019 Ray Hunter

* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:

* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
* LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
* WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*/
#ifndef FUNCTIONS_knot_helpers_INCLUDED
#define FUNCTIONS_knot_helpers_INCLUDED



#define MAKE_KNOT_CONFIG "/usr/local/etc/knot/make_knot_config.bash"
#define MAKE_KNOT_DS "/usr/local/etc/knot/make_knot_ds.bash"
#define MAKE_KNOT_DM_DS "/usr/local/etc/knot-dm/make_new_ds.bash"
#define MAKE_KNOT_DM_CONFIG "/usr/local/etc/knot-dm/make_knot_dm_config.bash"
#define KNOT_MAX_FILENAME_LEN 250


#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <string.h>

int fork_make_knot_config(char *zone, char *dm_notify, char *dm_acl);
int fork_make_knot_ds(char *zone,char *ds_filename);

int fork_make_knot_dm_ds(char *ds_rr);
int fork_make_knot_dm_config(char *zone, char *dm_remote);

#endif
