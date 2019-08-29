/* Homenet HNA

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
#include "ldns_helpers_test.h"

#include <CUnit/CUnit.h>

#include "../lib/ldns_helpers.h"

void test_ldns_helpers(void) {

ldns_zone* z;
char filename[50]="./dm/fwd.subzone.homenetdns.com.db";
char zone_name[50]="my_subzone.homenetdns.com";

CU_ASSERT(0 == 0);

const ldns_output_format *fmt = NULL;
// fmt = ldns_output_format_bubblebabble;

z=ldns_helpers_load_template(filename);
ldns_rr_print_fmt(stderr, fmt, ldns_zone_soa(z));

//ldns_helpers_fill_template(z,zone_name);
//ldns_rr_print_fmt(stderr, fmt, ldns_zone_soa(z));
//ldns_rr_list_print_fmt(stdout, fmt, ldns_zone_rrs(z));



}
