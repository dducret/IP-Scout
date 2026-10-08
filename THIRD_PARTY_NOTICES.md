# Third-party notices

The bundled `assets/oui.csv`, `assets/mam.csv`, and `assets/oui36.csv` manufacturer registries are published by the IEEE
Registration Authority. It is separate from the MIT-licensed application source.

Source: https://standards-oui.ieee.org/oui/oui.csv
Source: https://standards-oui.ieee.org/oui28/mam.csv
Source: https://standards-oui.ieee.org/oui36/oui36.csv

Snapshot downloaded: 2026-10-05.

The registries are used for offline mapping of globally assigned 24-, 28- and 36-bit MAC address
prefixes to registered organization names. It does not identify the maker of
randomized or locally administered addresses.

The application uses eframe/egui, egui_extras, egui-phosphor, Hickory DNS, serde,
csv, rfd, windows-sys, Tokio, tokio-util, futures-util, reqwest, netbios-parser,
rustls, mdns-sd, quick-xml, socket2, uuid, and their transitive dependencies. Their respective license
metadata is available in Cargo's registry source and `Cargo.lock` identifies the
versions used. Phosphor Icons are MIT licensed.

reqwest and netbios-parser are licensed under MIT OR Apache-2.0. rustls is
licensed under Apache-2.0 OR ISC OR MIT. IP Scout's own source remains MIT.
snmp2, sntpc and sntpc-net-tokio are licensed under MIT OR Apache-2.0.
quick-xml is MIT licensed; mdns-sd, socket2 and uuid are MIT OR Apache-2.0.
Hickory DNS is MIT OR Apache-2.0.

Inventory additionally uses tokio-rustls (MIT OR Apache-2.0), x509-parser
(MIT OR Apache-2.0), and scraper (ISC). rcgen is used only by tests, not the
released application. IP Scout's application license remains MIT.

## scraper ISC notice

Copyright © 2016, June McEnroe <june@causal.agency>
Copyright © 2017, Vivek Kushwaha <yoursvivek@gmail.com>
Copyright © 2024-2025, rust-scraper Contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

## x509-parser MIT notice

Copyright (c) 2017 Pierre Chifflier

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

## UDP protocol libraries MIT notices

snmp2: Copyright 2016 Hroi Sigurdsson

snmp2: Copyright 2024 Serhij Symonenko, Bohemia Automation Limited

sntpc and sntpc-net-tokio: Copyright (c) 2025 Vladimir Petrigo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

IP Scout uses original protocol code and the libraries listed above;
the application source remains MIT. No external packet-capture driver is needed.

IP Scout is not affiliated with or endorsed by Angry IP Scanner.

