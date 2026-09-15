# Third-party notices

This project includes code adapted from third-party work. The notices below are
reproduced as those licenses require. They also appear in the header of the
source file that carries the adapted code, because that file is redistributed
on its own inside the generated `iApp/MIDEYE_SHIELD.tmpl`, away from this
repository.

## JA4 (TLS client fingerprinting) — BSD 3-Clause

Used by `iRules/MIDEYE_SHIELD_TRAFFIC.tcl`, whose ClientHello byte parsing is
adapted from [`f5devcentral/f5-ja4`](https://github.com/f5devcentral/f5-ja4)
(`ja4.irule`). The JA4 specification and reference implementation are by
[FoxIO](https://github.com/FoxIO-LLC/ja4).

Only **JA4** is used. The JA4+ variants (JA4H, JA4S, JA4L, JA4T and the rest)
are covered by the separate FoxIO License 1.1 and are deliberately not
implemented here.

```
Copyright (c) 2024, FoxIO
All rights reserved.
Software: JA4 (TLS client fingerprinting)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of FoxIO nor the names of its contributors may be used to
  endorse or promote products derived from this software without specific
  prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## JA3 — no third-party code

JA3 is [Salesforce's published method](https://github.com/salesforce/ja3). It is
implemented here from the specification rather than adapted from their code, so
no Salesforce source is included and no notice is required. The attribution is
recorded because the method is theirs.
