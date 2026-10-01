<!-- ==================================================================
 WHAT : Komentar final untuk HackerOne report #3971462
        (libcurl CURLOPT_REFERER use-after-free - informative, no CVE)
 HOW  : 1. Buka  https://hackerone.com/reports/3971462
        2. Klik kotak komentar ("Add a comment" / "Leave a comment")
        3. COPY blok di bawah tanda CUT-HERE sampai END-CUT (tanpa tag html)
        4. PASTE ke kotak komentar H1 (editor H1 memakai markdown -
           bold **teks** dan backtick `kode` akan tampil rapi)
        5. Baca ulang sekali, lalu klik "Submit" / "Comment"
 NOTE : Jangan ubah isi komentar - semua klaimnya sudah terverifikasi
        terhadap knowledge/curl-referer-uaf.json (closed 2026-10-01).
=================================================================== -->

<!-- CUT-HERE -->
Thanks — we fully agree with this disposition: informative, no CVE. The trigger is the application's own code (the getinfo → setopt pointer round-trip), so the most a remote party can do is be the recipient of a few leaked bytes, and a CVE "about the past" has declining value — we won't be requesting one or a reopen.

Two quick clarifications on the evidence notes, both consistent with what you said:

- **ASan failures** — correct, those were our Termux/proot environment (ASan cannot map its shadow memory there); all conclusive ASan runs came from a native Ubuntu sandbox.
- **Three runs with different leaked bytes** — that's the reproducibility result itself: the free-then-read mechanism is deterministic, while the recycled bytes are ASLR-varied by construction (heap-pointer fragments ending in the tcache size-class byte). Same signature every run, different values — exactly as expected, and we're not disputing the past-bug framing.

The one fact worth keeping for packagers: regression window `ff300ac4aa` (2026-06-01) → `d0247689` (2026-08-27); **8.21.0 (2026-06-23) is the only tagged release that ever shipped it**, and the fix first shipped in **8.22.0**.

Happy for the report to stay informative — thanks for the clear triage.
<!-- END-CUT -->
