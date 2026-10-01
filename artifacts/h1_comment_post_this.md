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
Following the informative, no-CVE disposition: we agree with the outcome and are not requesting a reopen or a CVE. The trigger is the application's own code (the getinfo → setopt pointer round-trip), so the most a remote party can do is be the recipient of a few leaked bytes.

Three points on the evidence notes:

- **ASan failures** — those came from our Termux/proot environment, where ASan cannot map its shadow memory (documented in our own UBUNTU.md / preflight); all conclusive ASan runs came from a native Ubuntu sandbox. That is an environment fact, not a defect in the findings.
- **Three runs with different leaked bytes** — that is the reproducibility result itself: the free-then-read mechanism is deterministic, while the recycled bytes are ASLR-varied by construction (heap-pointer fragments ending in the tcache size-class byte). Same signature every run, different values — we never read that as weakening the finding.
- **Re-verification as requested** — when output from an environment other than the native Linux sandbox was requested, we re-ran the PoC in a cloud Linux terminal: same vulnerable commit, same free-then-read signature, and still clean on the fixed commit (logged in our knowledge record, knowledge/curl-referer-uaf.json).

The one fact worth keeping for packagers: regression window `ff300ac4aa` (2026-06-01) → `d0247689` (2026-08-27); **8.21.0 (2026-06-23) is the only tagged release that ever shipped it**, and the fix first shipped in **8.22.0**.

Happy for the report to stay informative — thanks for the clear triage.
<!-- END-CUT -->
