# Eval_Vulnerability_Detector
Penjelasan Singkat tentang Tools "Eval Vulnerability Detector":

Tools ini dibuat dalam bahasa Golang untuk mendeteksi dan memperbaiki kerentanan pada berbagai jenis file seperti .js, .php, .py, .java, .go, .html, dan .css.
Fitur Utama:

    Deteksi Pola Kerentanan, seperti:

        eval(), setTimeout(), setInterval(), new Function(), dll.

    Auto-Fix (Perbaikan Otomatis) dengan persetujuan pengguna.

    Log File menyimpan hasil before-after setiap perbaikan.

    Colorized Output dengan warna ANSI:

        🔴 Merah: Ada kerentanan ditemukan.

        🔵 Biru: Proses scanning selesai atau tidak ditemukan kerentanan.

        🟢 Hijau: Semua kerentanan diperbaiki.

Cara Kerja:

    Tools akan membaca setiap baris kode, mencocokkan dengan pola kerentanan, dan menampilkan hasilnya.

    Setelah scanning selesai, pengguna dapat memilih Y/N untuk memperbaiki seluruh kerentanan secara otomatis.

    Hasil log dan file perbaikan disimpan ke folder logs/ dan file baru bertanda _fixed.

? Tujuan:
Membantu cyber security enthusiasts mendeteksi dan memperbaiki kerentanan dengan efisien dan transparan. 🚀
