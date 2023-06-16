import argparse
import binascii
import sys
import os

magic_bytes = {'3c 3c 3c 20 4f 72 61 63 6c 65 20 56 4d 20 56 69 72 74 75 61 6c 42 6f 78 20 44 69 73 6b 20 49 6d 61 67 65 20 3e 3e 3e': 'Oracle VM Virtual Disk Image .vdi',
               '4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 53 6f 6c 75 74 69 6f 6e 20 46 69 6c 65': 'SLN File .sln',
               '2d 2d 2d 2d 2d 42 45 47 49 4e 20 4f 50 45 4e 53 53 48 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d': 'OPENSSH Private Key',
               '2d 2d 2d 2d 2d 42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45 20 52 45 51 55 45 53 54 2d 2d 2d 2d 2d': '.csr .pem',
               '2d 2d 2d 2d 2d 42 45 47 49 4e 20 44 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d': 'DSA Private Key .key .pem',
               '2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 45 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d': 'RSA Private Key .key .pem',
               '53 49 4d 50 4c 45 20 20 3d 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54': 'Flexible Image Transport System .fits',
               '23 20 4d 69 63 72 6f 73 6f 66 74 20 44 65 76 65 6c 6f 70 65 72 20 53 74 75 64 69 6f': 'Microsoft Developer Studio project file .dsp',
               '2d 2d 2d 2d 2d 42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d 2d': 'Certificate File .cert .pem',
               '2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d': 'Private Key .key .pem',
               '2d 2d 2d 2d 2d 42 45 47 49 4e 20 53 53 48 32 20 4b 45 59 2d 2d 2d 2d 2d': 'SSH2 Public Key .pub',
               '3c 00 00 00 3f 00 00 00 78 00 00 00 6d 00 00 00 6c 00 00 00 20 00 00 00': 'eXtensible Markup Language .xml',
               '00 00 00 3c 00 00 00 3f 00 00 00 78 00 00 00 6d 00 00 00 6c 00 00 00 20': 'eXtensible Markup Language .xml',
               '25 21 50 53 2d 41 64 6f 62 65 2d 33 2e 30 20 45 50 53 46 2d 33 20 30': 'EPS File .eps',
               '25 21 50 53 2d 41 64 6f 62 65 2d 33 2e 30 20 45 50 53 46 2d 33 2e 30': 'Encapsulated PostScript file version 3_0 .eps .epsf',
               '25 21 50 53 2d 41 64 6f 62 65 2d 33 2e 31 20 45 50 53 46 2d 33 2e 30': 'Encapsulated PostScript file version 3_1 .eps .epsf',
               '00 00 00 20 66 74 79 70 69 73 6f 6d 00 00 02 00 69 73 6f 6d 69 73 6f': 'MP4 Video File.mp4',
               '50 75 54 54 59 2d 55 73 65 72 2d 4b 65 79 2d 46 69 6c 65 2d 32 3a': 'PuTTY-User-Key-File-2 .ppk',
               '50 75 54 54 59 2d 55 73 65 72 2d 4b 65 79 2d 46 69 6c 65 2d 33 3a': 'PuTTY-User-Key-File-3 .ppk',
               '05 07 00 00 42 4f 42 4f 05 07 00 00 00 00 00 00 00 00 00 00 00 01': 'AppleWorks 5 document .cwk',
               '06 07 e1 00 42 4f 42 4f 06 07 e1 00 00 00 00 00 00 00 00 00 00 01': 'AppleWorks 6 document .cwk',
               '43 72 65 61 74 69 76 65 20 56 6f 69 63 65 20 46 69 6c 65 1a 1a 00': 'Creative Voice file .voc',
               '43 36 34 20 74 61 70 65 20 69 6d 61 67 65 20 66 69 6c 65': 'Commodore 64 tape image .t64',
               '00 01 00 00 4d 53 49 53 41 4d 20 44 61 74 61 62 61 73 65': 'Microsoft Money file .mny',
               '00 01 00 00 53 74 61 6e 64 61 72 64 20 41 43 45 20 44 42': 'Microsoft Access 2007 Database .accdb',
               '00 01 00 00 53 74 61 6e 64 61 72 64 20 4a 65 74 20 44 42': 'Microsoft Access Database .mdb',
               '53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00': 'SQLite Database .sqlite .sqlitedb .db',
               '30 26 b2 75 8e 66 cf 11 a6 d9 00 aa 00 62 ce 6c': 'Advanced Systems Format .asf .wma .wmv',
               '43 36 34 20 43 41 52 54 52 49 44 47 45 20 20 20': 'Commodore 64 cartridge image .crt',
               '23 20 44 69 73 6b 20 44 65 73 63 72 69 70 74 6f': 'VMware 4 Virtual Disk description file (split disk) .vmdk',
               '62 6f 6f 6b 00 00 00 00 6d 61 72 6b 00 00 00 00': 'macOS file Alias (Symbolic link) .alias',
               '06 06 ed f5 d8 1d 46 e5 bd 31 ef e7 fe 74 b7 1d': 'Adobe InDesign document .indd',
               '0a 16 6f 72 67 2e 62 69 74 63 6f 69 6e 2e 70 72': 'MultiBit Bitcoin wallet file .wallet',
               '37 48 03 02 00 00 00 00 58 35 30 39 4b 45 59': 'KDB file .kdb',
               '5b 5a 6f 6e 65 54 72 61 6e 73 66 65 72 5d': 'Microsoft Zone Identifier for URL Security Zones .identifier',
               '06 0e 2b 34 02 05 01 01 0d 01 02 01 01 02': 'Material Exchange Format file .mxf',
               '4d 53 57 49 4d 00 00 00 d0 00 00 00 00': 'Windows Imaging Format file .wim .swm .esd',
               '66 74 79 70 68 65 69 666 74 79 70 6d': 'High Efficiency Image Container (HEIC) .heic',
               '00 00 00 18 66 74 79 70 6d 70 34 32': 'Mpeg 4 video file .mp4',
               '53 74 61 6e 64 61 72 64 20 4a 65 74': 'Microsoft Database .mdb',
               '49 54 53 46 03 00 00 00 60 00 00 00': '    MS Windows HtmlHelp Data .chm',
               '42 41 43 4b 4d 49 4b 45 44 49 53 4b': 'AmiBack Amiga Backup data file .bac',
               '20 02 01 62 a0 1e ab 07 02 00 00 00': 'Tableau Datasource .tde',
               '00 00 00 0c 4a 58 4c 20 0d 0a 87 0a': 'Image encoded in the JPEG XL format .jxl',
               '3c 00 3f 00 78 00 6d 00 6c 00 20': 'eXtensible Markup Language .xml',
               '23 3f 52 41 44 49 41 4e 43 45 0a': 'Radiance High Dynamic Range image file .hdr',
               '67 69 6d 70 20 78 63 66 20 76': 'XCF Gimp file structure .xcf',
               '00 00 00 0c 6a 50 20 20 0d 0a': 'JPEG 2000 graphic file    .jp2',
               '50 4b 03 04 14 00 08 00 08 00': 'Jar File .jar',
               '49 49 2a 00 10 00 00 00 43 52': 'Canon RAW Format Version 2 Based On TIFF .cr2',
               '63 6f 6e 6e 65 63 74 69 78': 'Virtual Hard Drive File .vhd',
               '2f 2a 20 58 50 4d 20 2a 2f': 'XPM format .xpm',
               '52 65 63 65 69 76 65 64 3a': 'Email Message var5 .eml',
               '0f 53 49 42 45 4c 49 55 53': 'Sibelius Music - Score file .sib',
               '07 64 74 32 64 64 74 64': 'DesignTools 2D Design file: dtd',
               '66 74 79 70 4d 34 56 20': 'ISO Media, MPEG v4 system, or iTunes AVC-LC file .flv .m4v',
               '66 74 79 70 69 73 6f 6d': 'ISO Base Media file (MPEG-4) v1 .mp4',
               '66 74 79 70 4d 34 41 20': 'Apple Lossless Audio Codec file .m4a',
               '66 4c 61 43 00 00 00 22': 'Free Lossless Audio Codec file .flac',
               'd0 cf 11 e0 a1 b1 1a e1': '.doc .xls .ppt .msi .msg',
               '66 74 79 70 4d 53 4e 56': 'MPEG-4 video file .mp4',
               '50 4b 03 04 14 00 06 00': '.docx .pptx .xlsx',
               '76 68 64 78 66 69 6c 65': '.vhdx',
               '52 61 72 21 1a 07 01 00': 'Roshal ARchive compressed archive v5.00 onwards RAR File .rar',
               '09 08 10 00 00 06 05 00': '.xls',
               '21 3c 61 72 63 68 3e 0a': 'Linux deb file .deb',
               '47 53 52 2d 31 35 34 31': 'Commodore 64 1541 disk image (G64 format) .g64',
               '64 65 78 0a 30 33 35 00': 'Dalvik Executable .dex',
               '50 4d 4f 43 43 4d 4f 43': 'Windows Files And Settings Transfer Repository .dat',
               '24 53 44 49 30 30 30 31': 'System Deployment Image, a disk image format used by Microsoft .',
               '75 73 74 61 72 00 30 30': 'tar archive .tar',
               '75 73 74 61 72 20 20 00': 'tar archive .tar',
               '53 5a 44 44 88 f0 27 33': 'Microsoft compressed file in Quantum format, used prior to Windows XP File can be decompressed using Extract_exe or Expand_exe distributed with earlier versions of Windows After compression, the last character of the original filename extension is replaced with an underscore, eg ‘Setup_exe’ becomes ‘Setup_ex_’',
               '52 53 56 4b 44 41 54 41': 'QuickZip rs compressed archive .rs',
               '23 25 4d 6f 64 75 6c 65': 'Modulefile for Environment Modules',
               '21 2d 31 53 4c 4f 42 1f': 'Slob (sorted list of blobs) is a read-only, compressed data store with dictionary-like interface .slob',
               '48 5a 4c 52 00 00 00 18': 'Noodlesoft Hazel .hazelrules',
               '03 00 00 00 41 50 50 52': 'Approach index file .adx',
               '0e 4e 65 72 6f 49 53 4f': 'Nero CD Compilation .nri',
               '45 6c 66 46 69 6c 65': 'Windows Event Viewer XML file format .evtx',
               '52 61 72 21 1a 07 00': 'Roshal ARchive compressed archive v1.50 onwards RAR file .rar',
               '30 26 b2 75 8e 66 cf': 'Windows Video file .wmv or Windows Audio file .wma',
               '6d 61 69 6e 2e 62 73': 'Nintendo Game & Watch image file .mgw',
               '8b 45 52 02 00 00 00': 'Roxio Toast disc image file .toast',
               '2a 2a 41 43 45 2a 2a': 'ACE (compressed file format) .ace',
               '42 4c 45 4e 44 45 52': 'Blender File Format .blend',
               '52 4b 4d 43 32 31 30': 'Vormetric Encryption DPM Version 2.1 Header',
               '23 21 53 49 4c 4b 0a': 'Audio compression format developed by Skype .sil',
               '23 45 58 54 4d 33 55': 'Multimedia playlist .m3u .m3u8',
               '57 69 6e 5a 69 70': 'WinZip compressed archive .zip',
               '53 49 4d 50 4c 45': 'FITS format .fits',
               '37 7a bc af 27 1c': '7-Zip Archive .7z',
               'fd 37 7a 58 5a 00': 'XZ compression utility using LZMA2 compression .xz .tar.xz',
               '3c 3f 78 6d 6c 20': 'eXtensible Markup Language .xml',
               '7b 5c 72 74 66 31': 'RTF Document .rtf',
               '30 37 30 37 30 37': 'cpio archive file .cpio',
               'a0 32 41 a0 a0 a0': 'Commodore 64 1541 disk image (D64 format) .d64',
               '45 52 02 00 00 00': 'Roxio Toast disc image file .toast',
               '4c 6f a7 94 93 40': 'WebAssembly binary format .wasm',
               '66 74 79 70 33 67': '3rd Generation Partnership Project 3GPP and 3GPP2 multimedia files .3gp .3g2',
               '62 70 6c 69 73 74': 'Binary Property List file .plist',
               '01 ff 02 04 03 02': 'Micrografx vector graphic file .drw',
               '75 73 74 61 72': 'TAR (POSIX) .tar',
               '25 50 44 46 2d': 'PDF .pdf or Adobe Illustrator file .ai',
               '43 44 30 30 31': '.iso',
               '44 52 41 43 4f': '3D model compressed with Google Draco .drc',
               '21 42 44 4e 42': 'Outlook Post Office file .pst',
               'a0 33 44 a0 a0': ' Commodore 64 1581 disk image (D81 format) .d81',
               '2d 68 6c 30 2d': 'Lempel Ziv Huffman archive file Method 0 (No compression) .lzh',
               '2d 68 6c 35 2d': 'Lempel Ziv Huffman archive file Method 5 (8KiB sliding window) .lzh',
               '00 01 00 00 00': 'TrueType font .ttf. tte .dfont',
               '23 21 41 4d 52': 'Adaptive Multi-Rate ACELP (Algebraic Code Excited Linear Prediction) Codec, commonly audio format with GSM cell phones .amr',
               '4d 49 4c 20': '"SEAN : Session Analysis" Training file .stg',
               '00 00 01 ba': 'MPG, VOB DVD Video Movie File (video/dvd, video/mpeg) or DVD MPEG2 .m2p .vob .mpg .mpeg',
               'ff d8 ff e0': 'JPEG File Interchange Format .jpg .jpeg .jfif',
               'ff d8 ff e1': 'JPEG File Interchange Format .jpg .jpeg .jfif',
               'ff d8 ff ee': 'JPEG File Interchange Format .jpg .jpeg .jfif',
               'ff d8 ff db': 'JPEG File Interchange Format .jpg .jpeg .jfif',
               'ed ab ee db': 'RedHat Package Manager (RPM) package .rpm',
               '4d 4d 00 2a': 'TIFF format (Motorola - big endian) .tif',
               '49 49 2a 00': 'TIFF format (Intel - little endian) .tif',
               'd4 c3 b2 a1': 'Libpcap File Format little-endian .pcap',
               '4d 3c b2 a1': 'Libpcap File Format little-endian .pcap',
               'a1 b2 c3 d4': 'Libpcap File Format big-endian .pcap',
               'a1 b2 3c 4d': 'Libpcap File Format big-endian .pcap',
               '50 4b 03 04': 'pkzip format .zip',
               '47 4b 53 4d': 'Graphics Kernel System .gks',
               'f1 00 40 bb': 'ITC (CMU WM) format .itc',
               '49 49 4e 31': 'NIFF (Navy TIFF) .nif',
               '59 a6 6a 95': 'Sun Rasterfile .ras',
               '50 4b 05 06': 'pkzip format .zip',
               '50 4B 07 08': 'pkzip format .zip',
               '23 46 49 47': 'Xfig format .fig',
               '47 49 46 38': 'GIF format .gif',
               '89 50 4e 47': 'PNG format .png',
               '56 49 45 57': 'PM format .pm',
               '47 52 49 42': 'Gridded data (commonly weather observations or forecasts) in the WMO GRIB or GRIB2 format .grib .grib2',
               '00 00 01 b3': 'MPEG-1 video and MPEG-2 video (MPEG-1 Part 2 and MPEG-2 Part 2) .mpg .mpeg',
               '7f 45 4c 46': 'Unix elf',
               '77 4f 46 32': 'WOFF File Format 2.0 .woff2',
               '77 4f 46 46': 'WOFF File Format 1.0 .woff',
               '00 61 73 6d': '.wasm',
               '38 42 50 53': 'Photoshop Graphics .psd',
               'ec a5 c1 00': '.doc',
               '78 61 72 21': 'eXtensible ARchive format .xar',
               '6b 6f 6c 79': 'Apple Disk Image file .dmg',
               '44 49 43 4d': 'DICOM Medical File Format .dcm',
               '21 42 44 4e': 'Microsoft Outlook Personal Folder File .pst',
               '73 64 62 66': 'Windows customized database .sdb',
               '4c 66 4c 65': 'Windows Event Viewer file format .evt',
               '49 73 5a 21': 'Compressed ISO image .isz',
               '50 4d 43 43': 'Windows 3x Program Manager Program Group file format .grp',
               '4b 43 4d 53': 'ICC profile .icm',
               '6d 6f 6f 76': 'MOV video file .mov',
               '52 49 46 46': 'AVI video file .avi or WAV audio file .wav',
               '00 00 01 00': 'Icon file .ico',
               'ca fe ba be': 'Class File .class',
               'ff 4f ff 51': 'JPEG 2000 graphic file  .jp2',
               'd7 cd c6 9a': 'Windows Meta File .wmf',
               '4d 54 68 64': 'MIDI file .mid .midi',
               '4d 53 43 46': 'CAB Installer file .cab',
               '3f 5f 03 00': 'Help file .hlp',
               '4b 44 4d 56': 'VMWare Disk file .vmdk',
               '69 63 6e 73': 'Apple Icon Image format .icns',
               '4c 5a 49 50': 'lzip compressed file .lz',
               '4f 67 67 53': 'Ogg, an open source media container format .ogg .oga .ogv',
               '43 72 32 34': 'Google Chrome extension or packaged app .crx',
               '41 47 44 33': 'FreeHand 8 document .fh8',
               '4e 45 53 1a': 'Nintendo Entertainment System ROM file .nes',
               '74 6f 78 33': 'Open source portable voxel file .tox',
               '4d 4c 56 49': 'Magic Lantern Video file .mlv',
               '46 4c 49 46': 'Free Lossless Image Format .flif',
               '1a 45 df a3': 'Matroska media container, including .WebM .mkv .mka .mks .mk3d .webm',
               '27 05 19 56': 'U-Boot / uImage Das U-Boot Universal Boot Loader .',
               '54 41 50 45': 'Microsoft Tape Format .',
               '50 57 53 33': 'Password Gorilla Password Database .psafe3',
               '53 50 30 31': 'Amazon Kindle Update Package .bin',
               '49 57 41 44': 'internal WAD (main resource file of Doom) .wad',
               'be ba fe ca': 'Palm Desktop Calendar Archive .dba',
               '00 01 42 44': 'Palm Desktop To Do Archive .dba',
               '00 01 44 54': 'Palm Desktop Calendar Archive .tda',
               '54 44 46 24': 'Telegram Desktop File .tds$',
               '54 44 45 46': 'Telegram Desktop Encrypted File .tdef',
               '49 4e 44 58': 'AmiBack Amiga Backup index file .idx',
               '80 2a 5f d7': 'Kodak Cineon image .cin',
               '53 44 50 58': 'SMPTE DPX image (big-endian format) .dpx',
               '58 50 44 53': 'SMPTE DPX image (little-endian format) .dpx',
               '76 2f 31 01': 'OpenEXR image .exr',
               '42 50 47 fb': 'Better Portable Graphics format .bpg',
               '71 6f 69 66': 'QOI - The Quite OK Image Format .qoi',
               '25 21 50 53': 'PostScript document .ps',
               '62 76 78 32': 'LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding OSS by Apple .lzfse',
               '4f 62 6a 01': 'Apache Avro binary file format .avro',
               '53 45 51 36': 'RCFile columnar file format .rc',
               '65 87 78 56': 'PhotoCap Object Templates .p25 .obt',
               '55 55 aa aa': 'PhotoCap Vector .pcv',
               '50 41 52 31': 'Apache Parquet columnar file format',
               '45 4d 58 32': 'Emulator Emaxsynth samples .ez2',
               '45 4d 55 33': 'Emulator III synth samples .ez3 .iso',
               '1b 4c 75 61': 'Lua bytecode .luac',
               '28 b5 2f fd': '    Zstandard compress .zst',
               '4a 6f 79 21': 'Preferred Executable Format .',
               '31 0a 30 30': 'SubRip File .srt',
               '34 12 aa 55': 'VPK file, used to store game data for some Source Engine games .vpk',
               '49 53 63 28': 'InstallShield CAB Archive File .cab',
               '4b 57 41 4a': 'Windows 3_1x Compressed File',
               '53 5a 44 44': 'Windows 9x Compressed File',
               '45 56 46 32': 'EnCase EWF version 2 format .ex01',
               '72 65 67 66': 'Windows Registry file .dat .hiv',
               '4f 54 54 4f': 'OpenType font .otf',
               '2e 73 6e 64': 'Au audio file format .au .snd',
               'db 0a ce 00': 'OpenGL Iris Perfomer (Performer Fast Binary) .pfb',
               '46 4c 68 64': 'FL Studio Project File .flp',
               '31 30 4c 46': 'FL Studio Mobile Project File .flm',
               '02 64 73 73': 'Digital Speech Standard (Olympus, Grundig, & Phillips) v2 .dss',
               '03 64 73 73': 'Digital Speech Standard (Olympus, Grundig, & Phillips) v3 .dss',
               '07 53 4b 46': 'SkinCrafter skin file .skf',
               '0d 44 4f 43': 'DeskMate Document file .doc',
               '0e 57 4b 53': 'DeskMate Worksheet .wks',
               '23 40 7e 5e': 'VBScript Encoded script .vbe',
               '0d f0 1d c0': 'MikroTik WinBox Connection Database (Address Book) .cdb',
               '6d 64 66 00': 'M2 Archive, used by game developer M2 .m',
               '4b 50 4B 41': 'Capcom RE Engine game data archives .pak',
               'd0 4f 50 53': 'Interleaf PrinterLeaf / WorldView document format (now Broadvision QuickSilver) .pl',
               '4b 44 4d': 'VMDK files .vdmk',
               '49 44 33': 'MP3 file with ID3 identity tag .mp3',
               '43 57 53': 'Adobe Flash .swf',
               '46 57 53': 'Flash Shockwave .swf',
               '46 4c 56': 'Flash Video .flv',
               '44 41 41': 'Direct Access Archive PowerISO .daa',
               '1f 8b 08': 'gzip format .gz .tar.gz',
               '4e 45 53': 'Nintendo Entertainment System image file .nes',
               'cf 84 01': 'Lepton compressed JPEG image .lep',
               '42 5a 68': 'Compressed file using Bzip2 algorithm .bz2',
               '4f 41 52': 'OAR file archive format, where the next byte after magic is the format version .oar',
               '4f 52 43': 'Apache ORC (Optimized Row Columnar) file format .orc',
               '78 56 34': 'PhotoCap Template .pbt .pdt .pea .peb .pet .pgt .pict .pjt .pkt .pmt',
               '3a 29 0a': 'Smile file .sml',
               '5a 4f 4f': 'Zoo (file format) .zoo',
               '50 31 0a': 'Portable bitmap ASCII .pbm',
               '50 34 0a': 'Portable bitmap binary .pbm',
               '50 32 0a': 'Portable Gray Map ASCII .pgm',
               '50 35 0a': 'Portable Gray Map binary .pgm',
               '50 33 0a': 'Portable Pixmap ASCII .ppm',
               '50 36 0a': 'Portable Pixmap binary .ppm',
               '41 46 46': 'Advanced Forensics Format .aff',
               '45 56 46': 'EnCase EWF version 1 format e01',
               '51 46 49': 'qcow file format .qcow',
               '41 52 43': 'Capcom MT Framework game data archives .arc',
               '60 ea' : 'ARJ file .ajr',
               '42 4d': 'Bitmap format .bmp .dib',
               '58 2d': 'A commmon file extension for e-mail files. This variant is for Exchange .eml',
               '4d 5a': 'MS-DOS, OS/2 or MS Windows .exe .dll .sys',
               '25 21': 'Postscript format .[e]ps',
               '01 da': 'IRIS rgb format .rgb',
               '1f 9d': 'compressed file (often tar zip) using Lempel-Ziv-Welch algorithm .z .tar.z',
               '42 5a': 'Bzip .bz',
               '5a 4d': '.exe',
               '49 49': 'TIF graphic file .tif',
               '4c 01': 'Object Code File .obj',
               '78 9c': 'Zlib File .zlib or SDF File .sdf',
               '1f a0': 'Compressed file (often tar zip) using LZH algorithm .z .tar.z',
               '78 01': 'zlib No Compression (no preset dictionary) .zlib',
               '78 5e': 'zlib Best speed (no preset dictionary) .zlib',
               '78 9c': 'zlib Default Compression (no preset dictionary) .zlib',
               '78 da': 'zlib Best Compression (no preset dictionary) .zlib',
               '78 20': 'zlib No Compression (with preset dictionary) .zlib',
               '78 7d': 'zlib Best speed (with preset dictionary) .zlib',
               '78 bb': 'zlib Default Compression (with preset dictionary) .zlib',
               '78 f9': 'zlib Best Compression (with preset dictionary) .zlib',
               'ac ed': 'Serialized Java Data .',
               'c9': '.com',
               '47': 'MPEG Transport Stream (MPEG-2 Part 1) .ts .tsv .tsa .mpg .mpeg'

               }

end_bytes = {'ff d8 ff e0': 'ff d9', #jpg
             'ff d8 ff ee': 'ff d9', #jpg
             'ff d8 ff db': 'ff d9', #jpg
             'ff d8 ff e1': 'ff d9', #jpg
             '47 49 46 38': '00 3b', #gif
             '89 50 4e 47': '49 45 4e 44 ae 42 60 82', # png
             '50 4b 03 04 14 00 06 00': '50 4b 05 06', # docx pptx xlsx + 18 bytes or 36 hex chars + 18 spaces
             '00 00 00 20 66 74 79 70 69 73 6f 6d 00 00 02 00 69 73 6f 6d 69 73 6f': '4c 61 76 66', # mp4 file + 27
             '49 49': '48 00 00 00 01 00 00 00 48 00 00 00 01', # .tif
             '49 49 2a 00': '48 00 00 00 01 00 00 00 48 00 00 00 01', # .tif
             '4d 4d 00 2a': '48 00 00 00 01 00 00 00 48 00 00 00 01', # .tif

            }

def decode_suspicious_data(after_eof_data):
    split_data = after_eof_data.split(' ')
    outstr = ''
    for hex_byte in split_data:
        try:
            outstr += binascii.unhexlify(hex_byte).decode()
        except UnicodeDecodeError as e:
            pass

    with open('{}.suspiciousdata'.format(options.file), 'w') as f:
        f.write(outstr)
        f.close()

    print('Data after EOF marker was written to {}.suspiciousdata'.format(options.file))

if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True, description='')
    parser.add_argument('file', action='store', help='File to inspect')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if os.path.isfile(options.file) == False:
        print('Error: thats not a file')
        sys.exit(1)

    with open(options.file, 'rb') as f:
        file_bytes = f.read()
        f.close()

    hex_data = binascii.hexlify(file_bytes)
    hex_data = hex_data.decode()
    hex_data = ' '.join(hex_data[i:i + 2] for i in range(0, len(hex_data), 2))

    magic_arr = magic_bytes.keys()
    found = False
    for mgk in magic_arr:
        if hex_data.startswith(mgk.lower()):
            found = True
            print('Magic Bytes: {}'.format(mgk.lower()))
            print('Filetype: {}'.format(magic_bytes[mgk][:magic_bytes[mgk].find('.')]))
            print('Extensions: {}'.format(magic_bytes[mgk][magic_bytes[mgk].find('.'):]))
            try:
                endmagic = end_bytes[mgk].lower()
                print('End of File Bytes: {}'.format(endmagic))
                if endmagic == '50 4b 05 06': # This is for docx xlsx pptx files
                    if hex_data.find(endmagic)+len(endmagic)+54 != len(hex_data): # docx xlsx pptx is the endbytes + 18 bytes so 36 chars and 18 spaces = 54 chars total
                        print("WARNING: There is data after the end of file bytes")
                        decode_suspicious_data(hex_data[hex_data.find(endmagic)+len(endmagic)+54+1:])

                elif endmagic == '4c 61 76 66': # mp4 files
                    if hex_data.find(endmagic)+len(endmagic)+27 != len(hex_data): # mp4 is the endbytes + 9 bytes so 18 chars  and 9 spaces = 27 chars
                        print("WARNING: There is data after the end of file bytes")
                        decode_suspicious_data(hex_data[hex_data.find(endmagic)+len(endmagic)+27+1:])

                elif hex_data.find(endmagic)+len(endmagic) != len(hex_data):
                    print("WARNING: There is data after the end of file bytes")
                    decode_suspicious_data(hex_data[hex_data.find(endmagic)+len(endmagic)+1:])

                sys.exit(0)
            except KeyError as e:
                print('End of file bytes not in database')
                sys.exit(1)

            print('\n')

    if found == False:
        print('Error: No direct matches')

    sys.exit(0)
