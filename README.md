# PS3xploit-resigner

---

### About it:

A tool to resign PSX/PS2/PS3/PSP content for use with PS3 et'HAN'ol

PKG files are resigned converting from DEBUG to HAN style

---

### Notes

Separate resigning for .ENC/.EDAT/CONFIG is also supported by `ps3xploit_rifgen_edatresign.exe`/`ps3xploit_rifgen_edatresign`

Pre-compiled binary for Windows is found on `source/pre-compiled/windows/ps3xploit_rifgen_edatresign.exe`

Linux package need build from source `cd source/src; make` output is `source/src/ps3xploit_rifgen_edatresign`

---

### Thanks to:

- ***#PS3XploitTeam** for PS3Xploit-Resign*
- ***#PSL1GHTDevelopmentTeam** for pkg.py*
- ***@CaptainCPS-X** for original script to build a pkg*
- ***@aldostools** for PS3 Tools Collection (Specially PKG Creation)*
- ***@Hexcsl** for original compile rifgen and stuff*

---

### Usage:

<table>
  <tr>
    <th>To Resign<br></th>
    <th>Input Files</th>
    <th>Place on</th>
    <th>Ouput</th>
  </tr>
  <tr>
    <td rowspan="3">RAP to RIF<br></td>
    <td>act.dat</td>
    <td>input/act_dat/</td>
    <td rowspan="3">output/rif_pkg/PKG_RIF-INSTALLER.pkg_signed.pkg</td>
  </tr>
  <tr>
    <td>idps.hex</td>
    <td>input/idps_hex/</td>
  </tr>
  <tr>
    <td>.rap</td>
    <td>input/raps/</td>
  </tr>
  <tr>
    <td colspan="4"></td>
  </tr>
  <tr>
    <td>PKG<br></td>
    <td>.pkg</td>
    <td>input/pkgs/</td>
    <td>output/pkgs/</td>
  </tr>
</table>

---

### Run:

*'resign_windows.bat' for Windows OR 'resign_linux.sh' for Linux*
