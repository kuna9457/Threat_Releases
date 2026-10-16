Steps:

1. Bump the version in Threat_Backend/version.ini:
[Settings]
Version=1.0.5
   (Whatever's next after your current 1.0.4.)
2. Rebuild the executables:
cd "C:\Users\kunal\Desktop\Threat Platform - Copy\Threat_Backend"
pyinstaller ThreatScanner.spec --clean
   This regenerates dist\ThreatScanner\ThreatScanner.exe and ThreatScanner_CLI.exe with the new version baked in (via version.ini).
3. Rebuild the installer with Inno Setup (compiles Installer\ThreatScanner.iss, which reads the version straight out of version.ini):
   - Open Installer\ThreatScanner.iss in Inno Setup Compiler and hit Compile, or from the command line:
"C:\Users\kunal\AppData\Local\Programs\Inno Setup 6\ISCC.exe" "C:\Users\kunal\Desktop\Threat Platform - Copy\Installer\ThreatScanner.iss"
   - Output: Installer\ThreatScanner_Setup.exe.
4. Commit and push the source changes to Threat_Backend:
git add -A
git commit -m "Bump version to 1.0.7"
git push origin main
5. Publish the release on the Threat_Releases repo (this is the repo the app actually checks — not Threat_Backend):
   - Go to https://github.com/kuna9457/Threat_Releases/releases/new
   - Tag: v1.0.5 (must be parseable — updater.py strips a leading v and compares dotted version tuples)
   - Upload Installer\ThreatScanner_Setup.exe as a release asset — the filename must stay exactly ThreatScanner_Setup.exe, since updater.py's ASSET_NAME matches on that literal name.
   - Publish.