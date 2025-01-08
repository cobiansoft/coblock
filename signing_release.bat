signtool.exe sign /n "Luis Cobian" /t http://time.certum.pl /fd SHA256 ".\_BIN\Release\net8.0\publish\aot\win-x64\coblock.exe"
signtool.exe sign /n "Luis Cobian" /t http://time.certum.pl /fd SHA256 ".\_BIN\Release\net8.0\publish\aot\win-x86\coblock.exe"


ECHO DONE! Press any key...
pause >nul