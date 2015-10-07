.DEFAULT: trimcheck.exe          trimcheck64.exe
manifest: trimcheck-manifest.exe trimcheck64-manifest.exe
sign    : trimcheck-signed.exe   trimcheck64-signed.exe


trimcheck.exe : trimcheck.d
	rdmd --force --build-only -version=WindowsXP -version=Unicode trimcheck.d

trimcheck-manifest.exe : trimcheck.exe trimcheck.manifest
	cp -f trimcheck.exe trimcheck-tmp.exe
	mt -manifest trimcheck.manifest -outputresource:trimcheck-tmp.exe
	mv -f trimcheck-tmp.exe trimcheck-manifest.exe

trimcheck-signed.exe : trimcheck-manifest.exe
	cp -f trimcheck-manifest.exe trimcheck-tmp.exe
	signtool sign /a /n "Vladimir Panteleev" /d "TrimCheck" /du "https://github.com/CyberShadow/trimcheck" /t http://time.certum.pl/ trimcheck-tmp.exe
	mv -f trimcheck-tmp.exe trimcheck-signed.exe


trimcheck64.exe : trimcheck.d
	rdmd --force --build-only -version=WindowsXP -version=Unicode -m64 -oftrimcheck64.exe trimcheck.d

trimcheck64-manifest.exe : trimcheck64.exe trimcheck.manifest
	cp -f trimcheck64.exe trimcheck64-tmp.exe
	mt -manifest trimcheck.manifest -outputresource:trimcheck64-tmp.exe
	mv -f trimcheck64-tmp.exe trimcheck64-manifest.exe

trimcheck64-signed.exe : trimcheck64-manifest.exe
	cp -f trimcheck64-manifest.exe trimcheck64-tmp.exe
	signtool sign /a /n "Vladimir Panteleev" /d "TrimCheck" /du "https://github.com/CyberShadow/trimcheck" /t http://time.certum.pl/ trimcheck64-tmp.exe
	mv -f trimcheck64-tmp.exe trimcheck64-signed.exe
