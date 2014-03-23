.DEFAULT: trimcheck.exe
manifest: trimcheck-manifest.exe
sign    : trimcheck-signed.exe

trimcheck.exe : trimcheck.d
	rdmd --force --build-only -version=WindowsXP -version=Unicode trimcheck.d

trimcheck-manifest.exe : trimcheck.exe trimcheck.manifest
	cp -f trimcheck.exe trimcheck-tmp.exe
	mt -manifest trimcheck.manifest -outputresource:trimcheck-tmp.exe
	mv -f trimcheck-tmp.exe trimcheck-manifest.exe

trimcheck-signed.exe : trimcheck-manifest.exe
	cp -f trimcheck-manifest.exe trimcheck-tmp.exe
	signtool sign /n "Vladimir Panteleev" /d "TrimCheck" /du "https://github.com/CyberShadow/trimcheck" /t http://time.certum.pl/ trimcheck-tmp.exe
	mv -f trimcheck-tmp.exe trimcheck-signed.exe
