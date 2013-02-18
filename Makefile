trimcheck.exe : trimcheck.d trimcheck.manifest
	rdmd --force --build-only -version=WindowsXP -version=Unicode trimcheck.d
	mt -manifest trimcheck.manifest -outputresource:trimcheck.exe
