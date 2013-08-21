.DEFAULT: .witness-build
manifest: .witness-manifest
sign: .witness-sign

.witness-build : trimcheck.d
	rdmd --force --build-only -version=WindowsXP -version=Unicode trimcheck.d
	@touch .witness-build

.witness-manifest : .witness-build trimcheck.manifest
	mt -manifest trimcheck.manifest -outputresource:trimcheck.exe
	@touch .witness-manifest

.witness-sign : .witness-manifest
	signtool sign /a /d "TrimCheck" /du "https://github.com/CyberShadow/trimcheck" /t http://time.certum.pl/ trimcheck.exe
	@touch .witness-sign
