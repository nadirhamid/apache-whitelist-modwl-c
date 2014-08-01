CPPFLAGS = \
 /DWIN32 \
 /DNDEBUG \
 /I"c:\Program Files\Microsoft Visual Studio 9.0\VC\include" \
 /I"c:\Program Files\Microsoft SDKs\Windows\v6.0A\Include" \
 /I"c:\Program Files\Apache Software Foundation\Apache2.2\include" \
 /I"c:\Program Files\Apache Group\Apache2.2\include" \
 /I"c:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\include" \
 /I"c:\Program Files (x86)\Microsoft SDKs\Windows\v6.0A\Include" \
 /I"c:\Program Files (x86)\Apache Software Foundation\Apache2.2\include" \
 /I"c:\Program Files (x86)\Apache Group\Apache2\include" \
 /I"c:\Program Files (x86)\GnuWin32\include"


CFLAGS = \
 /MD \
 /GF \
 /Gy \
 /O1 \
 /Wall \
 /Zc:wchar_t \
 /w \
 /Zc:forScope

LDFLAGS = \
 /link \
 "/LIBPATH:c:\Program Files\Microsoft Visual Studio 9.0\VC\lib" \
 "/LIBPATH:c:\Program Files\Microsoft SDKs\Windows\v6.0A\Lib" \
 "/LIBPATH:c:\Program Files\Apache Software Foundation\Apache2.2\lib" \
 "/LIBPATH:c:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\lib" \
 "/LIBPATH:c:\Program Files (x86)\Microsoft SDKs\Windows\v6.0A\Lib" \
 "/LIBPATH:c:\Program Files (x86)\Apache Software Foundation\Apache2.2\lib" \
 "/LIBPATH:c:\Program Files (x86)\Apache Group\Apache2.2\lib" \
 "/LIBPATH:c:\Program Files (x86)\Apache Group\Apache2\lib" \
 "/LIBPATH:c:\Program Files (x86)\GnuWin32\lib" \
 /OPT:REF \
 /OPT:ICF=2 \
 /RELEASE \
 /SUBSYSTEM:WINDOWS

LDLIBS = \
 libhttpd.lib \
 libapr.lib \
 ws2_32.lib \
 libaprutil.lib

SRCFILES = mod_wl.n.c

mod_wl.so : $(SRCFILES)
	cl $(CPPFLAGS) $(CFLAGS) $(SRCFILES) /LD $(LDFLAGS) $(LDLIBS) /OUT:$@
clean :
	del *.obj *.so *.lib *.exp
