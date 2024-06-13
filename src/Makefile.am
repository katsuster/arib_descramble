
bin_PROGRAMS = arib_descramble

arib_descramble_SOURCES = main.cpp

arib_descramble_CPPFLAGS = $(arib_descramble_common_cppflags) \
	-I$(top_srcdir)/src \
	-I/usr/include/PCSC
arib_descramble_CFLAGS   = $(arib_descramble_common_cflags)
arib_descramble_CXXFLAGS = $(arib_descramble_common_cxxflags)
arib_descramble_LDFLAGS  = $(arib_descramble_common_ldflags) \
	-L$(top_srcdir)/src
arib_descramble_LDADD = $(arib_descramble_common_ldadd) \
	-lpcsclite
