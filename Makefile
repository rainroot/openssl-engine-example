CFLAGS= -Wall -W  -O2 -fPIC -I./ -I./include ${OPENSSL_INC}
LDFLAGS= ${OPENSSL_LIB}

OBJS= eaes.o eseed.o esha.o esha256.o esha512.o  \
	erc4.o edes.o e3des.o openssl_engine.o

LIBNAME=libopenssl_engine.so
LIB=libopenssl_engine.so

.SUFFIXES: .cpp .cxx .cc .C .c

.cpp.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.cxx.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.cc.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.C.o:
	$(CXX) -c $(CXXFLAGS) -o $@ $<

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

all: $(LIB)

$(LIB) :$(OBJS)
	$(CC) -shared -Wl,--soname=$(LIBNAME) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(LIB) $(LIB_LINK0) $(LIB_LINK1) /usr/local/ssl/lib/engines/$(LIB)
