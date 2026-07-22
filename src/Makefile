
ifeq ($(CC),)
  CC=gcc
endif
ifeq ($(CP),)
  CP=cp
endif

ERICSTOOLS_DIR:=./ericstools
CFLAGS:=$(CFLAGS) -Wall -Os
LIBS:=-lmbedtls -lmbedx509 -lmbedcrypto
STATIC_OBJS:=mbedtlsclu_common.o
#DEFS:=-DDEBUG -DOPENSSL_ENV_CONF_COMPAT
DEFS:=-DOPENSSL_ENV_CONF_COMPAT

#Set 0 to link to ericstools instead of compiling as static
#STATIC_LIBS:=1
ifeq ($(STATIC_LIBS),1)
	STATIC_OBJS:=$(STATIC_OBJS) libericstools.a
else
	LIBS:=$(LIBS) -lericstools
endif

#all: mbedtlsclu_common.o x509write_crl.o dhparam genpkey rand req ca
all: mbedtlsclu_common.o x509_create.o x509write_crl.o dhparam.o genpkey.o rand.o req.o ca.o x509.o crypt.o mbedtls-clu
mbedtlsclu_common.o: mbedtlsclu_common.c
	$(CC) $(CFLAGS) $(DEFS) -c mbedtlsclu_common.c -o $@

x509_create.o: x509_create.c
	$(CC) $(CFLAGS) $(DEFS) -c x509_create.c -o $@

x509write_crl.o: x509write_crl.c
	$(CC) $(CFLAGS) $(DEFS) -c x509write_crl.c -o $@
	
#dhparam: dhparam.o $(STATIC_OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

dhparam.o: dhparam.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c dhparam.c -o $@

#genpkey: genpkey.o $(STATIC_OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

genpkey.o: genpkey.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c genpkey.c -o $@

#rand: rand.o $(STATIC_OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

rand.o: rand.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c rand.c -o $@

#req: req.o $(STATIC_OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

req.o: req.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c req.c -o $@

#ca: ca.o $(STATIC_OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

ca.o: ca.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c ca.c -o $@

#x509: x509.o $(STATIC_OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

x509.o: x509.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c x509.c -o $@

crypt.o: crypt.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c crypt.c -o $@

mbedtls-clu: mbedtls-clu.o $(STATIC_OBJS) ca.o dhparam.o genpkey.o rand.o req.o x509.o crypt.o x509_create.o x509write_crl.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

mbedtls-clu.o: mbedtls-clu.c $(STATIC_OBJS)
	$(CC) $(CFLAGS) $(DEFS) -c mbedtls-clu.c -o $@

libericstools.a:
	make -C $(ERICSTOOLS_DIR)
	$(CP) $(ERICSTOOLS_DIR)/libericstools.a .
	$(CP) $(ERICSTOOLS_DIR)/erics_tools.h .

clean:
	if [ -e "$(ERICSTOOLS_DIR)" ] && [ -n "$(ERICSTOOLS_DIR)" ] ; then make -C $(ERICSTOOLS_DIR) clean ; fi
	rm -rf *.o *.a *~ .*sw* erics_tools.h mbedtlsclu_common x509write_crl x509_create dhparam genpkey rand req ca x509 mbedtls-clu
