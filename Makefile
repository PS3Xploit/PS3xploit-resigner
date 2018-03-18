CC=g++
CFLAGS=-pipe -fvisibility=hidden -D_GNU_SOURCE -O3 -static -D_FILE_OFFSET_BITS=64
OS_TARGET=ps3xploit_rifgen_edatresign
LDFLAGS=-lcrypto -lssl
OBJS=aes.o aes_omac.o main.o sha1.o util.o pkg2zip_aes.o pkg2zip_aes_x86.o
.SILENT:
.SUFFIXES: .c .cpp .o

$(OS_TARGET): $(OBJS)
	${LINK}
	if $(CC) $(CFLAGS) $(OBJS) -o $(OS_TARGET) $(LDFLAGS) $(LIBS); then \
		${LINK_OK}; \
	else \
		${LINK_FAILED}; \
	fi
	

%aes_x86.o: %aes_x86.c
	@echo [C] $<
	gcc ${CFLAGS} -std=c99 -maes -mssse3 -MMD -c -o $@ $<

%main.o: %main.cpp
	@echo [C] $<
	$(CC) ${CFLAGS} -std=c99 -c main.cpp
	
	
%.o: %.c
	${COMPILE_STATUS}
	if ${CC} ${CFLAGS} ${CFLAGS} -c -o $@ $<; then \
		${COMPILE_OK}; \
	else \
		${COMPILE_FAILED}; \
	fi

%.o: %.cpp
	${COMPILE_STATUS}
	if ${CC} ${CFLAGS} ${CFLAGS} -c -o $@ $<; then \
		${COMPILE_OK}; \
	else \
		${COMPILE_FAILED}; \
	fi

clean:
	@printf "\033[K\033[0;32mCleaning\033[1;32m\033[0;32m...\033[0m\n"
	rm -rf *.o *.d $(OS_TARGET)

install:
	@printf "\033[K\033[0;32mInstalling\033[1;32m\033[0;32m...\033[0m\n"
	install -m755 $(OS_TARGET) $(BINDIR)

DIR_ENTER = printf "\033[K\033[0;36mEntering directory \033[1;36m$$i\033[0;36m.\033[0m\n"; cd $$i || exit 1
DIR_LEAVE = printf "\033[K\033[0;36mLeaving directory \033[1;36m$$i\033[0;36m.\033[0m\n"; cd .. || exit 1
DEPEND_STATUS = printf "\033[K\033[0;33mGenerating dependencies...\033[0m\r"
DEPEND_OK = printf "\033[K\033[0;32mSuccessfully generated dependencies.\033[0m\n"
DEPEND_FAILED = printf "\033[K\033[0;31mFailed to generate dependencies!\033[0m\n"; exit 1
COMPILE_STATUS = printf "\033[K\033[0;33mCompiling \033[1;33m$<\033[0;33m...\033[0m\r"
COMPILE_OK = printf "\033[K\033[0;32mSuccessfully compiled \033[1;32m$<\033[0;32m.\033[0m\n"
COMPILE_FAILED = printf "\033[K\033[0;31mFailed to compile \033[1;31m$<\033[0;31m!\033[0m\n"; exit 1
LINK_STATUS = printf "\033[K\033[0;33mLinking \033[1;33m$@\033[0;33m...\033[0m\r"
LINK_OK = printf "\033[K\033[0;32mSuccessfully linked \033[1;32m$@\033[0;32m.\033[0m\n"
LINK_FAILED = printf "\033[K\033[0;31mFailed to link \033[1;31m$@\033[0;31m!\033[0m\n"; exit 1
INSTALL_STATUS = printf "\033[K\033[0;33mInstalling \033[1;33m$$i\033[0;33m...\033[0m\r"
INSTALL_OK = printf "\033[K\033[0;32mSuccessfully installed \033[1;32m$$i\033[0;32m.\033[0m\n"
INSTALL_FAILED = printf "\033[K\033[0;31mFailed to install \033[1;31m$$i\033[0;31m!\033[0m\n"; exit 1
DELETE_OK = printf "\033[K\033[0;34mDeleted \033[1;34m$$i\033[0;34m.\033[0m\n"
DELETE_FAILED = printf "\033[K\033[0;31mFailed to delete \033[1;31m$$i\033[0;31m!\033[0m\n"; exit 1

