CC	:= g++
TARGET	:= argosparser

CXXFLAGS	:= -O2 -W -Wall -ansi -pedantic
CXX_FILES	:= argosparser.cc
H_FILES 	:= argosparser.h
O_FILES 	:= argosparser.o

SOURCEFILES := $(CXX_FILES) $(H_FILES)
.PRECIOUS: $(SOURCEFILES)

all: $(TARGET)

$(TARGET): $(O_FILES)

clean:
	$(RM) $(O_FILES)

distclean:
	$(RM) $(TARGET) $(O_FILES) 

argosparser.o: argosparser.cc argosparser.h
