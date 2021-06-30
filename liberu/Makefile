
CC = gcc
CXX = g++
CFLAGS = -g
CXXFLAGS = -g -std=c++11
LDFLAGS = -g
LOADLIBES =
LDLIBS = -ltfhe-spqlios-fma -lcrypto

target := build/eru
modules := crypto alloc context main
modules_objs := $(foreach mod, $(modules), build/$(mod).o)

all: makedirs link

link: $(modules_objs)
	$(CXX) $(LDFLAGS) $^ -o $(target) $(LOADLIBES) $(LDLIBS)

makedirs:
	mkdir -p build/

build/%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c $<

run:
	./$(target)

debug:
	gdb ./$(target)

clean:
	rm -f $(modules_objs)
	rm -rf build
