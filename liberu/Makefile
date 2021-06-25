
CC = gcc
CXX = g++
CFLAGS = -g
CXXFLAGS = -g -std=c++11
LDFLAGS = -g
LOADLIBES =
LDLIBS = -ltfhe-spqlios-fma -lcrypto

# target := liberu
modules := crypto alloc context main
modules_objs := $(foreach mod, $(modules), $(mod).o)

all: $(modules_objs)
	$(CXX) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c $<

clean:
	rm -f $(modules_objs)
