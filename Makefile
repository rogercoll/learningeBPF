APP=tt

CC=clang
CCP=clang++

LIBS=-lbcc_bpf -lelf -lbcc

$(APP): $(APP).cpp
	$(CCP) $(CPP_FLAGS) -o $@ $^ $(LIBS)

.PHONY: clean
clean:
	rm -rf $(APP) *.a
